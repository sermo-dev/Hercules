"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http2 = require("node:http2");

const {
    createHandler, parseBlockMessage, buildPayload, signApnsJwt, normalizePem, ApnsClient,
} = require("../notify/index.js")._internal;

const HASH = "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054";
const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const PEM = privateKey.export({ type: "pkcs8", format: "pem" });

const token = (i) => i.toString(16).padStart(64, "0");
const silentLog = { log() {}, warn() {}, error() {} };

function fakeStore(pages, { claim = true, failScanAt = -1 } = {}) {
    const s = {
        deleted: [], claimed: [], released: [], scans: 0,
        async scanPage(key) {
            const idx = key === undefined ? 0 : key;
            s.scans++;
            if (idx === failScanAt) throw new Error("scan failed");
            return { tokens: pages[idx], lastEvaluatedKey: idx + 1 < pages.length ? idx + 1 : undefined };
        },
        async deleteToken(t) { s.deleted.push(t); },
        async claimBlock(h) { s.claimed.push(h); return claim; },
        async releaseBlock(h) { s.released.push(h); },
    };
    return s;
}

function fakeApns(responder = () => ({ status: 200 })) {
    const a = {
        calls: [], inFlight: 0, maxInFlight: 0,
        async send(tok, payload, jwt) {
            a.calls.push({ tok, payload, jwt });
            a.inFlight++;
            a.maxInFlight = Math.max(a.maxInFlight, a.inFlight);
            await new Promise((r) => setImmediate(r));
            a.inFlight--;
            return responder(tok, a.calls.filter((c) => c.tok === tok).length);
        },
        close() {},
    };
    return a;
}

const record = (body, attrs = {}) => ({ body: JSON.stringify(body), attributes: attrs });

function makeHandler(store, apns, extra = {}) {
    return createHandler({
        store, apns, log: silentLog, loadKey: async () => PEM,
        config: { apnsKeyId: "ABC123DEFG", apnsTeamId: "TEAM123456", concurrency: 4 },
        ...extra,
    });
}

test("parseBlockMessage validates hash and keeps optional height/time", () => {
    assert.deepEqual(parseBlockMessage(JSON.stringify({ hash: HASH, height: 870000, time: 1712234567 })),
        { hash: HASH, height: 870000, timestamp: 1712234567 });
    assert.deepEqual(parseBlockMessage(JSON.stringify({ hash: HASH.toUpperCase() })), { hash: HASH });
    assert.deepEqual(parseBlockMessage(JSON.stringify({ hash: HASH, height: 0 })), { hash: HASH });
    assert.equal(parseBlockMessage(JSON.stringify({ hash: "abc" })), null);
    assert.equal(parseBlockMessage("not json"), null);
    assert.equal(parseBlockMessage("null"), null);
});

test("buildPayload omits height when unknown instead of sending 0", () => {
    const withHeight = JSON.parse(buildPayload({ hash: HASH, height: 5, timestamp: 9 }));
    assert.deepEqual(withHeight, { aps: { "content-available": 1 }, block: { hash: HASH, timestamp: 9, height: 5 } });
    const without = JSON.parse(buildPayload({ hash: HASH }));
    assert.equal("height" in without.block, false);
    assert.equal(without.block.timestamp, 0);
});

test("signApnsJwt produces a verifiable ES256 JWS", () => {
    const jwt = signApnsJwt({ keyPem: PEM, keyId: "ABC123DEFG", teamId: "TEAM123456", issuedAt: 1700000000 });
    const [h, c, sig] = jwt.split(".");
    assert.deepEqual(JSON.parse(Buffer.from(h, "base64url")), { alg: "ES256", kid: "ABC123DEFG" });
    assert.deepEqual(JSON.parse(Buffer.from(c, "base64url")), { iss: "TEAM123456", iat: 1700000000 });
    const raw = Buffer.from(sig, "base64url");
    assert.equal(raw.length, 64, "raw r||s, not DER");
    assert.ok(crypto.verify("sha256", Buffer.from(`${h}.${c}`), { key: publicKey, dsaEncoding: "ieee-p1363" }, raw));
});

test("normalizePem accepts raw PEM and base64-encoded PEM", () => {
    assert.equal(normalizePem(PEM), PEM.trim());
    assert.equal(normalizePem(Buffer.from(PEM).toString("base64")), PEM.trim());
});

test("paginates the device scan and pushes every page", async () => {
    const pages = [[token(1), token(2)], [token(3)], [token(4), token(5)]];
    const store = fakeStore(pages);
    const apns = fakeApns();
    await makeHandler(store, apns)({ Records: [record({ hash: HASH, height: 870000, time: 1 })] });
    assert.equal(store.scans, 3);
    assert.deepEqual(apns.calls.map((c) => c.tok).sort(), pages.flat().sort());
    const payload = JSON.parse(apns.calls[0].payload);
    assert.equal(payload.block.height, 870000);
    assert.equal(apns.calls[0].jwt.split(".").length, 3);
    assert.deepEqual(store.claimed, [HASH]);
});

test("bounds APNs concurrency", async () => {
    const tokens = Array.from({ length: 40 }, (_, i) => token(i + 1));
    const apns = fakeApns();
    await makeHandler(fakeStore([tokens]), apns)({ Records: [record({ hash: HASH })] });
    assert.equal(apns.calls.length, 40);
    assert.ok(apns.maxInFlight <= 4, `max in flight ${apns.maxInFlight}`);
    assert.ok(apns.maxInFlight > 1, "should actually run in parallel");
});

test("prunes on 410, BadDeviceToken and DeviceTokenNotForTopic only", async () => {
    const responses = {
        [token(1)]: { status: 410, reason: "Unregistered" },
        [token(2)]: { status: 400, reason: "BadDeviceToken" },
        [token(3)]: { status: 400, reason: "DeviceTokenNotForTopic" },
        [token(4)]: { status: 400, reason: "PayloadTooLarge" },
        [token(5)]: { status: 200 },
    };
    const store = fakeStore([Object.keys(responses)]);
    await makeHandler(store, fakeApns((t) => responses[t]))({ Records: [record({ hash: HASH })] });
    assert.deepEqual(store.deleted.sort(), [token(1), token(2), token(3)]);
});

test("retries transient 503 and transport errors once", async () => {
    const apns = fakeApns((t, n) => (n === 1 ? { status: 503, reason: "ServiceUnavailable" } : { status: 200 }));
    await makeHandler(fakeStore([[token(1)]]), apns)({ Records: [record({ hash: HASH })] });
    assert.equal(apns.calls.length, 2);

    let attempts = 0;
    const flaky = {
        async send() { attempts++; if (attempts === 1) throw new Error("ECONNRESET"); return { status: 200 }; },
        close() {},
    };
    await makeHandler(fakeStore([[token(1)]]), flaky)({ Records: [record({ hash: HASH })] });
    assert.equal(attempts, 2);
});

test("re-signs the JWT on ExpiredProviderToken", async () => {
    let now = 1_700_000_000_000;
    const apns = fakeApns((t, n) => (n === 1 ? { status: 403, reason: "ExpiredProviderToken" } : { status: 200 }));
    const h = makeHandler(fakeStore([[token(1)]]), apns, { now: () => (now += 1000) });
    await h({ Records: [record({ hash: HASH })] });
    assert.equal(apns.calls.length, 2);
    assert.notEqual(apns.calls[0].jwt, apns.calls[1].jwt);
});

test("skips already-claimed block hashes (SQS redelivery)", async () => {
    const store = fakeStore([[token(1)]], { claim: false });
    const apns = fakeApns();
    await makeHandler(store, apns)({ Records: [record({ hash: HASH })] });
    assert.equal(apns.calls.length, 0);
    assert.equal(store.scans, 0);
});

test("first-page scan failure releases the claim and throws so SQS retries", async () => {
    const store = fakeStore([[token(1)]], { failScanAt: 0 });
    const apns = fakeApns();
    await assert.rejects(makeHandler(store, apns)({ Records: [record({ hash: HASH })] }), /scan failed/);
    assert.deepEqual(store.released, [HASH]);
    assert.equal(apns.calls.length, 0);
});

test("key-load failure throws before claiming", async () => {
    const store = fakeStore([[token(1)]]);
    const h = makeHandler(store, fakeApns(), { loadKey: async () => { throw new Error("ssm denied"); } });
    await assert.rejects(h({ Records: [record({ hash: HASH })] }), /ssm denied/);
    assert.deepEqual(store.claimed, []);
});

test("mid-fan-out failure does not throw (no re-push of earlier pages)", async () => {
    const store = fakeStore([[token(1)], [token(2)]], { failScanAt: 1 });
    const apns = fakeApns();
    await makeHandler(store, apns)({ Records: [record({ hash: HASH })] });
    assert.deepEqual(apns.calls.map((c) => c.tok), [token(1)]);
    assert.deepEqual(store.released, []);
});

test("drops malformed and stale messages without throwing", async () => {
    const store = fakeStore([[token(1)]]);
    const apns = fakeApns();
    const now = 1_700_000_000_000;
    const h = makeHandler(store, apns, { now: () => now });
    await h({ Records: [{ body: "{bad" }, record({ hash: "zz" })] });
    await h({ Records: [record({ hash: HASH }, { SentTimestamp: String(now - 3600 * 1000) })] });
    assert.equal(apns.calls.length, 0);
    assert.deepEqual(store.claimed, []);
});

test("stops starting sends near the Lambda deadline", async () => {
    const apns = fakeApns();
    let remaining = 10_000;
    const ctx = { getRemainingTimeInMillis: () => (remaining -= 4000) };
    await makeHandler(fakeStore([[token(1), token(2), token(3)]]), apns, { config: { concurrency: 1 } })(
        { Records: [record({ hash: HASH })] }, ctx);
    assert.equal(apns.calls.length, 1);
});

test("ApnsClient reuses one HTTP/2 session across many pushes", async (t) => {
    const server = http2.createServer();
    const seen = [];
    server.on("stream", (stream, headers) => {
        seen.push(headers);
        let body = "";
        stream.on("data", (c) => (body += c));
        stream.on("end", () => {
            const bad = headers[":path"].endsWith(token(2));
            stream.respond({ ":status": bad ? 410 : 200 });
            stream.end(bad ? JSON.stringify({ reason: "Unregistered" }) : "");
        });
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    t.after(() => server.close());
    const { port } = server.address();

    let connects = 0;
    const client = new ApnsClient({
        host: "unused",
        topic: "dev.sermo.hercules.app",
        connect: () => { connects++; return http2.connect(`http://127.0.0.1:${port}`); },
    });
    const results = await Promise.all([1, 2, 3, 4].map((i) => client.send(token(i), "{}", "jwt")));
    client.close();

    assert.equal(connects, 1);
    assert.deepEqual(results.map((r) => r.status), [200, 410, 200, 200]);
    assert.equal(results[1].reason, "Unregistered");
    assert.equal(seen[0]["apns-push-type"], "background");
    assert.equal(seen[0]["apns-topic"], "dev.sermo.hercules.app");
    assert.equal(seen[0].authorization, "bearer jwt");
});

/** Fake @aws-sdk/client-dynamodb: commands record their input, client replies from a script. */
function fakeSdk(reply) {
    const sent = [];
    const cmd = (name) => class { constructor(input) { this.name = name; this.input = input; } };
    return {
        sent,
        DynamoDBClient: class { async send(c) { sent.push(c); return reply(c); } },
        ScanCommand: cmd("Scan"),
        DeleteItemCommand: cmd("DeleteItem"),
        PutItemCommand: cmd("PutItem"),
        UpdateItemCommand: cmd("UpdateItem"),
    };
}

test("default DynamoDB store paginates, projects, and claims conditionally", async () => {
    const { defaultStore } = require("../notify/index.js")._internal;
    const sdk = fakeSdk((c) => {
        if (c.name === "Scan") {
            return c.input.ExclusiveStartKey
                ? { Items: [{ device_token: { S: token(2) } }] }
                : { Items: [{ device_token: { S: token(1) } }], LastEvaluatedKey: { device_token: { S: token(1) } } };
        }
        if (c.name === "PutItem" && sdk.sent.filter((x) => x.name === "PutItem").length > 1) {
            throw Object.assign(new Error("exists"), { name: "ConditionalCheckFailedException" });
        }
        return {};
    });
    const store = defaultStore({ devicesTable: "dev", pushLogTable: "log" }, sdk);
    const p1 = await store.scanPage(undefined);
    assert.deepEqual(p1.tokens, [token(1)]);
    const p2 = await store.scanPage(p1.lastEvaluatedKey);
    assert.deepEqual(p2, { tokens: [token(2)], lastEvaluatedKey: undefined });
    assert.equal(sdk.sent[0].input.ProjectionExpression, "device_token");
    assert.deepEqual(sdk.sent[1].input.ExclusiveStartKey, { device_token: { S: token(1) } });

    assert.equal(await store.claimBlock(HASH, 100), true);
    assert.equal(await store.claimBlock(HASH, 100), false);
    const put = sdk.sent.find((c) => c.name === "PutItem").input;
    assert.equal(put.TableName, "log");
    assert.equal(put.ConditionExpression, "attribute_not_exists(block_hash)");
    assert.equal(put.Item.ttl.N, String(100 + 86400));

    await store.deleteToken(token(9));
    assert.deepEqual(sdk.sent.at(-1).input, { TableName: "dev", Key: { device_token: { S: token(9) } } });
});

test("ApnsClient times out a hung request and reconnects on retry", async (t) => {
    // First connection accepts streams but never answers (a session that died
    // silently while the Lambda was frozen); the second answers normally.
    let connects = 0;
    const servers = [];
    const listen = async (respond) => {
        const server = http2.createServer();
        server.on("stream", (stream) => {
            stream.on("error", () => {});
            stream.on("data", () => {});
            stream.on("end", () => { if (respond) { stream.respond({ ":status": 200 }); stream.end(); } });
        });
        await new Promise((r) => server.listen(0, "127.0.0.1", r));
        servers.push(server);
        return server.address().port;
    };
    const hungPort = await listen(false);
    const goodPort = await listen(true);
    t.after(() => servers.forEach((s) => s.close()));

    const client = new ApnsClient({
        host: "unused",
        topic: "dev.sermo.hercules.app",
        requestTimeoutMs: 200,
        connect: () => http2.connect(`http://127.0.0.1:${connects++ === 0 ? hungPort : goodPort}`),
    });
    await assert.rejects(client.send(token(1), "{}", "jwt"), /timed out/);
    const res = await client.send(token(1), "{}", "jwt");
    client.close();
    assert.equal(res.status, 200);
    assert.equal(connects, 2);
});

test("handler closes the APNs session after each invocation", async () => {
    let closed = 0;
    const apns = { send: async () => ({ status: 200 }), close: () => { closed++; } };
    const store = {
        scanPage: async () => ({ tokens: [token(1)], lastEvaluatedKey: undefined }),
        deleteToken: async () => {},
        claimBlock: async () => true,
        releaseBlock: async () => {},
    };
    const handler = createHandler({ store, apns, loadKey: async () => PEM });
    await handler({ Records: [{ body: JSON.stringify({ hash: "ab".repeat(32) }), attributes: {} }] }, {});
    assert.equal(closed, 1);
});
