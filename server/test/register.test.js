"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createHandler, secretHash } = require("../register/index.js")._internal;

const TOKEN = "a1".repeat(32);
const SECRET = "5e".repeat(32);
const OTHER_SECRET = "77".repeat(32);

/** In-memory stand-in for the DynamoDB conditional writes. */
function fakeStore() {
    const rows = new Map();
    return {
        rows,
        async upsert({ token, secretHash: h, platform, nowIso, ttl }) {
            const row = rows.get(token);
            if (row && row.secret_hash !== h) return false;
            rows.set(token, {
                platform, secret_hash: h, updated_at: nowIso, ttl,
                created_at: row ? row.created_at : nowIso,
            });
            return true;
        },
        async remove({ token, secretHash: h }) {
            const row = rows.get(token);
            if (row && row.secret_hash !== h) return false;
            rows.delete(token);
            return true;
        },
    };
}

const req = (path, body, extra = {}) => ({
    resource: path, path, body: typeof body === "string" ? body : JSON.stringify(body), ...extra,
});

test("registers a valid token and stores only the secret hash", async () => {
    const store = fakeStore();
    const now = 1_700_000_000_000;
    const h = createHandler({ store, now: () => now });
    const res = await h(req("/register", { device_token: TOKEN.toUpperCase(), platform: "ios", install_secret: SECRET }));
    assert.equal(res.statusCode, 200);
    const row = store.rows.get(TOKEN);
    assert.deepEqual(Object.keys(row).sort(), ["created_at", "platform", "secret_hash", "ttl", "updated_at"]);
    assert.equal(row.secret_hash, secretHash(SECRET));
    assert.notEqual(row.secret_hash, SECRET);
    assert.equal(row.ttl, now / 1000 + 30 * 86400);
});

test("re-registration with the same secret refreshes; a different secret is rejected", async () => {
    const store = fakeStore();
    let now = 1_700_000_000_000;
    const h = createHandler({ store, now: () => now });
    await h(req("/register", { device_token: TOKEN, install_secret: SECRET }));
    const created = store.rows.get(TOKEN).created_at;
    now += 86400_000;
    assert.equal((await h(req("/register", { device_token: TOKEN, install_secret: SECRET }))).statusCode, 200);
    assert.equal(store.rows.get(TOKEN).created_at, created);
    assert.notEqual(store.rows.get(TOKEN).updated_at, created);
    assert.equal((await h(req("/register", { device_token: TOKEN, install_secret: OTHER_SECRET }))).statusCode, 403);
    assert.equal(store.rows.get(TOKEN).secret_hash, secretHash(SECRET));
});

test("unregister requires the matching secret and is idempotent", async () => {
    const store = fakeStore();
    const h = createHandler({ store });
    await h(req("/register", { device_token: TOKEN, install_secret: SECRET }));
    assert.equal((await h(req("/unregister", { device_token: TOKEN, install_secret: OTHER_SECRET }))).statusCode, 403);
    assert.ok(store.rows.has(TOKEN));
    assert.equal((await h(req("/unregister", { device_token: TOKEN, install_secret: SECRET }))).statusCode, 200);
    assert.ok(!store.rows.has(TOKEN));
    assert.equal((await h(req("/unregister", { device_token: TOKEN, install_secret: SECRET }))).statusCode, 200);
});

test("rejects malformed input", async () => {
    const store = fakeStore();
    const h = createHandler({ store });
    const cases = [
        [req("/register", "not json"), "invalid JSON"],
        [req("/register", "[]"), "invalid body"],
        [{ resource: "/register" }, "body required"],
        [req("/register", { install_secret: SECRET }), "invalid device_token"],
        [req("/register", { device_token: "abc", install_secret: SECRET }), "invalid device_token"],
        [req("/register", { device_token: "zz".repeat(32), install_secret: SECRET }), "invalid device_token"],
        [req("/register", { device_token: "a".repeat(65), install_secret: SECRET }), "invalid device_token"],
        [req("/register", { device_token: "ab".repeat(101), install_secret: SECRET }), "invalid device_token"],
        [req("/register", { device_token: TOKEN }), "invalid install_secret"],
        [req("/register", { device_token: TOKEN, install_secret: "short" }), "invalid install_secret"],
        [req("/register", { device_token: TOKEN, install_secret: SECRET, platform: "android" }), "unsupported platform"],
        [req("/register", { device_token: TOKEN, install_secret: SECRET, pad: "x".repeat(4096) }), "body too large"],
    ];
    for (const [event, error] of cases) {
        const res = await h(event);
        assert.equal(res.statusCode, 400, error);
        assert.equal(JSON.parse(res.body).error, error);
    }
    assert.equal(store.rows.size, 0);
});

test("accepts base64-encoded bodies and longer future tokens", async () => {
    const store = fakeStore();
    const h = createHandler({ store });
    const long = "cd".repeat(100);
    const body = Buffer.from(JSON.stringify({ device_token: long, install_secret: SECRET })).toString("base64");
    const res = await h(req("/register", body, { isBase64Encoded: true }));
    assert.equal(res.statusCode, 200);
    assert.ok(store.rows.has(long));
});

test("unknown routes 404 and store errors 500 without leaking details", async () => {
    const h = createHandler({ store: fakeStore() });
    assert.equal((await h(req("/other", {}))).statusCode, 404);

    const failing = createHandler({
        store: { async upsert() { throw Object.assign(new Error("boom " + TOKEN), { name: "ProvisionedThroughputExceededException" }); } },
    });
    const errors = [];
    const orig = console.error;
    console.error = (m) => errors.push(m);
    try {
        const res = await failing(req("/register", { device_token: TOKEN, install_secret: SECRET }));
        assert.equal(res.statusCode, 500);
        assert.equal(JSON.parse(res.body).error, "internal error");
    } finally {
        console.error = orig;
    }
    assert.ok(errors.every((m) => !m.includes(TOKEN)), "token must not be logged");
});

test("default DynamoDB store uses conditional UpdateItem/DeleteItem with #ttl alias", async () => {
    const { defaultStore } = require("../register/index.js")._internal;
    const sent = [];
    const cmd = (name) => class { constructor(input) { this.name = name; this.input = input; } };
    let fail = false;
    const sdk = {
        DynamoDBClient: class {
            async send(c) {
                sent.push(c);
                if (fail) throw Object.assign(new Error("x"), { name: "ConditionalCheckFailedException" });
                return {};
            }
        },
        UpdateItemCommand: cmd("UpdateItem"),
        DeleteItemCommand: cmd("DeleteItem"),
    };
    const store = defaultStore("devices", sdk);
    const h = secretHash(SECRET);
    assert.equal(await store.upsert({ token: TOKEN, secretHash: h, platform: "ios", nowIso: "t", ttl: 5 }), true);
    const up = sent[0].input;
    assert.equal(up.TableName, "devices");
    assert.match(up.UpdateExpression, /#ttl = :ttl/);
    assert.match(up.UpdateExpression, /created_at = if_not_exists\(created_at, :now\)/);
    assert.deepEqual(up.ExpressionAttributeNames, { "#ttl": "ttl" });
    assert.equal(up.ConditionExpression, "attribute_not_exists(device_token) OR secret_hash = :h");
    assert.equal(up.ExpressionAttributeValues[":h"].S, h);

    assert.equal(await store.remove({ token: TOKEN, secretHash: h }), true);
    assert.equal(sent[1].input.ConditionExpression, "attribute_not_exists(device_token) OR secret_hash = :h");

    fail = true;
    assert.equal(await store.upsert({ token: TOKEN, secretHash: h, platform: "ios", nowIso: "t", ttl: 5 }), false);
    assert.equal(await store.remove({ token: TOKEN, secretHash: h }), false);
});
