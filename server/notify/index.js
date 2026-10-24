// Hercules Push Relay — Block Notification Lambda
//
// Triggered by SQS when Bitcoin Core's blocknotify fires. Pages through every
// registered device token in DynamoDB and sends a silent APNs push to each
// one over a single, reused HTTP/2 connection with bounded concurrency.
//
// SQS message format (from the blocknotify script in server/README.md):
//   { "hash": "000000...", "height": 870000, "time": 1712234567 }
// `height` and `time` are optional; `hash` (64 hex chars) is required.
//
// Push payload (consumed by NotificationManager.parsePushPayload in the app):
//   { "aps": { "content-available": 1 },
//     "block": { "hash": "...", "timestamp": 1712234567, "height": 870000 } }
// `height` is omitted when unknown, never sent as 0.
//
// Delivery semantics:
//   - Each block hash is claimed in PUSH_LOG_TABLE with a conditional write
//     before fan-out starts. A redelivered SQS message (Lambda timeout, crash,
//     at-least-once duplicate, DLQ redrive) for an already-claimed hash is
//     skipped, so devices are never re-pushed for the same block.
//   - Errors before fan-out release the claim and are rethrown so SQS retries
//     (and eventually moves the message to the DLQ).
//   - Errors after fan-out has started are logged, never rethrown.
//
// Environment variables:
//   DEVICES_TABLE      — DynamoDB device table (default "hercules-devices")
//   PUSH_LOG_TABLE     — DynamoDB per-block idempotency table (default "hercules-push-log")
//   APNS_KEY_ID        — APNs key ID (10 chars)
//   APNS_TEAM_ID       — Apple Developer Team ID
//   APNS_KEY_PARAM     — SSM SecureString parameter name holding the .p8 PEM
//   APNS_TOPIC         — App bundle ID (dev.sermo.hercules.app)
//   APNS_HOST          — api.push.apple.com or api.sandbox.push.apple.com
//   APNS_CONCURRENCY   — max in-flight APNs requests (default 50)
//   MAX_MESSAGE_AGE_SECONDS — drop SQS messages older than this (default 1800)

"use strict";

const crypto = require("node:crypto");
const http2 = require("node:http2");

const config = () => ({
    devicesTable: process.env.DEVICES_TABLE || "hercules-devices",
    pushLogTable: process.env.PUSH_LOG_TABLE || "hercules-push-log",
    apnsHost: process.env.APNS_HOST || "api.sandbox.push.apple.com",
    apnsTopic: process.env.APNS_TOPIC || "dev.sermo.hercules.app",
    apnsKeyId: process.env.APNS_KEY_ID || "",
    apnsTeamId: process.env.APNS_TEAM_ID || "",
    apnsKeyParam: process.env.APNS_KEY_PARAM || "",
    concurrency: positiveInt(process.env.APNS_CONCURRENCY, 50),
    maxMessageAgeSeconds: positiveInt(process.env.MAX_MESSAGE_AGE_SECONDS, 1800),
});

// APNs responses that mean the token will never work again → delete the row.
// https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns
const PRUNE_REASONS = new Set(["BadDeviceToken", "Unregistered", "DeviceTokenNotForTopic"]);
// Transient failures worth one in-invocation retry.
const RETRY_STATUSES = new Set([429, 500, 503]);
// Stop starting new sends when the invocation is this close to its timeout.
const DEADLINE_MARGIN_MS = 3000;
// Push log rows expire after a day; long enough to dedupe any redelivery.
const PUSH_LOG_TTL_SECONDS = 86400;
const HASH_RE = /^[0-9a-f]{64}$/;

function positiveInt(value, fallback) {
    const n = Number.parseInt(value, 10);
    return Number.isFinite(n) && n > 0 ? n : fallback;
}

// MARK: - Message parsing

/** Parse and validate an SQS record. Returns null for a malformed message. */
function parseBlockMessage(body) {
    let msg;
    try {
        msg = JSON.parse(body);
    } catch {
        return null;
    }
    if (!msg || typeof msg !== "object") return null;
    const hash = typeof msg.hash === "string" ? msg.hash.toLowerCase() : "";
    if (!HASH_RE.test(hash)) return null;
    const block = { hash };
    if (Number.isSafeInteger(msg.height) && msg.height > 0) block.height = msg.height;
    if (Number.isSafeInteger(msg.time) && msg.time > 0) block.timestamp = msg.time;
    return block;
}

/** Build the silent-push payload. Height is omitted (not zeroed) when unknown. */
function buildPayload(block) {
    const out = { hash: block.hash, timestamp: block.timestamp ?? 0 };
    if (block.height !== undefined) out.height = block.height;
    return JSON.stringify({ aps: { "content-available": 1 }, block: out });
}

// MARK: - ES256 JWT (Node built-in crypto, no jsonwebtoken dependency)

function base64url(input) {
    return Buffer.from(input).toString("base64url");
}

/**
 * Sign an APNs provider token. APNs wants a JWS with a raw r||s (IEEE P1363)
 * ECDSA P-256 signature, which `crypto.sign` produces with dsaEncoding
 * "ieee-p1363".
 */
function signApnsJwt({ keyPem, keyId, teamId, issuedAt }) {
    const header = base64url(JSON.stringify({ alg: "ES256", kid: keyId }));
    const claims = base64url(JSON.stringify({ iss: teamId, iat: issuedAt }));
    const signingInput = `${header}.${claims}`;
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: keyPem,
        dsaEncoding: "ieee-p1363",
    });
    return `${signingInput}.${signature.toString("base64url")}`;
}

// MARK: - APNs HTTP/2 client (one session, many streams)

class ApnsClient {
    constructor({ host, topic, connect = http2.connect }) {
        this.origin = `https://${host}`;
        this.topic = topic;
        this.connect = connect;
        this.session = null;
    }

    getSession() {
        if (!this.session || this.session.closed || this.session.destroyed) {
            const session = this.connect(this.origin);
            // A session-level error fails in-flight streams individually;
            // swallow here so it doesn't become an uncaught exception, and
            // drop the session so the next send reconnects.
            session.on("error", () => {
                if (this.session === session) this.session = null;
            });
            session.on("goaway", () => {
                if (this.session === session) this.session = null;
            });
            session.on("close", () => {
                if (this.session === session) this.session = null;
            });
            this.session = session;
        }
        return this.session;
    }

    /**
     * Send one push. Resolves { status, reason } for any HTTP response;
     * rejects only on transport errors.
     */
    send(deviceToken, payload, jwt) {
        return new Promise((resolve, reject) => {
            let req;
            try {
                req = this.getSession().request({
                    ":method": "POST",
                    ":path": `/3/device/${deviceToken}`,
                    authorization: `bearer ${jwt}`,
                    "apns-topic": this.topic,
                    "apns-push-type": "background",
                    "apns-priority": "5",
                });
            } catch (err) {
                this.session = null;
                reject(err);
                return;
            }
            req.setEncoding("utf8");
            let status = 0;
            let data = "";
            req.on("response", (headers) => { status = headers[":status"]; });
            req.on("data", (chunk) => { data += chunk; });
            req.on("end", () => {
                let reason;
                if (data) {
                    try { reason = JSON.parse(data).reason; } catch { /* non-JSON body */ }
                }
                resolve({ status, reason });
            });
            req.on("error", reject);
            req.end(payload);
        });
    }

    close() {
        if (this.session && !this.session.closed) this.session.close();
        this.session = null;
    }
}

// MARK: - Bounded concurrency

/** Run `fn` over `items` with at most `limit` in flight. */
async function forEachLimit(items, limit, fn) {
    let next = 0;
    const worker = async () => {
        while (next < items.length) {
            const i = next++;
            await fn(items[i], i);
        }
    };
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

// MARK: - DynamoDB / SSM adapters (lazy so tests never load the AWS SDK)

function defaultStore(cfg, sdk = require("@aws-sdk/client-dynamodb")) {
    const {
        DynamoDBClient, ScanCommand, DeleteItemCommand, PutItemCommand,
    } = sdk;
    const client = new DynamoDBClient({});
    return {
        async scanPage(exclusiveStartKey) {
            const out = await client.send(new ScanCommand({
                TableName: cfg.devicesTable,
                ProjectionExpression: "device_token",
                ExclusiveStartKey: exclusiveStartKey,
            }));
            return {
                tokens: (out.Items || []).map((i) => i.device_token && i.device_token.S).filter(Boolean),
                lastEvaluatedKey: out.LastEvaluatedKey,
            };
        },
        async deleteToken(token) {
            await client.send(new DeleteItemCommand({
                TableName: cfg.devicesTable,
                Key: { device_token: { S: token } },
            }));
        },
        /** Returns false if this block hash was already claimed. */
        async claimBlock(hash, nowSeconds) {
            try {
                await client.send(new PutItemCommand({
                    TableName: cfg.pushLogTable,
                    Item: {
                        block_hash: { S: hash },
                        claimed_at: { N: String(nowSeconds) },
                        ttl: { N: String(nowSeconds + PUSH_LOG_TTL_SECONDS) },
                    },
                    ConditionExpression: "attribute_not_exists(block_hash)",
                }));
                return true;
            } catch (err) {
                if (err && err.name === "ConditionalCheckFailedException") return false;
                throw err;
            }
        },
        async releaseBlock(hash) {
            await client.send(new DeleteItemCommand({
                TableName: cfg.pushLogTable,
                Key: { block_hash: { S: hash } },
            }));
        },
    };
}

async function defaultLoadKey(cfg) {
    if (!cfg.apnsKeyParam) throw new Error("APNS_KEY_PARAM is not set");
    const { SSMClient, GetParameterCommand } = require("@aws-sdk/client-ssm");
    const out = await new SSMClient({}).send(new GetParameterCommand({
        Name: cfg.apnsKeyParam,
        WithDecryption: true,
    }));
    return normalizePem(out.Parameter.Value);
}

/** Accept either the raw .p8 PEM text or its base64 encoding. */
function normalizePem(value) {
    const v = String(value || "").trim();
    if (v.startsWith("-----BEGIN")) return v;
    return Buffer.from(v, "base64").toString("utf8").trim();
}

// MARK: - Handler factory

/**
 * Build a handler. Dependencies are injectable for tests:
 *   store   — { scanPage, deleteToken, claimBlock, releaseBlock }
 *   apns    — { send(token, payload, jwt) → {status, reason}, close() }
 *   loadKey — async () → PEM string
 *   now     — () → ms since epoch
 */
function createHandler(deps = {}) {
    const cfg = { ...config(), ...(deps.config || {}) };
    const now = deps.now || Date.now;
    let store = deps.store || null;
    let apns = deps.apns || null;
    const loadKey = deps.loadKey || (() => defaultLoadKey(cfg));
    const log = deps.log || console;

    // Cold-start caches, reused across warm invocations.
    let keyPem = null;
    let jwt = null;
    let jwtIssuedAt = 0;

    // `rejected` is the JWT APNs just called expired; only re-sign if no other
    // concurrent stream has already replaced it (Apple rejects refreshes more
    // often than every 20 min with TooManyProviderTokenUpdates).
    async function currentJwt(rejected = null) {
        if (!keyPem) keyPem = await loadKey();
        const nowSec = Math.floor(now() / 1000);
        // APNs tokens are valid for 60 min. Refresh at 50.
        if (!jwt || (rejected && rejected === jwt) || nowSec - jwtIssuedAt > 50 * 60) {
            jwt = signApnsJwt({ keyPem, keyId: cfg.apnsKeyId, teamId: cfg.apnsTeamId, issuedAt: nowSec });
            jwtIssuedAt = nowSec;
        }
        return jwt;
    }

    async function sendOne(token, payload, stats) {
        for (let attempt = 0; attempt < 2; attempt++) {
            let res;
            const usedJwt = await currentJwt();
            try {
                res = await apns.send(token, payload, usedJwt);
            } catch (err) {
                if (attempt === 0) continue; // transport error: retry once
                stats.failed++;
                return;
            }
            if (res.status === 200) {
                stats.sent++;
                return;
            }
            if (res.status === 410 || PRUNE_REASONS.has(res.reason)) {
                stats.pruned++;
                try {
                    await store.deleteToken(token);
                } catch (err) {
                    log.error(`Failed to prune token ${token.slice(0, 8)}…: ${err.message}`);
                }
                return;
            }
            if (res.status === 403 && res.reason === "ExpiredProviderToken" && attempt === 0) {
                await currentJwt(usedJwt);
                continue;
            }
            if (RETRY_STATUSES.has(res.status) && attempt === 0) continue;
            stats.failed++;
            log.warn(`APNs ${res.status} ${res.reason || ""} for ${token.slice(0, 8)}…`);
            return;
        }
    }

    async function processRecord(record, context) {
        const block = parseBlockMessage(record.body);
        if (!block) {
            // Retrying a malformed message can never succeed; drop it.
            log.error("Dropping malformed block message");
            return;
        }

        const sentMs = Number(record.attributes && record.attributes.SentTimestamp);
        if (sentMs && now() - sentMs > cfg.maxMessageAgeSeconds * 1000) {
            log.warn(`Dropping stale message for ${block.hash} (sent ${Math.round((now() - sentMs) / 1000)}s ago)`);
            return;
        }

        // Everything that can fail before any device is pushed: key load,
        // JWT signing, the idempotency claim. Throwing here is safe.
        await currentJwt();
        const payload = buildPayload(block);
        const nowSec = Math.floor(now() / 1000);
        if (!(await store.claimBlock(block.hash, nowSec))) {
            log.log(`Block ${block.hash} already pushed; skipping redelivery`);
            return;
        }

        let firstPage;
        try {
            firstPage = await store.scanPage(undefined);
        } catch (err) {
            // Nobody has been pushed yet: release the claim so SQS can retry.
            await store.releaseBlock(block.hash).catch(() => {});
            throw err;
        }

        // From here on, never throw: a retry would re-push devices.
        const stats = { sent: 0, pruned: 0, failed: 0, skipped: 0, devices: 0 };
        const label = block.height !== undefined ? `#${block.height}` : block.hash.slice(0, 16);
        let page = firstPage;
        try {
            for (;;) {
                stats.devices += page.tokens.length;
                await forEachLimit(page.tokens, cfg.concurrency, async (token) => {
                    if (context && context.getRemainingTimeInMillis
                        && context.getRemainingTimeInMillis() < DEADLINE_MARGIN_MS) {
                        stats.skipped++;
                        return;
                    }
                    await sendOne(token, payload, stats);
                });
                if (!page.lastEvaluatedKey) break;
                page = await store.scanPage(page.lastEvaluatedKey);
            }
        } catch (err) {
            log.error(`Fan-out for block ${label} aborted after partial delivery: ${err.message}`);
        }
        log.log(`Block ${label}: ${stats.devices} devices, ${stats.sent} sent, ${stats.pruned} pruned, `
            + `${stats.failed} failed, ${stats.skipped} skipped (deadline)`);
    }

    return async function handler(event, context) {
        if (!store) store = defaultStore(cfg);
        if (!apns) apns = new ApnsClient({ host: cfg.apnsHost, topic: cfg.apnsTopic });
        for (const record of event.Records || []) {
            await processRecord(record, context);
        }
    };
}

exports.handler = createHandler();

// Exported for tests.
exports._internal = {
    createHandler,
    defaultStore,
    parseBlockMessage,
    buildPayload,
    signApnsJwt,
    normalizePem,
    forEachLimit,
    ApnsClient,
};
