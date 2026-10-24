// Hercules Push Relay — Device Registration Lambda
//
// POST /register
//   Body: { "device_token": "<hex>", "platform": "ios", "install_secret": "<64 hex>" }
//   Creates or refreshes the row for this APNs token with a 30-day TTL. The
//   app re-registers on launch (at most daily), so live installs never expire.
//   The first registration binds the token to sha256(install_secret); later
//   updates must present the same secret or get 403.
//
// POST /unregister
//   Body: { "device_token": "<hex>", "install_secret": "<64 hex>" }
//   Deletes the row if the secret matches. Unknown tokens succeed (idempotent).
//
// Stored per row, nothing else: device_token, platform, secret_hash,
// created_at, updated_at, ttl. Tokens and secrets are never logged.

"use strict";

const crypto = require("node:crypto");

const TTL_DAYS = 30;
const MAX_BODY_BYTES = 2048;
// APNs tokens are currently 32 bytes (64 hex chars); Apple reserves the right
// to grow them, so accept up to 100 bytes.
const TOKEN_RE = /^(?:[0-9a-f]{2}){32,100}$/;
// 32 random bytes generated on device, hex encoded.
const SECRET_RE = /^[0-9a-f]{64}$/;
const PLATFORMS = new Set(["ios"]);

const json = (statusCode, body) => ({
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
});

function secretHash(secret) {
    return crypto.createHash("sha256").update(secret, "utf8").digest("hex");
}

/** Parse + validate a request body. Returns { value } or { error }. */
function parseRequest(event, { requirePlatform }) {
    let raw = event && event.body;
    if (typeof raw !== "string") return { error: "body required" };
    if (event.isBase64Encoded) raw = Buffer.from(raw, "base64").toString("utf8");
    if (Buffer.byteLength(raw, "utf8") > MAX_BODY_BYTES) return { error: "body too large" };

    let body;
    try {
        body = JSON.parse(raw);
    } catch {
        return { error: "invalid JSON" };
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) return { error: "invalid body" };

    const token = typeof body.device_token === "string" ? body.device_token.toLowerCase() : "";
    if (!TOKEN_RE.test(token)) return { error: "invalid device_token" };

    const secret = typeof body.install_secret === "string" ? body.install_secret.toLowerCase() : "";
    if (!SECRET_RE.test(secret)) return { error: "invalid install_secret" };

    let platform = "ios";
    if (requirePlatform && body.platform !== undefined) {
        if (typeof body.platform !== "string" || !PLATFORMS.has(body.platform)) {
            return { error: "unsupported platform" };
        }
        platform = body.platform;
    }
    return { value: { token, secretHash: secretHash(secret), platform } };
}

function routeOf(event) {
    const path = (event && (event.resource || event.path)) || "";
    if (path.endsWith("/unregister")) return "unregister";
    if (path.endsWith("/register")) return "register";
    return null;
}

function defaultStore(tableName, sdk = require("@aws-sdk/client-dynamodb")) {
    const { DynamoDBClient, UpdateItemCommand, DeleteItemCommand } = sdk;
    const client = new DynamoDBClient({});
    const isConditionFailure = (err) => err && err.name === "ConditionalCheckFailedException";
    return {
        /** Returns false if the row exists with a different secret. */
        async upsert({ token, secretHash: hash, platform, nowIso, ttl }) {
            try {
                await client.send(new UpdateItemCommand({
                    TableName: tableName,
                    Key: { device_token: { S: token } },
                    UpdateExpression:
                        "SET platform = :p, secret_hash = :h, updated_at = :now, #ttl = :ttl, "
                        + "created_at = if_not_exists(created_at, :now)",
                    ConditionExpression: "attribute_not_exists(device_token) OR secret_hash = :h",
                    ExpressionAttributeNames: { "#ttl": "ttl" },
                    ExpressionAttributeValues: {
                        ":p": { S: platform },
                        ":h": { S: hash },
                        ":now": { S: nowIso },
                        ":ttl": { N: String(ttl) },
                    },
                }));
                return true;
            } catch (err) {
                if (isConditionFailure(err)) return false;
                throw err;
            }
        },
        /** Returns false if the row exists with a different secret. */
        async remove({ token, secretHash: hash }) {
            try {
                await client.send(new DeleteItemCommand({
                    TableName: tableName,
                    Key: { device_token: { S: token } },
                    ConditionExpression: "attribute_not_exists(device_token) OR secret_hash = :h",
                    ExpressionAttributeValues: { ":h": { S: hash } },
                }));
                return true;
            } catch (err) {
                if (isConditionFailure(err)) return false;
                throw err;
            }
        },
    };
}

function createHandler(deps = {}) {
    const tableName = process.env.DEVICES_TABLE || "hercules-devices";
    const now = deps.now || Date.now;
    let store = deps.store || null;

    return async function handler(event) {
        const route = routeOf(event);
        if (!route) return json(404, { error: "not found" });

        const parsed = parseRequest(event, { requirePlatform: route === "register" });
        if (parsed.error) return json(400, { error: parsed.error });
        const req = parsed.value;

        if (!store) store = defaultStore(tableName);
        try {
            if (route === "register") {
                const nowMs = now();
                const ok = await store.upsert({
                    ...req,
                    nowIso: new Date(nowMs).toISOString(),
                    ttl: Math.floor(nowMs / 1000) + TTL_DAYS * 86400,
                });
                if (!ok) return json(403, { error: "forbidden" });
                return json(200, { status: "registered" });
            }
            const ok = await store.remove(req);
            if (!ok) return json(403, { error: "forbidden" });
            return json(200, { status: "unregistered" });
        } catch (err) {
            console.error(`${route} failed: ${err.name || "Error"}`);
            return json(500, { error: "internal error" });
        }
    };
}

exports.handler = createHandler();

// Exported for tests.
exports._internal = { createHandler, defaultStore, parseRequest, secretHash, routeOf, TOKEN_RE };
