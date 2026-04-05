// Hercules Push Relay — Block Notification Lambda
//
// Triggered by SQS when Bitcoin Core's blocknotify fires.
// Reads all device tokens from DynamoDB and sends a silent APNs push
// to each one with the new block's height, hash, and timestamp.
//
// SQS message format: { "hash": "000000...", "time": 1712234567 }
//
// Requires environment variables:
//   DEVICES_TABLE  — DynamoDB table name (default: "hercules-devices")
//   APNS_KEY_ID    — APNs key ID from Apple Developer account
//   APNS_TEAM_ID   — Apple Developer Team ID
//   APNS_KEY_BASE64 — Base64-encoded .p8 private key
//   APNS_TOPIC     — App bundle ID (dev.sermo.hercules.app)
//   APNS_HOST      — api.push.apple.com (production) or api.sandbox.push.apple.com

const { DynamoDBClient, ScanCommand, DeleteItemCommand } = require("@aws-sdk/client-dynamodb");
const http2 = require("http2");
const jwt = require("jsonwebtoken");

const DEVICES_TABLE = process.env.DEVICES_TABLE || "hercules-devices";
const APNS_HOST = process.env.APNS_HOST || "api.sandbox.push.apple.com";
const APNS_TOPIC = process.env.APNS_TOPIC || "dev.sermo.hercules.app";

exports.handler = async (event) => {
    const dynamo = new DynamoDBClient({});

    for (const record of event.Records) {
        const block = JSON.parse(record.body);
        const height = block.height || 0;
        const hash = block.hash || "";
        const timestamp = block.time || 0;

        // Build APNs JWT
        const apnsKey = Buffer.from(process.env.APNS_KEY_BASE64 || "", "base64").toString("utf8");
        const token = jwt.sign({}, apnsKey, {
            algorithm: "ES256",
            keyid: process.env.APNS_KEY_ID,
            issuer: process.env.APNS_TEAM_ID,
            header: { alg: "ES256", kid: process.env.APNS_KEY_ID },
        });

        // Build silent push payload
        const payload = JSON.stringify({
            aps: { "content-available": 1 },
            block: { height, hash, timestamp },
        });

        // Scan all device tokens
        const devices = await dynamo.send(
            new ScanCommand({
                TableName: DEVICES_TABLE,
                ProjectionExpression: "device_token",
            })
        );

        if (!devices.Items || devices.Items.length === 0) {
            console.log("No registered devices");
            continue;
        }

        console.log(`Sending block #${height} notification to ${devices.Items.length} devices`);

        // Send to each device via APNs HTTP/2
        const results = await Promise.allSettled(
            devices.Items.map((item) =>
                sendAPNs(item.device_token.S, payload, token)
            )
        );

        // Clean up invalid tokens
        for (let i = 0; i < results.length; i++) {
            if (results[i].status === "rejected" && results[i].reason === "BadDeviceToken") {
                const badToken = devices.Items[i].device_token.S;
                console.log(`Removing invalid token: ${badToken.substring(0, 8)}...`);
                await dynamo.send(
                    new DeleteItemCommand({
                        TableName: DEVICES_TABLE,
                        Key: { device_token: { S: badToken } },
                    })
                );
            }
        }
    }
};

function sendAPNs(deviceToken, payload, jwtToken) {
    return new Promise((resolve, reject) => {
        const client = http2.connect(`https://${APNS_HOST}`);

        const req = client.request({
            ":method": "POST",
            ":path": `/3/device/${deviceToken}`,
            authorization: `bearer ${jwtToken}`,
            "apns-topic": APNS_TOPIC,
            "apns-push-type": "background",
            "apns-priority": "5",
        });

        req.setEncoding("utf8");
        let data = "";

        req.on("response", (headers) => {
            const status = headers[":status"];
            if (status === 200) {
                resolve();
            } else {
                req.on("data", (chunk) => (data += chunk));
                req.on("end", () => {
                    try {
                        const body = JSON.parse(data);
                        reject(body.reason || `HTTP ${status}`);
                    } catch {
                        reject(`HTTP ${status}`);
                    }
                });
            }
        });

        req.write(payload);
        req.end();

        req.on("error", reject);
        req.on("close", () => client.close());
    });
}
