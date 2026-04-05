// Hercules Push Relay — Device Registration Lambda
//
// POST /register
// Body: { "device_token": "abc123...", "platform": "ios" }
//
// Stores token in DynamoDB with a 30-day TTL. Tokens are re-registered
// on each app launch (iOS can rotate them), so stale entries expire naturally.

const { DynamoDBClient, PutItemCommand } = require("@aws-sdk/client-dynamodb");

const DEVICES_TABLE = process.env.DEVICES_TABLE || "hercules-devices";
const TTL_DAYS = 30;

exports.handler = async (event) => {
    let body;
    try {
        body = JSON.parse(event.body);
    } catch {
        return { statusCode: 400, body: JSON.stringify({ error: "invalid JSON" }) };
    }

    const { device_token, platform } = body;
    if (!device_token) {
        return { statusCode: 400, body: JSON.stringify({ error: "device_token required" }) };
    }

    const client = new DynamoDBClient({});
    const ttl = Math.floor(Date.now() / 1000) + TTL_DAYS * 86400;

    await client.send(
        new PutItemCommand({
            TableName: DEVICES_TABLE,
            Item: {
                device_token: { S: device_token },
                platform: { S: platform || "ios" },
                registered_at: { S: new Date().toISOString() },
                ttl: { N: String(ttl) },
            },
        })
    );

    return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "registered" }),
    };
};
