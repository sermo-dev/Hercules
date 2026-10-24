# Hercules Push Notification Relay

Lightweight server that sends push notifications to Hercules iOS nodes when new Bitcoin blocks arrive.

## Architecture

```
Bitcoin Core (blocknotify) → SQS → Lambda (notify) → APNs → iOS devices
                              ↓                               ↑
                             DLQ      Lambda (register) ← iOS app POST /register, /unregister
```

- `register/` — `POST /register` and `POST /unregister` behind API Gateway with stage-level throttling.
- `notify/` — SQS-triggered. Pages through every device row and sends a silent push over one reused HTTP/2 connection to APNs with bounded concurrency.
- Neither Lambda has npm dependencies. The APNs ES256 JWT is signed with Node's built-in `crypto`, and the AWS SDK v3 ships with the `nodejs20.x` runtime. `sam build` / `sam deploy` package each `CodeUri` directory as is.

## What the relay stores

One row per APNs device token in `hercules-devices`, and nothing else:

| Attribute | Meaning |
|---|---|
| `device_token` | APNs token (opaque, per install, per device) |
| `platform` | Always `ios` today |
| `secret_hash` | SHA-256 of a random per-install secret generated on the phone and kept in its Keychain |
| `created_at`, `updated_at` | ISO timestamps |
| `ttl` | Expiry 30 days after the last registration (DynamoDB TTL) |

The per-install secret means only the install that first registered a token can refresh or delete that row. The relay never sees a user identity, contacts, payment codes, or the node's onion key. It does see the client IP of each registration request through API Gateway, which neither Lambda logs.

`hercules-push-log` holds one row per block hash pushed, kept for 24 hours, so a redelivered SQS message never re-pushes every device.

## API

```
POST /register    { "device_token": "<hex>", "platform": "ios", "install_secret": "<64 hex>" }
POST /unregister  { "device_token": "<hex>", "install_secret": "<64 hex>" }
```

- `200` means success. `/unregister` on an unknown token also succeeds.
- `400` means a malformed token (must be 64–200 hex chars), secret, platform, or body.
- `403` means the token is registered with a different secret.
- `429` means you were throttled by API Gateway (`ApiRateLimit` / `ApiBurstLimit`).

The app re-registers on launch (at most once a day) while notifications are enabled, and calls `/unregister` when they're turned off.

## Deploy

### 1. Put the APNs key in SSM Parameter Store

The `.p8` key is stored as an SSM **SecureString**, never as a Lambda environment variable. The notify Lambda reads it once per cold start. CloudFormation can't create SecureString parameters, so create it once by hand:

```bash
aws ssm put-parameter \
  --name /hercules/apns/p8 \
  --type SecureString \
  --value file://AuthKey_XXXXXXXXXX.p8
```

This uses the AWS-managed `aws/ssm` KMS key, which needs no extra IAM grant. If you use a customer-managed KMS key, add `kms:Decrypt` on that key to `NotifyFunction`'s policy. The Lambda accepts the raw PEM or a base64-encoded PEM.

### 2. Deploy the stack

```bash
sam build
sam deploy --guided \
  --parameter-overrides \
    ApnsKeyId=YOUR_KEY_ID \
    ApnsTeamId=YOUR_TEAM_ID \
    ApnsKeyParameterName=/hercules/apns/p8 \
    ApnsTopic=dev.sermo.hercules.app \
    ApnsHost=api.sandbox.push.apple.com
```

Outputs:
- `ApiBaseUrl`: put this in the app's `RelayConfig.defaultBaseURL` (in `NotificationManager.swift`). The app appends `/register` and `/unregister`.
- `QueueUrl` / `QueueArn`: for the blocknotify script and its IAM policy.
- `DeadLetterQueueUrl`: messages that failed 3 times before any device was pushed.

Optional parameters: `ApiRateLimit` (default 5 req/s) and `ApiBurstLimit` (default 10).

### IAM (least privilege)

| Function | Permissions |
|---|---|
| RegisterFunction | `dynamodb:UpdateItem`, `dynamodb:DeleteItem` on `hercules-devices` |
| NotifyFunction | `dynamodb:Scan`, `dynamodb:DeleteItem` on `hercules-devices`; `dynamodb:PutItem`, `dynamodb:DeleteItem` on `hercules-push-log`; `ssm:GetParameter` on the key parameter |

## Delivery behaviour

- **Pagination.** The device scan follows `LastEvaluatedKey`, so tables larger than 1 MB are fully covered.
- **Connection reuse.** One HTTP/2 session to APNs per warm Lambda container, at most `APNS_CONCURRENCY` (default 50) streams in flight. New sends stop 3 s before the 60 s Lambda timeout.
- **Token pruning.** A row is deleted on HTTP 410 (`Unregistered`), `BadDeviceToken`, or `DeviceTokenNotForTopic`.
- **Retries.** 429, 500, 503 and transport errors are retried once in the same invocation. `ExpiredProviderToken` re-signs the JWT once. JWTs are otherwise cached for 50 minutes.
- **Idempotency.** Before fan-out, the Lambda conditionally claims the block hash in `hercules-push-log`.
  - If the claim already exists, the message is skipped.
  - Failures *before* fan-out (key load, claim, first scan page) release the claim and throw, so SQS retries. After 3 receives the message goes to the DLQ.
  - Failures *after* fan-out starts are logged and swallowed, so no device gets pushed twice for one block.
- **Staleness.** Messages older than 30 minutes (`MAX_MESSAGE_AGE_SECONDS`) are dropped, so redriving the DLQ late doesn't wake phones for old blocks. Malformed messages are dropped.

## Bitcoin Core Setup

Add to `bitcoin.conf`:

```
blocknotify=/usr/local/bin/hercules-notify.sh %s
```

Create `/usr/local/bin/hercules-notify.sh` (run `chmod +x` on it). It must run as the same user as `bitcoind` so `bitcoin-cli` can read the RPC cookie:

```bash
#!/bin/bash
# Called by bitcoind as: hercules-notify.sh <blockhash>
# bitcoind discards blocknotify output, so everything goes to a log file.
set -u
QUEUE_URL="YOUR_SQS_QUEUE_URL"
LOG="${HERCULES_NOTIFY_LOG:-/var/log/hercules-notify.log}"
HASH="${1:-}"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$LOG"; }

[[ "$HASH" =~ ^[0-9a-f]{64}$ ]] || { log "ignoring malformed hash: $HASH"; exit 1; }

# blocknotify fires for every connected block during IBD / -reindex.
# Don't wake every phone hundreds of times while catching up.
if bitcoin-cli getblockchaininfo 2>/dev/null | grep -q '"initialblockdownload": true'; then
  exit 0
fi

# Look up height and header timestamp. If bitcoin-cli fails, still send the
# hash; the relay omits height and the app falls back to its own state.
HEADER=$(bitcoin-cli getblockheader "$HASH" 2>/dev/null || true)
HEIGHT=$(printf '%s\n' "$HEADER" | sed -n 's/^ *"height": *\([0-9][0-9]*\),*$/\1/p')
TIME=$(printf '%s\n' "$HEADER" | sed -n 's/^ *"time": *\([0-9][0-9]*\),*$/\1/p')
TIME="${TIME:-$(date +%s)}"

if [[ -n "$HEIGHT" ]]; then
  BODY="{\"hash\":\"$HASH\",\"height\":$HEIGHT,\"time\":$TIME}"
else
  log "getblockheader failed for $HASH; sending without height"
  BODY="{\"hash\":\"$HASH\",\"time\":$TIME}"
fi

# Route the AWS API call through Tor so AWS doesn't see the node's IP.
torsocks aws --profile hercules-notify sqs send-message \
  --queue-url "$QUEUE_URL" \
  --message-body "$BODY" >> "$LOG" 2>&1 || log "send-message failed for $HASH"
```

The SQS message is `{"hash": "...", "height": 870000, "time": 1712234567}`, where `time` is the block header timestamp. The notify Lambda passes `height` through to the push payload as `block.height`. If the message has no height, the payload omits `block.height` rather than sending `0`, and the app falls back to its own last-known height.

## IAM Policy for Bitcoin Node

The node only needs `sqs:SendMessage` on the queue:

```json
{
  "Effect": "Allow",
  "Action": "sqs:SendMessage",
  "Resource": "YOUR_SQS_QUEUE_ARN"
}
```

## Tests

```bash
cd server && npm test   # node:test, no AWS or APNs calls (clients are mocked)
```

## Cost

Negligible at small scale:
- The Lambda free tier covers millions of invocations.
- DynamoDB on-demand costs pennies.
- SQS is free for the first million messages.
- SSM standard parameters are free.
