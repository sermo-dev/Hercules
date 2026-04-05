# Hercules Push Notification Relay

Lightweight server that sends push notifications to Hercules iOS nodes when new Bitcoin blocks arrive.

## Architecture

```
Bitcoin Core (blocknotify) → SQS → Lambda (notify) → APNs → iOS devices
                                                             ↑
                                   Lambda (register) ← iOS app POST /register
```

## Prerequisites

- AWS account with SAM CLI installed
- Apple Developer account with APNs key (.p8 file)
- Bitcoin Core node with `blocknotify` configured

## Deploy

```bash
# Generate base64 key from your .p8 file
APNS_KEY=$(base64 < AuthKey_XXXXXXXXXX.p8)

sam deploy --guided \
  --parameter-overrides \
    ApnsKeyId=YOUR_KEY_ID \
    ApnsTeamId=YOUR_TEAM_ID \
    ApnsKeyBase64=$APNS_KEY \
    ApnsHost=api.sandbox.push.apple.com
```

## Bitcoin Core Setup

Add to `bitcoin.conf`:

```
blocknotify=/usr/local/bin/hercules-notify.sh %s
```

Create `/usr/local/bin/hercules-notify.sh`:

```bash
#!/bin/bash
# Route through Tor for privacy (optional)
torsocks aws sqs send-message \
  --queue-url YOUR_SQS_QUEUE_URL \
  --message-body "{\"hash\": \"$1\", \"time\": $(date +%s)}"
```

The notify Lambda enriches the message with block height by querying
the block hash — or you can extend the script to include height from
`bitcoin-cli getblockheader`.

## IAM Policy for Bitcoin Node

The node only needs `sqs:SendMessage` on the queue:

```json
{
  "Effect": "Allow",
  "Action": "sqs:SendMessage",
  "Resource": "YOUR_SQS_QUEUE_ARN"
}
```

## Cost

Negligible at small scale: Lambda free tier covers millions of invocations,
DynamoDB on-demand is pennies, SQS is free tier for the first million messages.
