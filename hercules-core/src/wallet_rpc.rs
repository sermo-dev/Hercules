//! Wallet-facing JSON-RPC 2.0 server over HTTP/1.1.
//!
//! Runs on a dedicated Tor onion service (separate from the P2P onion)
//! and provides read-only access to node state plus transaction broadcast.
//! See ticket 014 for design rationale.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::BlockHash;
use log::{info, warn};
use serde::{Deserialize, Serialize};

use crate::sync::HeaderSync;
use crate::tor::TorManager;

// ── JSON-RPC 2.0 types ──────────────────────────────────────────────

#[derive(Deserialize)]
struct RpcRequest {
    jsonrpc: Option<String>,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl RpcResponse {
    fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        RpcResponse {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    fn err(id: serde_json::Value, code: i32, message: String) -> Self {
        RpcResponse {
            jsonrpc: "2.0",
            result: None,
            error: Some(RpcError { code, message }),
            id,
        }
    }
}

// Standard JSON-RPC error codes.
const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;
const INTERNAL_ERROR: i32 = -32603;
// Application-specific codes.
const BLOCK_PRUNED: i32 = -1;
const TX_REJECTED: i32 = -2;

// ── HTTP/1.1 minimal parser ─────────────────────────────────────────

/// Maximum request body size (1 MB — comfortably above max signed tx).
const MAX_BODY_SIZE: usize = 1_048_576;
/// Maximum number of HTTP headers we'll read before giving up.
const MAX_HEADER_COUNT: usize = 64;
/// Maximum length of any single HTTP line (request line or header).
const MAX_LINE_LENGTH: usize = 8192;
/// Idle timeout for keepalive connections (matches Bitcoin Core's default).
const KEEPALIVE_TIMEOUT_SECS: u64 = 30;
/// A request, once its first byte is in, must arrive in full within this
/// (ticket 049): a client sending a byte per read timeout can't hold its
/// connection for hours. Test builds shrink it so the bound is testable.
#[cfg(not(test))]
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(KEEPALIVE_TIMEOUT_SECS);
#[cfg(test)]
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// How long one response write may wait for the client to take bytes.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(KEEPALIVE_TIMEOUT_SECS);
/// Connections served at once, each on its own thread (ticket 049), so one
/// slow client can't keep the others out. More are dropped.
const MAX_CONNECTIONS: usize = 4;

/// The head of an HTTP/1.1 request: method, path, lower-cased headers.
type HttpHead = (String, String, HashMap<String, String>);

/// Read one line (through `\n`) of at most `MAX_LINE_LENGTH` bytes (ticket
/// 049): a longer one is refused after reading just past the limit, never
/// buffered whole. `Ok(None)` at a clean end of stream.
fn read_bounded_line<R: Read>(reader: &mut BufReader<R>, what: &str) -> Result<Option<String>, String> {
    let mut line = Vec::new();
    let n = reader
        .by_ref()
        .take(MAX_LINE_LENGTH as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(|e| format!("read {}: {}", what, e))?;
    if n == 0 {
        return Ok(None);
    }
    if line.len() > MAX_LINE_LENGTH {
        return Err(format!("{} too long", what));
    }
    Ok(Some(String::from_utf8_lossy(&line).into_owned()))
}

/// Read the request line and headers of one HTTP/1.1 request, everything
/// bounded (ticket 049), so it costs at most `MAX_HEADER_COUNT` lines of
/// `MAX_LINE_LENGTH` before the caller checks auth. The caller owns the
/// `BufReader` so it persists across requests on a keepalive connection.
/// Returns `Err` on disconnect, timeout, or malformed input.
fn read_http_head<R: Read>(reader: &mut BufReader<R>) -> Result<HttpHead, String> {
    // Read request line.
    let request_line = read_bounded_line(reader, "request line")?
        .ok_or_else(|| "client disconnected".to_string())?;
    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err("malformed request line".into());
    }
    let method = parts[0].to_uppercase();
    let path = parts[1].to_string();

    // Read headers.
    let mut headers = HashMap::new();
    for _ in 0..MAX_HEADER_COUNT {
        let Some(line) = read_bounded_line(reader, "header line")? else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    // The body's size is known now, before anything else is read.
    let content_length = content_length(&headers);
    if content_length > MAX_BODY_SIZE {
        return Err(format!("body too large: {} > {}", content_length, MAX_BODY_SIZE));
    }
    Ok((method, path, headers))
}

fn content_length(headers: &HashMap<String, String>) -> usize {
    headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Read the body of a request whose head `read_http_head` accepted.
fn read_http_body<R: Read>(reader: &mut BufReader<R>, headers: &HashMap<String, String>) -> Result<Vec<u8>, String> {
    let content_length = content_length(headers);
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|e| format!("read body: {}", e))?;
    }
    Ok(body)
}

/// Read one whole HTTP/1.1 request (head and body).
fn read_http_request<R: Read>(
    reader: &mut BufReader<R>,
) -> Result<(String, String, HashMap<String, String>, Vec<u8>), String> {
    let (method, path, headers) = read_http_head(reader)?;
    let body = read_http_body(reader, &headers)?;
    Ok((method, path, headers, body))
}

/// Write an HTTP/1.1 response. When `close` is true the `Connection: close`
/// header signals the client that the server is done; otherwise
/// `Connection: keep-alive` with a timeout hint keeps the stream open.
fn write_http_response<W: Write>(
    stream: &mut W,
    status: u16,
    status_text: &str,
    body: &[u8],
    close: bool,
) -> std::io::Result<()> {
    if close {
        write!(
            stream,
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status, status_text, body.len()
        )?;
    } else {
        write!(
            stream,
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\nKeep-Alive: timeout={}\r\n\r\n",
            status, status_text, body.len(), KEEPALIVE_TIMEOUT_SECS
        )?;
    }
    stream.write_all(body)?;
    stream.flush()
}

// ── Authentication ──────────────────────────────────────────────────

/// Verify HTTP Basic auth. Returns true if the provided credentials match.
/// Uses constant-time comparison to prevent timing attacks.
fn verify_auth(headers: &HashMap<String, String>, expected_token: &str) -> bool {
    let auth = match headers.get("authorization") {
        Some(a) => a,
        None => return false,
    };

    // Expect "Basic <base64(user:token)>". We ignore the username.
    let encoded = match auth.strip_prefix("Basic ") {
        Some(e) => e,
        None => return false,
    };

    // Decode base64.
    let decoded = match base64_decode(encoded.trim()) {
        Some(d) => d,
        None => return false,
    };

    // Extract the password part after the colon.
    let password = match decoded.split_once(':') {
        Some((_, p)) => p,
        None => return false,
    };

    // Constant-time comparison.
    constant_time_eq(password.as_bytes(), expected_token.as_bytes())
}

/// Minimal base64 decoder (standard alphabet, with padding).
fn base64_decode(input: &str) -> Option<String> {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        table[c as usize] = i as u8;
    }

    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let bytes = input.as_bytes();

    for chunk in bytes.chunks(4) {
        let mut buf: u32 = 0;
        let mut count = 0;
        for &b in chunk {
            let val = table[b as usize];
            if val == 255 {
                return None;
            }
            buf = (buf << 6) | val as u32;
            count += 1;
        }
        buf <<= (4 - count) * 6;
        let out_bytes = count * 6 / 8;
        for i in 0..out_bytes {
            output.push((buf >> (16 - i * 8)) as u8);
        }
    }

    String::from_utf8(output).ok()
}

/// Minimal base64 encoder (standard alphabet, with padding).
#[cfg(test)]
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        output.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        output.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Rate limiter ────────────────────────────────────────────────────

/// Simple per-connection rate limiter (not per-IP, since all traffic is Tor).
struct RateLimiter {
    max_requests: u32,
    window: std::time::Duration,
    timestamps: Vec<Instant>,
}

impl RateLimiter {
    fn new(max_requests: u32, window: std::time::Duration) -> Self {
        RateLimiter {
            max_requests,
            window,
            timestamps: Vec::new(),
        }
    }

    /// Returns true if the request should be allowed.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        self.timestamps.retain(|t| now.duration_since(*t) < self.window);
        if self.timestamps.len() >= self.max_requests as usize {
            return false;
        }
        self.timestamps.push(now);
        true
    }
}

// ── RPC dispatch ────────────────────────────────────────────────────

/// Handle a single JSON-RPC request and return the response.
fn dispatch(syncer: &HeaderSync, request: &RpcRequest) -> RpcResponse {
    let id = request.id.clone();
    match request.method.as_str() {
        "get_tip" => handle_get_tip(syncer, id),
        "get_block_header" => handle_get_block_header(syncer, &request.params, id),
        "get_block_hash" => handle_get_block_hash(syncer, &request.params, id),
        "get_block" => handle_get_block(syncer, &request.params, id),
        "get_utxo" => handle_get_utxo(syncer, &request.params, id),
        "get_mempool_entry" => handle_get_mempool_entry(syncer, &request.params, id),
        "get_fee_estimates" => handle_get_fee_estimates(syncer, id),
        "broadcast_transaction" => handle_broadcast_transaction(syncer, &request.params, id),
        "get_broadcast_status" => handle_get_broadcast_status(syncer, &request.params, id),
        "get_compact_filter" => handle_get_compact_filter(id),
        "get_node_info" => handle_get_node_info(syncer, id),
        _ => RpcResponse::err(id, METHOD_NOT_FOUND, format!("unknown method: {}", request.method)),
    }
}

// ── Individual RPC handlers ─────────────────────────────────────────

fn handle_get_tip(syncer: &HeaderSync, id: serde_json::Value) -> RpcResponse {
    match syncer.rpc_get_tip() {
        Ok(Some((height, hash, header))) => {
            let validated = syncer.rpc_validated_height().unwrap_or(0);
            let is_stale = header.time < (now_unix() - 1800) as u32; // 30 min
            RpcResponse::ok(
                id,
                serde_json::json!({
                    "height": height,
                    "hash": hash.to_string(),
                    "time": header.time,
                    "validated_height": validated,
                    "is_stale": is_stale,
                }),
            )
        }
        Ok(None) => RpcResponse::ok(id, serde_json::Value::Null),
        Err(e) => RpcResponse::err(id, INTERNAL_ERROR, format!("{}", e)),
    }
}

fn handle_get_block_header(
    syncer: &HeaderSync,
    params: &serde_json::Value,
    id: serde_json::Value,
) -> RpcResponse {
    // Accept either {"height": N} or {"hash": "hex"}.
    if let Some(height) = params.get("height").and_then(|v| v.as_u64()) {
        let Ok(height) = u32::try_from(height) else {
            return RpcResponse::err(id, INVALID_PARAMS, format!("height {} out of range", height));
        };
        match syncer.rpc_get_header_at_height(height) {
            Ok(Some((hash, header))) => RpcResponse::ok(
                id,
                serde_json::json!({
                    "hash": hash.to_string(),
                    "height": height,
                    "version": header.version.to_consensus(),
                    "prev_block_hash": header.prev_blockhash.to_string(),
                    "merkle_root": header.merkle_root.to_string(),
                    "time": header.time,
                    "bits": header.bits.to_consensus(),
                    "nonce": header.nonce,
                }),
            ),
            Ok(None) => RpcResponse::ok(id, serde_json::Value::Null),
            Err(e) => RpcResponse::err(id, INTERNAL_ERROR, format!("{}", e)),
        }
    } else if let Some(hash_str) = params.get("hash").and_then(|v| v.as_str()) {
        let hash = match hash_str.parse::<BlockHash>() {
            Ok(h) => h,
            Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("bad hash: {}", e)),
        };
        match syncer.rpc_find_height(hash) {
            Ok(Some(height)) => {
                // Recurse with height.
                let params = serde_json::json!({"height": height});
                handle_get_block_header(syncer, &params, id)
            }
            Ok(None) => RpcResponse::ok(id, serde_json::Value::Null),
            Err(e) => RpcResponse::err(id, INTERNAL_ERROR, format!("{}", e)),
        }
    } else {
        RpcResponse::err(id, INVALID_PARAMS, "expected {\"height\": N} or {\"hash\": \"hex\"}".into())
    }
}

fn handle_get_block_hash(
    syncer: &HeaderSync,
    params: &serde_json::Value,
    id: serde_json::Value,
) -> RpcResponse {
    let height = match params.get("height").and_then(|v| v.as_u64()) {
        Some(h) => match u32::try_from(h) {
            Ok(h) => h,
            Err(_) => return RpcResponse::err(id, INVALID_PARAMS, format!("height {} out of range", h)),
        },
        None => return RpcResponse::err(id, INVALID_PARAMS, "expected {\"height\": N}".into()),
    };
    match syncer.rpc_get_block_hash(height) {
        Ok(Some(hash)) => RpcResponse::ok(id, serde_json::json!(hash.to_string())),
        Ok(None) => RpcResponse::ok(id, serde_json::Value::Null),
        Err(e) => RpcResponse::err(id, INTERNAL_ERROR, format!("{}", e)),
    }
}

fn handle_get_block(
    syncer: &HeaderSync,
    params: &serde_json::Value,
    id: serde_json::Value,
) -> RpcResponse {
    let hash_str = match params.get("hash").and_then(|v| v.as_str()) {
        Some(h) => h,
        None => return RpcResponse::err(id, INVALID_PARAMS, "expected {\"hash\": \"hex\"}".into()),
    };
    let hash = match hash_str.parse::<BlockHash>() {
        Ok(h) => h,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("bad hash: {}", e)),
    };
    match syncer.rpc_get_block(&hash) {
        Ok(Some(block)) => {
            RpcResponse::ok(id, serde_json::json!({"hex": serialize_hex(&block)}))
        }
        Ok(None) => RpcResponse::err(id, BLOCK_PRUNED, "block not in prune window".into()),
        Err(e) => RpcResponse::err(id, INTERNAL_ERROR, format!("{}", e)),
    }
}

fn handle_get_utxo(
    syncer: &HeaderSync,
    params: &serde_json::Value,
    id: serde_json::Value,
) -> RpcResponse {
    let txid_str = match params.get("txid").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => {
            return RpcResponse::err(
                id,
                INVALID_PARAMS,
                "expected {\"txid\": \"hex\", \"vout\": N}".into(),
            )
        }
    };
    let vout = match params.get("vout").and_then(|v| v.as_u64()) {
        Some(v) => match u32::try_from(v) {
            Ok(v) => v,
            Err(_) => return RpcResponse::err(id, INVALID_PARAMS, format!("vout {} out of range", v)),
        },
        None => {
            return RpcResponse::err(
                id,
                INVALID_PARAMS,
                "expected {\"txid\": \"hex\", \"vout\": N}".into(),
            )
        }
    };
    let txid = match txid_str.parse::<bitcoin::Txid>() {
        Ok(t) => t,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("bad txid: {}", e)),
    };
    match syncer.rpc_get_utxo(&txid, vout) {
        Ok(Some(entry)) => RpcResponse::ok(
            id,
            serde_json::json!({
                "value": entry.amount,
                "script_pubkey": hex::encode(&entry.script_pubkey),
                "height": entry.height,
                "is_coinbase": entry.is_coinbase,
            }),
        ),
        Ok(None) => RpcResponse::ok(id, serde_json::Value::Null),
        Err(e) => RpcResponse::err(id, INTERNAL_ERROR, format!("{}", e)),
    }
}

fn handle_get_mempool_entry(
    syncer: &HeaderSync,
    params: &serde_json::Value,
    id: serde_json::Value,
) -> RpcResponse {
    let txid_str = match params.get("txid").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return RpcResponse::err(id, INVALID_PARAMS, "expected {\"txid\": \"hex\"}".into()),
    };
    let txid = match txid_str.parse::<bitcoin::Txid>() {
        Ok(t) => t,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("bad txid: {}", e)),
    };
    match syncer.rpc_get_mempool_entry(&txid) {
        Some(info) => RpcResponse::ok(
            id,
            serde_json::json!({
                "fee": info.fee,
                "vsize": info.vsize,
                "fee_rate": info.fee_rate,
                "ancestor_count": info.ancestor_count,
                "descendant_count": info.descendant_count,
                "ancestor_fee": info.ancestor_fee,
                "ancestor_vsize": info.ancestor_vsize,
            }),
        ),
        None => RpcResponse::ok(id, serde_json::Value::Null),
    }
}

fn handle_get_fee_estimates(syncer: &HeaderSync, id: serde_json::Value) -> RpcResponse {
    let est = syncer.rpc_get_fee_estimates();
    RpcResponse::ok(
        id,
        serde_json::json!({
            "1": est.one_block,
            "6": est.six_blocks,
            "12": est.twelve_blocks,
            "24": est.twenty_four_blocks,
            "144": est.one_forty_four_blocks,
        }),
    )
}

fn handle_broadcast_transaction(
    syncer: &HeaderSync,
    params: &serde_json::Value,
    id: serde_json::Value,
) -> RpcResponse {
    let hex_str = match params.get("hex").and_then(|v| v.as_str()) {
        Some(h) => h,
        None => return RpcResponse::err(id, INVALID_PARAMS, "expected {\"hex\": \"rawtx\"}".into()),
    };
    let raw = match hex::decode(hex_str) {
        Ok(r) => r,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("bad hex: {}", e)),
    };
    broadcast_response(syncer.submit_own_tx(&raw), id)
}

/// Map an own-tx submission (ticket 033) to a JSON-RPC response.
///
/// Success keeps the 014 shape (`{"txid": ...}`) and adds `warnings`.
/// `AlreadyKnown` is reported as success with `"already_known": true`:
/// the tx is in our mempool, tracked and re-announced, which is what a
/// wallet retrying a send wants (Bitcoin Core's `sendrawtransaction`
/// behaves the same). Rejections use `TX_REJECTED` with
/// `"<kind>: <message>"` so clients can tell a consensus failure from a
/// standardness/fee problem or an unsynced node.
fn broadcast_response(
    result: Result<crate::own_tx_store::OwnTxReceipt, crate::own_tx_store::SubmitError>,
    id: serde_json::Value,
) -> RpcResponse {
    use crate::own_tx_store::SubmitError;
    match result {
        Ok(receipt) => RpcResponse::ok(
            id,
            serde_json::json!({
                "txid": receipt.txid.to_string(),
                "already_known": false,
                "warnings": receipt.warnings,
            }),
        ),
        Err(SubmitError::AlreadyKnown { txid }) => RpcResponse::ok(
            id,
            serde_json::json!({
                "txid": txid.to_string(),
                "already_known": true,
                "warnings": Vec::<String>::new(),
            }),
        ),
        Err(e) => RpcResponse::err(id, TX_REJECTED, format!("{}: {}", e.kind(), e)),
    }
}

fn handle_get_broadcast_status(
    syncer: &HeaderSync,
    params: &serde_json::Value,
    id: serde_json::Value,
) -> RpcResponse {
    let txid = match params
        .get("txid")
        .and_then(|v| v.as_str())
        .map(|t| t.parse::<bitcoin::Txid>())
    {
        Some(Ok(t)) => t,
        Some(Err(e)) => return RpcResponse::err(id, INVALID_PARAMS, format!("bad txid: {}", e)),
        None => return RpcResponse::err(id, INVALID_PARAMS, "expected {\"txid\": \"hex\"}".into()),
    };
    match syncer.own_tx_status(&txid) {
        Ok(Some(rec)) => RpcResponse::ok(id, own_tx_json(&rec)),
        Ok(None) => RpcResponse::ok(id, serde_json::Value::Null),
        Err(e) => RpcResponse::err(id, INTERNAL_ERROR, format!("{}", e)),
    }
}

fn own_tx_json(rec: &crate::own_tx_store::OwnTxRecord) -> serde_json::Value {
    use crate::own_tx_store::OwnTxStatus;
    let (height, related) = match &rec.status {
        OwnTxStatus::Confirmed { height } => (Some(*height), None),
        OwnTxStatus::Replaced { by } | OwnTxStatus::Conflicted { by } => (None, Some(by.to_string())),
        _ => (None, None),
    };
    serde_json::json!({
        "txid": rec.txid.to_string(),
        "status": rec.status.name(),
        "confirmed_height": height,
        "related_txid": related,
        "first_sent_at": rec.first_sent_at,
        "last_sent_at": rec.last_sent_at,
        "attempts": rec.attempts,
        "seen_from_peers": rec.seen_from_peers,
        "delivered_to_peers": rec.delivered_to_peers,
        "delivery": rec.delivery().name(),
    })
}

fn handle_get_compact_filter(id: serde_json::Value) -> RpcResponse {
    // Compact filter serving is deferred to a future ticket.
    RpcResponse::err(
        id,
        METHOD_NOT_FOUND,
        "compact filter serving not yet implemented".into(),
    )
}

fn handle_get_node_info(syncer: &HeaderSync, id: serde_json::Value) -> RpcResponse {
    let status = syncer.get_node_status();
    let mempool = syncer.get_mempool_status();
    let validated = syncer.rpc_validated_height().unwrap_or(0);
    let tip_height = syncer
        .rpc_get_tip()
        .ok()
        .flatten()
        .map(|(h, _, _)| h)
        .unwrap_or(0);

    RpcResponse::ok(
        id,
        serde_json::json!({
            "version": crate::hercules_version(),
            "tip_height": tip_height,
            "validated_height": validated,
            "mempool_tx_count": mempool.tx_count,
            "mempool_size": mempool.total_size,
            "inbound_peers": status.inbound_peers,
            "outbound_peers": status.outbound_peers,
            "blocks_served": status.blocks_served,
            "txs_relayed": status.txs_relayed,
        }),
    )
}

// ── Server ──────────────────────────────────────────────────────────

/// How often an idle keep-alive connection checks for server shutdown
/// (ticket 028: stopping the server must not wait out the 30 s idle
/// timeout).
const SHUTDOWN_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// A stream the RPC server can serve: Tor in production, TCP in tests.
trait RpcStream: Read + Write {
    fn set_rpc_read_timeout(&mut self, timeout: std::time::Duration);
    fn set_rpc_write_timeout(&mut self, timeout: std::time::Duration);
}

impl RpcStream for crate::tor::TorStream {
    fn set_rpc_read_timeout(&mut self, timeout: std::time::Duration) {
        self.set_read_timeout(Some(timeout));
    }
    fn set_rpc_write_timeout(&mut self, timeout: std::time::Duration) {
        self.set_write_timeout(Some(timeout));
    }
}

#[cfg(test)]
impl RpcStream for std::net::TcpStream {
    fn set_rpc_read_timeout(&mut self, timeout: std::time::Duration) {
        let _ = self.set_read_timeout(Some(timeout));
    }
    fn set_rpc_write_timeout(&mut self, timeout: std::time::Duration) {
        let _ = self.set_write_timeout(Some(timeout));
    }
}

/// One served connection's stream (ticket 049): every read waits at most
/// until `deadline` (the keep-alive idle limit between requests, then
/// `REQUEST_TIMEOUT` for the request itself) and gives up as soon as the
/// server shuts down; every write waits at most `WRITE_TIMEOUT`.
struct RpcConn<'a, S: RpcStream> {
    stream: S,
    deadline: Instant,
    shutdown: &'a AtomicBool,
}

impl<'a, S: RpcStream> RpcConn<'a, S> {
    fn new(mut stream: S, shutdown: &'a AtomicBool) -> Self {
        stream.set_rpc_write_timeout(WRITE_TIMEOUT);
        RpcConn { stream, deadline: Instant::now(), shutdown }
    }
}

impl<S: RpcStream> Read for RpcConn<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "server shutting down"));
            }
            let left = self.deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out"));
            }
            // Short reads, so a shutdown is noticed within SHUTDOWN_POLL.
            self.stream
                .set_rpc_read_timeout(left.min(SHUTDOWN_POLL).max(std::time::Duration::from_millis(1)));
            match self.stream.read(buf) {
                Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => {}
                other => return other,
            }
        }
    }
}

impl<S: RpcStream> Write for RpcConn<'_, S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// Wait until the next request's first bytes arrive. False if the client
/// went away, stayed idle past the keep-alive timeout, or the server is
/// shutting down.
fn await_next_request<S: RpcStream>(reader: &mut BufReader<RpcConn<'_, S>>) -> bool {
    reader.get_mut().deadline = Instant::now() + std::time::Duration::from_secs(KEEPALIVE_TIMEOUT_SECS);
    match reader.fill_buf() {
        Ok(buf) if buf.is_empty() => return false, // disconnected
        Ok(_) => {}
        Err(_) => return false, // idle too long, shutting down, or gone
    }
    // A request is arriving: it has REQUEST_TIMEOUT to finish.
    reader.get_mut().deadline = Instant::now() + REQUEST_TIMEOUT;
    true
}

/// Handle an inbound wallet connection. Supports HTTP/1.1 keepalive:
/// multiple JSON-RPC requests can be sent on the same Tor stream,
/// matching Bitcoin Core's RPC server behavior. The connection closes
/// on idle timeout (30s), auth failure, `Connection: close` from the
/// client, or server shutdown (checked while idle and between requests).
fn handle_connection<S: RpcStream>(
    syncer: &HeaderSync,
    stream: S,
    auth_token: &str,
    shutdown: &AtomicBool,
) {
    let mut reader = BufReader::new(RpcConn::new(stream, shutdown));

    loop {
        if !await_next_request(&mut reader) {
            break;
        }

        // ── Read one HTTP request ──────────────────────────────────
        // Bounded before auth (ticket 049): at most MAX_HEADER_COUNT
        // lines of MAX_LINE_LENGTH and a MAX_BODY_SIZE body, within
        // REQUEST_TIMEOUT.
        let (method, _path, headers, body) = match read_http_request(&mut reader) {
            Ok(r) => r,
            Err(e) => {
                // Timeout, clean disconnect or shutdown — normal keepalive exit.
                if !e.contains("client disconnected") && !e.contains("timed out") && !e.contains("shutting down") {
                    warn!("wallet_rpc: bad HTTP request: {}", e);
                    let _ = write_http_response(reader.get_mut(), 400, "Bad Request", b"bad request", true);
                }
                break;
            }
        };

        let client_wants_close = headers
            .get("connection")
            .map(|v| v.eq_ignore_ascii_case("close"))
            .unwrap_or(false);

        // ── Validate HTTP method ───────────────────────────────────
        if method != "POST" {
            let _ = write_http_response(reader.get_mut(), 405, "Method Not Allowed", b"use POST", true);
            break;
        }

        // ── Verify auth ────────────────────────────────────────────
        if !verify_auth(&headers, auth_token) {
            let _ = write_http_response(
                reader.get_mut(),
                401,
                "Unauthorized",
                b"{\"error\":\"unauthorized\"}",
                true,
            );
            break; // Wrong token — close immediately.
        }

        // ── Parse JSON-RPC ─────────────────────────────────────────
        let request: RpcRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                let resp = RpcResponse::err(serde_json::Value::Null, PARSE_ERROR, format!("{}", e));
                let resp_body = serde_json::to_vec(&resp).unwrap_or_default();
                // Keep connection open — client may retry with valid JSON.
                let _ = write_http_response(reader.get_mut(), 200, "OK", &resp_body, client_wants_close);
                if client_wants_close { break; }
                continue;
            }
        };

        // ── Validate jsonrpc field ─────────────────────────────────
        if request.jsonrpc.as_deref() != Some("2.0") {
            let resp = RpcResponse::err(
                request.id.clone(),
                INVALID_REQUEST,
                "expected jsonrpc: \"2.0\"".into(),
            );
            let resp_body = serde_json::to_vec(&resp).unwrap_or_default();
            let _ = write_http_response(reader.get_mut(), 200, "OK", &resp_body, client_wants_close);
            if client_wants_close { break; }
            continue;
        }

        // ── Dispatch and respond ───────────────────────────────────
        let response = dispatch(syncer, &request);
        let resp_body = serde_json::to_vec(&response).unwrap_or_default();
        let _ = write_http_response(reader.get_mut(), 200, "OK", &resp_body, client_wants_close);

        if client_wants_close {
            break;
        }
    }
}

/// The accept loop: each connection `next` yields is served on a thread of
/// its own, up to `MAX_CONNECTIONS` at once (ticket 049: before, one slow
/// or trickling client held the only connection and kept every other
/// wallet out). Returns once `shutdown` is set and the connections are
/// done.
fn serve_streams<S: RpcStream + Send + 'static>(
    syncer: &Arc<HeaderSync>,
    auth_token: &str,
    shutdown: &Arc<AtomicBool>,
    mut next: impl FnMut() -> Option<S>,
) {
    let mut limiter = RateLimiter::new(100, std::time::Duration::from_secs(60));
    let mut connections: Vec<std::thread::JoinHandle<()>> = Vec::new();

    while !shutdown.load(Ordering::Relaxed) {
        connections.retain(|c| !c.is_finished());
        let Some(stream) = next() else {
            // No pending connection — sleep briefly to avoid busy-wait.
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        };
        if !limiter.allow() {
            warn!("wallet_rpc: rate limit exceeded, dropping connection");
            continue;
        }
        if connections.len() >= MAX_CONNECTIONS {
            warn!("wallet_rpc: {} connections open, dropping another", MAX_CONNECTIONS);
            continue;
        }
        let (syncer, token, shutdown) = (Arc::clone(syncer), auth_token.to_string(), Arc::clone(shutdown));
        connections.push(std::thread::spawn(move || handle_connection(&syncer, stream, &token, &shutdown)));
    }

    for c in connections {
        let _ = c.join();
    }
}

/// The wallet RPC server. Holds shared state and runs the accept loop.
pub struct WalletRpcServer {
    syncer: Arc<HeaderSync>,
    tor: Arc<TorManager>,
    auth_token: String,
    shutdown: Arc<AtomicBool>,
}

impl WalletRpcServer {
    pub fn new(
        syncer: Arc<HeaderSync>,
        tor: Arc<TorManager>,
        auth_token: String,
    ) -> Self {
        WalletRpcServer {
            syncer,
            tor,
            auth_token,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Run the accept loop. Blocks until `stop()` is called, and until
    /// the connections it started have ended (each ends within
    /// `SHUTDOWN_POLL` of the stop, or a write timeout).
    pub fn serve(&self) {
        info!("wallet_rpc: server started, waiting for connections");
        serve_streams(&self.syncer, &self.auth_token, &self.shutdown, || self.tor.accept_wallet_inbound());
        info!("wallet_rpc: server stopped");
    }

    /// Signal the server to stop.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

// ── Utilities ───────────────────────────────────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_response_shapes() {
        use crate::own_tx_store::{OwnTxReceipt, SubmitError};
        use bitcoin::hashes::Hash;
        let txid = bitcoin::Txid::from_byte_array([3; 32]);

        let ok = broadcast_response(
            Ok(OwnTxReceipt { txid, warnings: vec!["w".into()] }),
            serde_json::json!(1),
        );
        let json = serde_json::to_value(&ok).unwrap();
        assert_eq!(json["result"]["txid"], txid.to_string());
        assert_eq!(json["result"]["already_known"], false);

        let known = broadcast_response(Err(SubmitError::AlreadyKnown { txid }), serde_json::json!(1));
        let json = serde_json::to_value(&known).unwrap();
        assert_eq!(json["result"]["already_known"], true);
        assert!(json.get("error").is_none());

        let rej = broadcast_response(
            Err(SubmitError::Consensus("bad sig".into())),
            serde_json::json!(1),
        );
        let json = serde_json::to_value(&rej).unwrap();
        assert_eq!(json["error"]["code"], TX_REJECTED);
        assert!(json["error"]["message"].as_str().unwrap().starts_with("consensus: "));
    }

    #[test]
    fn base64_roundtrip() {
        let original = "hercules:my_secret_token_123";
        let encoded = base64_encode(original.as_bytes());
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn base64_decode_standard_vector() {
        // "user:pass" in base64
        assert_eq!(base64_decode("dXNlcjpwYXNz"), Some("user:pass".to_string()));
    }

    #[test]
    fn verify_auth_valid() {
        let mut headers = HashMap::new();
        let creds = base64_encode(b"hercules:secret123");
        headers.insert("authorization".to_string(), format!("Basic {}", creds));
        assert!(verify_auth(&headers, "secret123"));
    }

    #[test]
    fn verify_auth_wrong_token() {
        let mut headers = HashMap::new();
        let creds = base64_encode(b"hercules:wrong");
        headers.insert("authorization".to_string(), format!("Basic {}", creds));
        assert!(!verify_auth(&headers, "secret123"));
    }

    #[test]
    fn verify_auth_missing_header() {
        let headers = HashMap::new();
        assert!(!verify_auth(&headers, "secret123"));
    }

    #[test]
    fn verify_auth_bad_scheme() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer token123".to_string());
        assert!(!verify_auth(&headers, "token123"));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new(3, std::time::Duration::from_secs(60));
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow()); // 4th should be denied
    }

    #[test]
    fn rpc_response_ok_serializes() {
        let resp = RpcResponse::ok(serde_json::json!(1), serde_json::json!({"height": 800000}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"height\":800000"));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn rpc_response_err_serializes() {
        let resp = RpcResponse::err(serde_json::json!(1), -32601, "not found".into());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"code\":-32601"));
        assert!(json.contains("\"not found\""));
        assert!(!json.contains("\"result\""));
    }

    /// A loopback connection served by `handle_connection` on a thread.
    fn served_connection(
        shutdown: Arc<AtomicBool>,
    ) -> (std::net::TcpStream, std::thread::JoinHandle<()>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = dir.path().join("headers.sqlite3").to_string_lossy().into_owned();
        let hs = HeaderSync::new(&db, None).unwrap();
        let listener = std::net::TcpListener::bind(crate::testkit::loopback_bind()).unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let handle = std::thread::spawn(move || handle_connection(&hs, server, "token", &shutdown));
        (client, handle, dir)
    }

    #[test]
    fn idle_keepalive_connection_ends_on_shutdown() {
        // Ticket 028: stopping the wallet API must not wait out the 30 s
        // keep-alive read on an idle client.
        let shutdown = Arc::new(AtomicBool::new(false));
        let (_client, handle, _dir) = served_connection(Arc::clone(&shutdown));
        std::thread::sleep(std::time::Duration::from_millis(100));
        let start = Instant::now();
        shutdown.store(true, Ordering::Relaxed);
        while !handle.is_finished() {
            assert!(start.elapsed() < std::time::Duration::from_secs(2), "connection outlived shutdown");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        handle.join().unwrap();
    }

    #[test]
    fn connection_still_serves_requests_with_shutdown_polling() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (mut client, handle, _dir) = served_connection(shutdown);
        // Arrive after a few idle polls; wrong token gets a 401 and a close.
        std::thread::sleep(std::time::Duration::from_millis(600));
        client
            .write_all(b"POST / HTTP/1.1\r\nContent-Length: 2\r\nAuthorization: Bearer nope\r\n\r\n{}")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 401"), "{}", response);
        handle.join().unwrap();
    }

    #[test]
    fn read_http_request_parses_post() {
        let request = b"POST / HTTP/1.1\r\nContent-Length: 13\r\nAuthorization: Basic dGVzdA==\r\n\r\n{\"test\":true}";
        let mut reader = BufReader::new(&request[..]);
        let (method, path, headers, body) = read_http_request(&mut reader).unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/");
        assert_eq!(headers.get("content-length").unwrap(), "13");
        assert_eq!(&body, b"{\"test\":true}");
    }

    #[test]
    fn read_http_request_detects_disconnect() {
        let empty: &[u8] = b"";
        let mut reader = BufReader::new(empty);
        let err = read_http_request(&mut reader).unwrap_err();
        assert!(err.contains("client disconnected"));
    }

    #[test]
    fn keepalive_two_requests_on_same_stream() {
        // Two back-to-back HTTP requests in a single byte stream.
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}\
                     POST /2 HTTP/1.1\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest";
        let mut reader = BufReader::new(&raw[..]);

        let (m1, p1, _, b1) = read_http_request(&mut reader).unwrap();
        assert_eq!(m1, "POST");
        assert_eq!(p1, "/");
        assert_eq!(&b1, b"{}");

        let (m2, p2, h2, b2) = read_http_request(&mut reader).unwrap();
        assert_eq!(m2, "POST");
        assert_eq!(p2, "/2");
        assert_eq!(h2.get("connection").unwrap(), "close");
        assert_eq!(&b2, b"test");
    }

    // ══ Request validation and parsing (tests/network-app) ═══════════

    use crate::testkit::{lmdb_slot, FixtureChain, LmdbSlot};
    use proptest::prelude::*;
    use std::io::Cursor;

    /// A regtest node with a 12-block chain's headers, blocks 10..=12 in
    /// the block store, and one UTXO at `UTXO_TXID:0`.
    struct Rpc {
        hs: HeaderSync,
        chain: FixtureChain,
        _dir: tempfile::TempDir,
        _slot: LmdbSlot,
    }

    const UTXO_TXID: [u8; 32] = [0x77; 32];

    fn rpc_node() -> Rpc {
        let slot = lmdb_slot();
        let dir = tempfile::TempDir::new().unwrap();
        let hs = HeaderSync::with_config(crate::sync::SyncConfig {
            db_path: dir.path().join("headers.sqlite3").to_str().unwrap().to_string(),
            tor: None,
            params: crate::chain_params::ChainParams::regtest(),
            peers: crate::peer_pool::PeerSource::Static(vec![]),
        })
        .unwrap();
        let mut chain = FixtureChain::new();
        chain.mine(12);
        let headers: Vec<bitcoin::block::Header> = (1..=12).map(|h| chain.block(h).header).collect();
        hs.header_store_for_test().store_headers(&headers, 1).unwrap();
        for h in 10..=12 {
            hs.block_store_for_test().store_block(chain.block(h), h).unwrap();
        }
        hs.utxo_for_test()
            .test_insert_utxo(
                UTXO_TXID,
                0,
                crate::utxo::UtxoEntry { amount: 4242, script_pubkey: vec![0x51], height: 3, is_coinbase: false },
            )
            .unwrap();
        Rpc { hs, chain, _dir: dir, _slot: slot }
    }

    impl Rpc {
        /// Dispatch `method` with `params`; the response as JSON.
        fn call(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
            let req = RpcRequest { jsonrpc: Some("2.0".into()), method: method.into(), params, id: serde_json::json!(7) };
            let v = serde_json::to_value(dispatch(&self.hs, &req)).unwrap();
            assert_eq!(v["id"], 7, "id not echoed: {}", v);
            v
        }
    }

    fn code(v: &serde_json::Value) -> Option<i64> {
        v["error"]["code"].as_i64()
    }

    fn utxo_txid_hex() -> String {
        bitcoin::Txid::from_byte_array(UTXO_TXID).to_string()
    }

    use bitcoin::hashes::Hash;

    /// Heights and vouts arrive as JSON u64 and used to be cast with `as
    /// u32`, so 2^32 + n silently became n: `get_block_hash {"height":
    /// 4294967296}` answered with genesis, `get_utxo` with `vout`
    /// 4294967296 returned output 0's coin.
    #[test]
    fn out_of_range_heights_and_vouts_are_invalid_params_not_wrapped() {
        let r = rpc_node();
        let big = 1u64 << 32;
        let genesis = r.chain.hash_at(0).to_string();
        let v = r.call("get_block_hash", serde_json::json!({ "height": big }));
        assert_eq!(code(&v), Some(INVALID_PARAMS as i64), "{}", v);
        assert_ne!(v["result"], serde_json::json!(genesis));
        let v = r.call("get_block_header", serde_json::json!({ "height": big + 5 }));
        assert_eq!(code(&v), Some(INVALID_PARAMS as i64), "{}", v);
        let v = r.call("get_utxo", serde_json::json!({ "txid": utxo_txid_hex(), "vout": big }));
        assert_eq!(code(&v), Some(INVALID_PARAMS as i64), "{}", v);
        // In range, the same calls answer normally.
        assert_eq!(r.call("get_block_hash", serde_json::json!({ "height": 0 }))["result"], serde_json::json!(genesis));
        assert_eq!(r.call("get_utxo", serde_json::json!({ "txid": utxo_txid_hex(), "vout": 0 }))["result"]["value"], 4242);
        assert!(r.call("get_utxo", serde_json::json!({ "txid": utxo_txid_hex(), "vout": u32::MAX }))["result"].is_null());
    }

    #[test]
    fn every_method_answers_valid_requests() {
        let r = rpc_node();
        let tip = r.call("get_tip", serde_json::Value::Null);
        assert_eq!(tip["result"]["height"], 12);
        assert_eq!(tip["result"]["hash"], r.chain.hash_at(12).to_string());
        // Fixture timestamps are years old.
        assert_eq!(tip["result"]["is_stale"], true);

        let by_height = r.call("get_block_header", serde_json::json!({ "height": 5 }));
        assert_eq!(by_height["result"]["hash"], r.chain.hash_at(5).to_string());
        assert_eq!(by_height["result"]["prev_block_hash"], r.chain.hash_at(4).to_string());
        let by_hash = r.call("get_block_header", serde_json::json!({ "hash": r.chain.hash_at(5).to_string() }));
        assert_eq!(by_hash["result"], by_height["result"]);
        assert!(r.call("get_block_header", serde_json::json!({ "height": 99 }))["result"].is_null());
        assert!(r.call("get_block_header", serde_json::json!({ "hash": "00".repeat(32) }))["result"].is_null());

        let block = r.call("get_block", serde_json::json!({ "hash": r.chain.hash_at(11).to_string() }));
        let hex = block["result"]["hex"].as_str().unwrap();
        let decoded: bitcoin::Block = bitcoin::consensus::encode::deserialize_hex(hex).unwrap();
        assert_eq!(decoded.block_hash(), r.chain.hash_at(11));
        let pruned = r.call("get_block", serde_json::json!({ "hash": r.chain.hash_at(2).to_string() }));
        assert_eq!(code(&pruned), Some(BLOCK_PRUNED as i64));

        assert!(r.call("get_mempool_entry", serde_json::json!({ "txid": utxo_txid_hex() }))["result"].is_null());
        assert!(r.call("get_fee_estimates", serde_json::Value::Null)["result"].is_object());
        assert!(r.call("get_broadcast_status", serde_json::json!({ "txid": utxo_txid_hex() }))["result"].is_null());
        let info = r.call("get_node_info", serde_json::Value::Null);
        assert_eq!(info["result"]["tip_height"], 12);
        assert_eq!(code(&r.call("get_compact_filter", serde_json::Value::Null)), Some(METHOD_NOT_FOUND as i64));
    }

    #[test]
    fn malformed_params_are_invalid_params_for_every_method() {
        let r = rpc_node();
        let bad_params = [
            serde_json::Value::Null,
            serde_json::json!([]),
            serde_json::json!([5]),
            serde_json::json!("x"),
            serde_json::json!({}),
            serde_json::json!({ "height": -1 }),
            serde_json::json!({ "height": 1.5 }),
            serde_json::json!({ "height": "5" }),
            serde_json::json!({ "hash": 5 }),
            serde_json::json!({ "hash": "zz" }),
            serde_json::json!({ "hash": "00" }),
            serde_json::json!({ "txid": "not hex" }),
            serde_json::json!({ "txid": "ab".repeat(33) }),
            serde_json::json!({ "txid": utxo_txid_hex() }),          // no vout
            serde_json::json!({ "txid": utxo_txid_hex(), "vout": -1 }),
            serde_json::json!({ "hex": "zz" }),
            serde_json::json!({ "hex": 12 }),
        ];
        for method in [
            "get_block_header",
            "get_block_hash",
            "get_block",
            "get_utxo",
            "get_mempool_entry",
            "broadcast_transaction",
            "get_broadcast_status",
        ] {
            for p in &bad_params {
                let v = r.call(method, p.clone());
                if v.get("error").is_some() {
                    let c = code(&v).unwrap();
                    assert!(
                        c == INVALID_PARAMS as i64 || c == TX_REJECTED as i64,
                        "{} {} -> unexpected error {}",
                        method,
                        p,
                        v
                    );
                }
            }
        }
        // The specific shapes that must be refused, not answered.
        for (method, p) in [
            ("get_block_hash", serde_json::json!({ "height": -1 })),
            ("get_block_hash", serde_json::json!({ "height": "5" })),
            ("get_block", serde_json::json!({ "hash": "zz" })),
            ("get_utxo", serde_json::json!({ "txid": utxo_txid_hex() })),
            ("get_mempool_entry", serde_json::json!({ "txid": "not hex" })),
            ("broadcast_transaction", serde_json::json!({ "hex": "zz" })),
            ("get_broadcast_status", serde_json::json!({})),
        ] {
            assert_eq!(code(&r.call(method, p.clone())), Some(INVALID_PARAMS as i64), "{} {}", method, p);
        }
        assert_eq!(code(&r.call("getblockcount", serde_json::Value::Null)), Some(METHOD_NOT_FOUND as i64));
        assert_eq!(code(&r.call("", serde_json::Value::Null)), Some(METHOD_NOT_FOUND as i64));
    }

    #[test]
    fn broadcast_of_non_transaction_bytes_is_rejected_not_internal() {
        let r = rpc_node();
        for hex in ["", "00", "deadbeef", &"ff".repeat(100)] {
            let v = r.call("broadcast_transaction", serde_json::json!({ "hex": hex }));
            assert_eq!(code(&v), Some(TX_REJECTED as i64), "{:?} -> {}", hex, v);
        }
    }

    // ── HTTP parsing bounds ──────────────────────────────────────────

    /// A reader that counts what is consumed from it.
    struct Counting<R> {
        inner: R,
        read: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl<R: Read> Read for Counting<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.read.set(self.read.get() + n);
            Ok(n)
        }
    }

    /// Reviewer finding: `read_line` reads the whole line before the
    /// MAX_LINE_LENGTH check, so a client (before authenticating) can make
    /// the server buffer an arbitrarily long request line or header.
    #[test]
    fn oversized_lines_are_refused_without_buffering_them() {
        for prefix in [&b""[..], &b"POST / HTTP/1.1\r\n"[..]] {
            let mut data = prefix.to_vec();
            data.extend(std::iter::repeat(b'A').take(16 * 1024 * 1024));
            let read = std::rc::Rc::new(std::cell::Cell::new(0));
            let mut reader = BufReader::new(Counting { inner: Cursor::new(data), read: read.clone() });
            assert!(read_http_request(&mut reader).is_err());
            assert!(
                read.get() < 4 * MAX_LINE_LENGTH + prefix.len(),
                "consumed {} bytes of one line (limit {})",
                read.get(),
                MAX_LINE_LENGTH
            );
        }
    }

    #[test]
    fn line_and_body_limits_are_enforced() {
        let long = format!("POST /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_LINE_LENGTH));
        assert!(read_http_request(&mut BufReader::new(long.as_bytes())).is_err());
        let long_header = format!("POST / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_LINE_LENGTH));
        assert!(read_http_request(&mut BufReader::new(long_header.as_bytes())).is_err());
        let too_big = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY_SIZE + 1);
        let err = read_http_request(&mut BufReader::new(too_big.as_bytes())).unwrap_err();
        assert!(err.contains("too large"), "{}", err);
        // At the limit: accepted (body truncated here, so read fails, but
        // not for size).
        let at_limit = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY_SIZE);
        let err = read_http_request(&mut BufReader::new(at_limit.as_bytes())).unwrap_err();
        assert!(err.contains("read body"), "{}", err);
    }

    #[test]
    fn malformed_requests_are_errors_or_parse_safely() {
        for raw in [
            &b"\r\n"[..],
            b"POST\r\n\r\n",
            b"GARBAGE",
            b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort",
        ] {
            assert!(read_http_request(&mut BufReader::new(raw)).is_err(), "{:?}", String::from_utf8_lossy(raw));
        }
        // Lenient on what doesn't matter: lowercase method, odd headers,
        // a non-numeric length (read as 0).
        let raw = b"post /x HTTP/1.0\r\nNoColonHere\r\nContent-Length: abc\r\nX-Y:  spaced  \r\n\r\n";
        let (m, p, h, b) = read_http_request(&mut BufReader::new(&raw[..])).unwrap();
        assert_eq!((m.as_str(), p.as_str(), b.len()), ("POST", "/x", 0));
        assert_eq!(h.get("x-y").map(String::as_str), Some("spaced"));
    }

    #[test]
    fn auth_parsing_edge_cases() {
        let with = |v: &str| {
            let mut h = HashMap::new();
            h.insert("authorization".to_string(), v.to_string());
            h
        };
        let b64 = |s: &str| base64_encode(s.as_bytes());
        // Username ignored; password may itself contain ':'.
        assert!(verify_auth(&with(&format!("Basic {}", b64("anyone:tok:en"))), "tok:en"));
        assert!(verify_auth(&with(&format!("Basic {}", b64(":tok"))), "tok"));
        assert!(verify_auth(&with(&format!("Basic   {}  ", b64("u:tok"))), "tok"));
        for bad in [
            "Basic".to_string(),
            "Basic ".to_string(),
            format!("basic {}", b64("u:tok")),
            format!("Basic {}", b64("tok")),            // no colon
            format!("Basic {}", b64("u:tok ")),         // trailing space
            format!("Basic {}", b64("u:TOK")),
            "Basic !!!!".to_string(),
            "Basic /w==".to_string(),                    // decodes to non-UTF-8
            format!("Basic {}=", b64("u:tok")),          // extra padding is tolerated? must not panic
        ] {
            let _ = verify_auth(&with(&bad), "tok");
            if !bad.ends_with("==") && !bad.ends_with('=') {
                assert!(!verify_auth(&with(&bad), "tok"), "{:?} accepted", bad);
            }
        }
        // An empty expected token never matches a real request by accident.
        assert!(!verify_auth(&with(&format!("Basic {}", b64("u:x"))), ""));
    }

    // ── Keep-alive connection behavior ───────────────────────────────

    fn request(body: &str, auth: Option<&str>, extra: &str) -> String {
        let auth = auth.map(|t| format!("Authorization: Basic {}\r\n", base64_encode(format!("w:{}", t).as_bytes()))).unwrap_or_default();
        format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n{}{}\r\n{}", body.len(), auth, extra, body)
    }

    /// Read one HTTP response (status code, body) off `reader`.
    fn read_response(reader: &mut BufReader<std::net::TcpStream>) -> (u16, String) {
        let mut status = String::new();
        reader.read_line(&mut status).unwrap();
        let code: u16 = status.split(' ').nth(1).unwrap_or("0").parse().unwrap_or(0);
        let mut len = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line.trim().is_empty() {
                break;
            }
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; len];
        reader.read_exact(&mut body).unwrap();
        (code, String::from_utf8_lossy(&body).into_owned())
    }

    #[test]
    fn connection_recovers_from_bad_json_and_checks_auth_on_every_request() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (client, handle, _dir) = served_connection(shutdown.clone());
        let mut writer = client.try_clone().unwrap();
        let mut reader = BufReader::new(client);

        // Bad JSON: an error response, connection kept.
        writer.write_all(request("{nope", Some("token"), "").as_bytes()).unwrap();
        let (status, body) = read_response(&mut reader);
        assert_eq!(status, 200);
        assert!(body.contains(&PARSE_ERROR.to_string()), "{}", body);

        // Wrong protocol version: an error response, connection kept.
        writer.write_all(request(r#"{"jsonrpc":"1.0","method":"get_tip","id":1}"#, Some("token"), "").as_bytes()).unwrap();
        let (_, body) = read_response(&mut reader);
        assert!(body.contains(&INVALID_REQUEST.to_string()), "{}", body);

        // Two pipelined requests in one write: two answers, in order.
        let one = request(r#"{"jsonrpc":"2.0","method":"get_tip","id":"a"}"#, Some("token"), "");
        let two = request(r#"{"jsonrpc":"2.0","method":"nope","id":"b"}"#, Some("token"), "");
        writer.write_all(format!("{}{}", one, two).as_bytes()).unwrap();
        let (_, a) = read_response(&mut reader);
        let (_, b) = read_response(&mut reader);
        assert!(a.contains("\"id\":\"a\"") && b.contains("\"id\":\"b\""), "{} / {}", a, b);
        assert!(b.contains(&METHOD_NOT_FOUND.to_string()));

        // An authorized connection is not a session: an unauthenticated
        // request on it is refused and the connection closed.
        writer.write_all(request(r#"{"jsonrpc":"2.0","method":"get_tip","id":2}"#, None, "").as_bytes()).unwrap();
        let (status, _) = read_response(&mut reader);
        assert_eq!(status, 401);
        handle.join().unwrap();
    }

    #[test]
    fn non_post_and_oversized_bodies_close_the_connection() {
        for raw in [
            "GET / HTTP/1.1\r\n\r\n".to_string(),
            format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY_SIZE + 1),
        ] {
            let (client, handle, _dir) = served_connection(Arc::new(AtomicBool::new(false)));
            let mut writer = client.try_clone().unwrap();
            writer.write_all(raw.as_bytes()).unwrap();
            let mut response = String::new();
            BufReader::new(client).read_to_string(&mut response).unwrap();
            assert!(response.starts_with("HTTP/1.1 405") || response.starts_with("HTTP/1.1 400"), "{}", response);
            handle.join().unwrap();
        }
    }

    #[test]
    fn connection_close_is_honored_after_the_response() {
        let (client, handle, _dir) = served_connection(Arc::new(AtomicBool::new(false)));
        let mut writer = client.try_clone().unwrap();
        writer
            .write_all(request(r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#, Some("token"), "Connection: close\r\n").as_bytes())
            .unwrap();
        let mut response = String::new();
        BufReader::new(client).read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200") && response.contains("Connection: close"), "{}", response);
        handle.join().unwrap();
    }

    // ── Slow clients (ticket 049) ────────────────────────────────────

    /// Write `bytes` to `client` one at a time, `every` apart, until done
    /// or the server hangs up.
    fn trickle(mut client: std::net::TcpStream, bytes: Vec<u8>, every: std::time::Duration) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for b in bytes {
                if client.write_all(&[b]).is_err() {
                    return;
                }
                std::thread::sleep(every);
            }
        })
    }

    #[test]
    fn a_trickling_request_is_cut_off_at_the_request_timeout() {
        let (client, handle, _dir) = served_connection(Arc::new(AtomicBool::new(false)));
        let start = Instant::now();
        let dripper = trickle(
            client,
            request(r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#, Some("token"), "").into_bytes(),
            std::time::Duration::from_millis(100),
        );
        while !handle.is_finished() {
            assert!(start.elapsed() < REQUEST_TIMEOUT + std::time::Duration::from_secs(3), "connection held past its request timeout");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(start.elapsed() >= REQUEST_TIMEOUT, "cut off early: {:?}", start.elapsed());
        handle.join().unwrap();
        dripper.join().unwrap();
    }

    /// `serve_streams` on a loopback listener; returns its address, the
    /// shutdown flag and the server thread.
    fn served_listener() -> (std::net::SocketAddr, Arc<AtomicBool>, std::thread::JoinHandle<()>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = dir.path().join("headers.sqlite3").to_string_lossy().into_owned();
        let hs = Arc::new(HeaderSync::new(&db, None).unwrap());
        let listener = std::net::TcpListener::bind(crate::testkit::loopback_bind()).unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let server = std::thread::spawn(move || {
            serve_streams(&hs, "token", &stop, || {
                let (s, _) = listener.accept().ok()?;
                // Accepted sockets inherit the listener's non-blocking mode.
                s.set_nonblocking(false).unwrap();
                Some(s)
            })
        });
        (addr, shutdown, server, dir)
    }

    #[test]
    fn a_slow_client_does_not_keep_out_another() {
        let (addr, shutdown, server, _dir) = served_listener();
        let slow = std::net::TcpStream::connect(addr).unwrap();
        let dripper = trickle(slow, b"POST / HTTP/1.1\r\n".repeat(100), std::time::Duration::from_millis(100));
        std::thread::sleep(std::time::Duration::from_millis(300));

        let start = Instant::now();
        let client = std::net::TcpStream::connect(addr).unwrap();
        client.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        client
            .try_clone()
            .unwrap()
            .write_all(request(r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#, Some("token"), "").as_bytes())
            .unwrap();
        let (status, body) = read_response(&mut BufReader::new(client));
        assert_eq!(status, 200, "{}", body);
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "answered after {:?}", start.elapsed());

        shutdown.store(true, Ordering::Relaxed);
        server.join().unwrap();
        dripper.join().unwrap();
    }

    #[test]
    fn connections_past_the_cap_are_dropped() {
        let (addr, shutdown, server, _dir) = served_listener();
        let open: Vec<std::net::TcpStream> = (0..MAX_CONNECTIONS)
            .map(|_| std::net::TcpStream::connect(addr).unwrap())
            .collect();
        // Let the accept loop take them all.
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut extra = std::net::TcpStream::connect(addr).unwrap();
        extra.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 1];
        assert!(matches!(extra.read(&mut buf), Ok(0) | Err(_)), "connection past the cap was served");
        shutdown.store(true, Ordering::Relaxed);
        server.join().unwrap();
        drop(open);
    }

    // ── Properties ───────────────────────────────────────────────────

    proptest! {
        #[test]
        fn prop_read_http_request_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let mut reader = BufReader::new(&bytes[..]);
            for _ in 0..4 {
                if read_http_request(&mut reader).is_err() {
                    break;
                }
            }
        }

        #[test]
        fn prop_base64_round_trips_and_decode_never_panics(s in ".{0,64}", junk in ".{0,64}") {
            prop_assert_eq!(base64_decode(&base64_encode(s.as_bytes())), Some(s));
            let _ = base64_decode(&junk);
        }

        /// The right token always authenticates, whatever the username
        /// (without ':'); any other token never does.
        #[test]
        fn prop_auth_accepts_exactly_the_token(user in "[^:]{0,16}", token in "[ -~]{1,64}", other in "[ -~]{1,64}") {
            let mut h = HashMap::new();
            h.insert("authorization".to_string(), format!("Basic {}", base64_encode(format!("{}:{}", user, token).as_bytes())));
            prop_assert!(verify_auth(&h, &token));
            prop_assume!(other != token);
            prop_assert!(!verify_auth(&h, &other));
        }
    }

    #[test]
    fn prop_dispatch_never_panics_on_arbitrary_params() {
        let r = rpc_node();
        let methods = [
            "get_tip", "get_block_header", "get_block_hash", "get_block", "get_utxo", "get_mempool_entry",
            "get_fee_estimates", "broadcast_transaction", "get_broadcast_status", "get_compact_filter",
            "get_node_info", "unknown",
        ];
        let leaf = prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::from),
            any::<i64>().prop_map(serde_json::Value::from),
            any::<u64>().prop_map(serde_json::Value::from),
            any::<f64>().prop_map(serde_json::Value::from),
            "[0-9a-f]{0,80}".prop_map(serde_json::Value::from),
            ".{0,20}".prop_map(serde_json::Value::from),
        ];
        let params = prop::collection::btree_map(
            prop::sample::select(vec!["height", "hash", "txid", "vout", "hex", "x"]),
            leaf,
            0..4,
        )
        .prop_map(|m| serde_json::Value::Object(m.into_iter().map(|(k, v)| (k.to_string(), v)).collect()));
        let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
            cases: std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(256),
            ..Default::default()
        });
        runner
            .run(&(prop::sample::select(methods.to_vec()), params), |(method, params)| {
                let v = r.call(method, params);
                prop_assert!(v.get("result").is_some() || v.get("error").is_some());
                Ok(())
            })
            .unwrap();
    }
}
