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

/// Read one HTTP/1.1 request from a buffered reader. The caller owns the
/// `BufReader` so it persists across requests on a keepalive connection.
/// Returns `Err` on disconnect, timeout, or malformed input.
fn read_http_request<R: Read>(
    reader: &mut BufReader<R>,
) -> Result<(String, String, HashMap<String, String>, Vec<u8>), String> {
    // Read request line.
    let mut request_line = String::new();
    let n = reader
        .read_line(&mut request_line)
        .map_err(|e| format!("read request line: {}", e))?;
    if n == 0 {
        return Err("client disconnected".into());
    }
    if request_line.len() > MAX_LINE_LENGTH {
        return Err("request line too long".into());
    }
    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err("malformed request line".into());
    }
    let method = parts[0].to_uppercase();
    let path = parts[1].to_string();

    // Read headers.
    let mut headers = HashMap::new();
    for _ in 0..MAX_HEADER_COUNT {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read header: {}", e))?;
        if line.len() > MAX_LINE_LENGTH {
            return Err("header line too long".into());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    // Read body based on Content-Length.
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if content_length > MAX_BODY_SIZE {
        return Err(format!("body too large: {} > {}", content_length, MAX_BODY_SIZE));
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|e| format!("read body: {}", e))?;
    }

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
        match syncer.rpc_get_header_at_height(height as u32) {
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
        Some(h) => h as u32,
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
        Some(v) => v as u32,
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
    match syncer.rpc_broadcast_tx(&raw) {
        Ok(txid) => RpcResponse::ok(id, serde_json::json!({"txid": txid.to_string()})),
        Err(e) => RpcResponse::err(id, TX_REJECTED, format!("{}", e)),
    }
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

/// Handle an inbound wallet connection. Supports HTTP/1.1 keepalive:
/// multiple JSON-RPC requests can be sent on the same Tor stream,
/// matching Bitcoin Core's RPC server behavior. The connection closes
/// on idle timeout (30s), auth failure, or `Connection: close` from
/// the client.
fn handle_connection(
    syncer: &HeaderSync,
    mut stream: crate::tor::TorStream,
    auth_token: &str,
) {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(KEEPALIVE_TIMEOUT_SECS)));
    let mut reader = BufReader::new(&mut stream);

    loop {
        // ── Read one HTTP request ──────────────────────────────────
        let (method, _path, headers, body) = match read_http_request(&mut reader) {
            Ok(r) => r,
            Err(e) => {
                // Timeout or clean disconnect — normal keepalive exit.
                if !e.contains("client disconnected") && !e.contains("timed out") {
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

    /// Run the accept loop. Blocks until `stop()` is called. Each inbound
    /// connection is handled inline (wallet connections are rare enough
    /// that parallelism isn't needed — Tor circuit setup already takes
    /// seconds, so single-threaded handling adds negligible latency).
    pub fn serve(&self) {
        info!("wallet_rpc: server started, waiting for connections");
        let mut limiter = RateLimiter::new(100, std::time::Duration::from_secs(60));

        while !self.shutdown.load(Ordering::Relaxed) {
            if let Some(stream) = self.tor.accept_wallet_inbound() {
                if !limiter.allow() {
                    warn!("wallet_rpc: rate limit exceeded, dropping connection");
                    continue;
                }
                handle_connection(&self.syncer, stream, &self.auth_token);
            } else {
                // No pending connection — sleep briefly to avoid busy-wait.
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }

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
}
