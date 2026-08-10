//! Microsoft Graph API client for sending emails
//!
//! Uses the Microsoft Graph REST API (`POST /me/sendMail`) to send emails
//! from Microsoft accounts (personal and enterprise). This bypasses SMTP
//! entirely, which is necessary for personal hotmail/outlook.com accounts
//! where Microsoft has disabled SMTP AUTH.
//!
//! When `in_reply_to` is provided, uses the Graph reply flow
//! (`createReply` → PATCH → send) for proper threading.
//!
//! # Requirements
//!
//! - OAuth2 configured with `provider=microsoft`
//! - Token scope must include `https://graph.microsoft.com/Mail.Send`
//!
//! # Configuration
//!
//! Uses the same `MAIL_OAUTH2_<SEGMENT>_*` variables as IMAP/SMTP OAuth2.
//! No additional configuration needed beyond OAuth2.

use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::errors::{AppError, AppResult};
use crate::mime::truncate_chars;
use crate::oauth2::TokenManager;

/// Microsoft Graph API base URL
const GRAPH_API_BASE: &str = "https://graph.microsoft.com/v1.0";

/// Threshold (in raw decoded bytes) above which an attachment must be
/// uploaded via `createUploadSession` instead of inlined in a single
/// POST to `/me/messages/{id}/attachments`. Per Microsoft Graph docs the
/// inline limit is 3 MB; we use a slightly conservative value to stay
/// well clear of base64-overhead edge cases on the wire.
const ATTACHMENT_INLINE_MAX_BYTES: usize = 3 * 1024 * 1024;

/// Chunk size for createUploadSession PUTs. Graph accepts up to ~4 MB
/// per chunk; we use exactly 4 MB which divides evenly and stays under
/// the documented ceiling.
const UPLOAD_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// Timeout for ordinary Graph calls (search, get, mutate).
const GRAPH_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for attachment listing, which can pull multi-MB `contentBytes`.
const GRAPH_ATTACHMENT_TIMEOUT: Duration = Duration::from_secs(90);

/// Largest PDF we will attempt text extraction on, in decoded bytes.
/// Matches the EWS path so both protocols behave identically.
const PDF_EXTRACT_MAX_BYTES: usize = 5_000_000;

/// Bounds on the breadth-first search used to resolve a folder display name.
/// Graph has no deep-traversal equivalent of the EWS `Traversal="Deep"`, so a
/// miss would otherwise walk the whole tree.
const FOLDER_BFS_MAX_DEPTH: usize = 5;
const FOLDER_BFS_MAX_REQUESTS: usize = 40;

/// Shared HTTP client.
///
/// The send path historically built a fresh `reqwest::Client` per call, which
/// throws away connection pooling and TLS session reuse. One client for the
/// process is both faster and the documented reqwest recommendation.
fn http() -> &'static reqwest::Client {
    static HTTP: OnceLock<reqwest::Client> = OnceLock::new();
    HTTP.get_or_init(reqwest::Client::new)
}

/// Cache of resolved folder display names, keyed by `(account_id, lowercased name)`.
///
/// Folder ids are stable for the life of a folder, so entries never need
/// invalidating; a rename simply costs one cache miss. This exists because the
/// BFS in [`resolve_folder`] can cost several round trips on a nested tree.
fn folder_cache() -> &'static Mutex<HashMap<(String, String), String>> {
    static CACHE: OnceLock<Mutex<HashMap<(String, String), String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Percent-encode a value destined for a URL path segment or query value.
///
/// Graph message and folder ids are base64url-ish and routinely carry `=`
/// padding; folder names and KQL queries can carry spaces and non-ASCII.
fn enc(value: &str) -> String {
    urlencoding::encode(value).into_owned()
}

// ─── Error shape ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GraphErrorEnvelope {
    error: GraphErrorBody,
}

#[derive(Debug, Deserialize)]
struct GraphErrorBody {
    code: Option<String>,
    message: Option<String>,
}

/// Turn a failed Graph response into an `AppError`, preserving the body.
///
/// Graph reports actionable failures in a machine-readable `code` (for example
/// `SearchWithFilter` when `$search` and `$filter` are combined, or
/// `ErrorItemNotFound`). Surfacing that verbatim is what makes the failure
/// legible at the tool boundary instead of an opaque status code.
async fn graph_error(response: reqwest::Response, context: &str) -> AppError {
    let status = response.status();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = response.text().await.unwrap_or_default();

    let detail = match serde_json::from_str::<GraphErrorEnvelope>(&body) {
        Ok(env) => {
            let code = env.error.code.unwrap_or_default();
            let message = env.error.message.unwrap_or_default();
            if code.is_empty() {
                message
            } else {
                format!("{code}: {message}")
            }
        }
        Err(_) => body,
    };

    match status.as_u16() {
        401 | 403 => AppError::AuthFailed(format!(
            "Graph {context} authentication failed ({status}): {detail}"
        )),
        404 => AppError::NotFound(format!("Graph {context} not found: {detail}")),
        429 => {
            let wait = retry_after
                .map(|s| format!(" (Retry-After: {s}s)"))
                .unwrap_or_default();
            AppError::Internal(format!("Graph {context} rate limited{wait}: {detail}"))
        }
        _ => AppError::Internal(format!("Graph {context} failed ({status}): {detail}")),
    }
}

// ─── Request helpers ─────────────────────────────────────────────────────────

/// Issue an authenticated Graph request.
///
/// Mirrors the shape of `ews::ews_request`: fetch a token, one shared client,
/// explicit timeout, uniform error mapping. `path_and_query` is appended to
/// [`GRAPH_API_BASE`] and must already be encoded.
async fn graph_request(
    token_manager: &TokenManager,
    account_id: &str,
    method: reqwest::Method,
    path_and_query: &str,
    body: Option<&serde_json::Value>,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
) -> AppResult<reqwest::Response> {
    let access_token = token_manager.get_access_token(account_id).await?;
    let url = format!("{GRAPH_API_BASE}{path_and_query}");

    let mut req = http()
        .request(method, &url)
        .bearer_auth(&access_token)
        .timeout(timeout);
    for (name, value) in extra_headers {
        req = req.header(*name, *value);
    }
    if let Some(json) = body {
        req = req.json(json);
    }

    req.send()
        .await
        .map_err(|e| AppError::Internal(format!("Graph request to {path_and_query} failed: {e}")))
}

/// Deserialize a successful response body, or map the failure.
async fn handle_json<T: DeserializeOwned>(
    response: reqwest::Response,
    context: &str,
) -> AppResult<T> {
    if !response.status().is_success() {
        return Err(graph_error(response, context).await);
    }
    response
        .json::<T>()
        .await
        .map_err(|e| AppError::Internal(format!("failed to parse Graph {context} response: {e}")))
}

/// Discard a successful response body, or map the failure.
async fn handle_empty(response: reqwest::Response, context: &str) -> AppResult<()> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(graph_error(response, context).await)
    }
}

async fn graph_get<T: DeserializeOwned>(
    tm: &TokenManager,
    account_id: &str,
    path_and_query: &str,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
    context: &str,
) -> AppResult<T> {
    let resp = graph_request(
        tm,
        account_id,
        reqwest::Method::GET,
        path_and_query,
        None,
        extra_headers,
        timeout,
    )
    .await?;
    handle_json(resp, context).await
}

async fn graph_post_json<T: DeserializeOwned>(
    tm: &TokenManager,
    account_id: &str,
    path: &str,
    body: &serde_json::Value,
    context: &str,
) -> AppResult<T> {
    let resp = graph_request(
        tm,
        account_id,
        reqwest::Method::POST,
        path,
        Some(body),
        &[],
        GRAPH_TIMEOUT,
    )
    .await?;
    handle_json(resp, context).await
}

async fn graph_post_empty(
    tm: &TokenManager,
    account_id: &str,
    path: &str,
    context: &str,
) -> AppResult<()> {
    let resp = graph_request(
        tm,
        account_id,
        reqwest::Method::POST,
        path,
        None,
        &[],
        GRAPH_TIMEOUT,
    )
    .await?;
    handle_empty(resp, context).await
}

async fn graph_patch_json(
    tm: &TokenManager,
    account_id: &str,
    path: &str,
    body: &serde_json::Value,
    context: &str,
) -> AppResult<()> {
    let resp = graph_request(
        tm,
        account_id,
        reqwest::Method::PATCH,
        path,
        Some(body),
        &[],
        GRAPH_TIMEOUT,
    )
    .await?;
    handle_empty(resp, context).await
}

async fn graph_delete(
    tm: &TokenManager,
    account_id: &str,
    path: &str,
    context: &str,
) -> AppResult<()> {
    let resp = graph_request(
        tm,
        account_id,
        reqwest::Method::DELETE,
        path,
        None,
        &[],
        GRAPH_TIMEOUT,
    )
    .await?;
    handle_empty(resp, context).await
}

// ─── Request types (sendMail) ───────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SendMailRequest {
    message: GraphMessage,
    save_to_sent_items: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphMessage {
    subject: String,
    body: GraphBody,
    to_recipients: Vec<GraphRecipient>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cc_recipients: Vec<GraphRecipient>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bcc_recipients: Vec<GraphRecipient>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<Vec<GraphRecipient>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    internet_message_headers: Option<Vec<GraphHeader>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<GraphAttachment>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphBody {
    content_type: &'static str,
    content: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphRecipient {
    email_address: GraphEmailAddress,
}

#[derive(Debug, Serialize)]
struct GraphEmailAddress {
    address: String,
}

#[derive(Debug, Serialize)]
struct GraphHeader {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphAttachment {
    #[serde(rename = "@odata.type")]
    odata_type: &'static str,
    name: String,
    content_type: String,
    content_bytes: String,
}

// ─── Request types (reply / patch draft) ────────────────────────────────────

// NOTE: `attachments` is INTENTIONALLY ABSENT from this struct. Microsoft
// Graph treats `Message.attachments` as a navigation property — PATCH
// requests against `/me/messages/{id}` silently DISCARD the field
// (returns 2xx but the attachments never land on the draft). For the
// createReply → PATCH → send flow we must instead POST each attachment to
// `/me/messages/{id}/attachments` (or use createUploadSession for ≥3 MB)
// between PATCH and send. See `upload_attachment_to_draft` below.
//
// This was the v0.4.6 silent-data-loss bug — see BUG_GRAPH_ATTACHMENTS.md
// and the v0.4.7 release notes.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PatchDraftRequest {
    subject: String,
    body: GraphBody,
    to_recipients: Vec<GraphRecipient>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cc_recipients: Vec<GraphRecipient>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bcc_recipients: Vec<GraphRecipient>,
}

// ─── Response types ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MessageListResponse {
    value: Vec<MessageItem>,
}

#[derive(Debug, Deserialize)]
struct MessageItem {
    id: String,
}

#[derive(Debug, Deserialize)]
struct DraftResponse {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadSessionResponse {
    upload_url: String,
}

// ─── Helper constructors ─────────────────────────────────────────────────────

fn recipient(addr: &str) -> GraphRecipient {
    GraphRecipient {
        email_address: GraphEmailAddress {
            address: addr.to_owned(),
        },
    }
}

fn recipients(addrs: &[String]) -> Vec<GraphRecipient> {
    addrs.iter().map(|a| recipient(a)).collect()
}

fn build_attachments(attachments: &[GraphEmailAttachment]) -> Vec<GraphAttachment> {
    attachments
        .iter()
        .map(|a| GraphAttachment {
            odata_type: "#microsoft.graph.fileAttachment",
            name: a.filename.clone(),
            content_type: a.content_type.clone(),
            content_bytes: a.content_base64.clone(),
        })
        .collect()
}

fn resolve_body(body_html: &Option<String>, body_text: &Option<String>) -> (&'static str, String) {
    match (body_html, body_text) {
        (Some(html), _) => ("HTML", sanitize_cdata(html)),
        (None, Some(text)) => ("Text", sanitize_cdata(text)),
        (None, None) => ("Text", String::new()),
    }
}

/// Upload one attachment to an existing draft message.
///
/// Used by the createReply → PATCH → send flow because Graph silently
/// discards `attachments` set via PATCH on `/me/messages/{id}`. After the
/// PATCH succeeds (body + recipients), every attachment must be POSTed
/// individually to `/me/messages/{id}/attachments`.
///
/// Routing:
/// - Raw size < 3 MB: single inline POST with `contentBytes` (base64).
/// - Raw size ≥ 3 MB: `createUploadSession` + 4 MB chunked PUTs to the
///   returned (pre-authenticated) upload URL.
async fn upload_attachment_to_draft(
    client: &reqwest::Client,
    access_token: &str,
    draft_id: &str,
    att: &GraphEmailAttachment,
) -> AppResult<()> {
    // Decode once to know the real size and to feed the chunked upload.
    let raw_bytes = base64::engine::general_purpose::STANDARD
        .decode(att.content_base64.as_bytes())
        .map_err(|e| {
            AppError::invalid(format!(
                "attachment '{}' has invalid base64 content: {e}",
                att.filename
            ))
        })?;

    if raw_bytes.len() < ATTACHMENT_INLINE_MAX_BYTES {
        upload_attachment_inline(client, access_token, draft_id, att).await
    } else {
        upload_attachment_via_session(client, access_token, draft_id, att, &raw_bytes).await
    }
}

/// POST `/me/messages/{id}/attachments` with the file inline in JSON.
/// Only safe for attachments whose raw (decoded) size is < 3 MB.
async fn upload_attachment_inline(
    client: &reqwest::Client,
    access_token: &str,
    draft_id: &str,
    att: &GraphEmailAttachment,
) -> AppResult<()> {
    let url = format!("{}/me/messages/{}/attachments", GRAPH_API_BASE, draft_id);
    let body = serde_json::json!({
        "@odata.type": "#microsoft.graph.fileAttachment",
        "name": att.filename,
        "contentType": att.content_type,
        "contentBytes": att.content_base64,
    });
    let response = client
        .post(&url)
        .bearer_auth(access_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            AppError::Internal(format!(
                "Graph attachment POST failed for '{}': {e}",
                att.filename
            ))
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let resp_body = response.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "Graph attachment POST for '{}' failed ({status}): {resp_body}",
            att.filename
        )));
    }
    Ok(())
}

/// Create an upload session and PUT the file in 4 MB chunks.
/// Used for attachments ≥ 3 MB raw size.
///
/// The `uploadUrl` returned by `createUploadSession` is pre-authenticated
/// for the duration of the session — chunks must be PUT WITHOUT a Bearer
/// token (Graph rejects it with 401 if included).
async fn upload_attachment_via_session(
    client: &reqwest::Client,
    access_token: &str,
    draft_id: &str,
    att: &GraphEmailAttachment,
    raw_bytes: &[u8],
) -> AppResult<()> {
    // Step A: createUploadSession.
    let session_url = format!(
        "{}/me/messages/{}/attachments/createUploadSession",
        GRAPH_API_BASE, draft_id
    );
    let session_request = serde_json::json!({
        "AttachmentItem": {
            "attachmentType": "file",
            "name": att.filename,
            "size": raw_bytes.len(),
            "contentType": att.content_type,
        }
    });

    let response = client
        .post(&session_url)
        .bearer_auth(access_token)
        .json(&session_request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            AppError::Internal(format!(
                "createUploadSession failed for '{}': {e}",
                att.filename
            ))
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let resp_body = response.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "createUploadSession for '{}' failed ({status}): {resp_body}",
            att.filename
        )));
    }

    let session: UploadSessionResponse = response.json().await.map_err(|e| {
        AppError::Internal(format!(
            "createUploadSession response parse failed for '{}': {e}",
            att.filename
        ))
    })?;

    // Step B: PUT chunks (no Bearer token — uploadUrl is pre-authenticated).
    let total = raw_bytes.len();
    let mut offset: usize = 0;
    while offset < total {
        let end = (offset + UPLOAD_CHUNK_BYTES).min(total);
        let chunk = raw_bytes[offset..end].to_vec();
        let range_header = format!("bytes {}-{}/{}", offset, end - 1, total);

        let put_response = client
            .put(&session.upload_url)
            .header("Content-Length", chunk.len().to_string())
            .header("Content-Range", range_header)
            .body(chunk)
            .timeout(std::time::Duration::from_secs(120))
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "upload chunk PUT failed for '{}' at offset {offset}: {e}",
                    att.filename
                ))
            })?;

        if !put_response.status().is_success() {
            let status = put_response.status();
            let resp_body = put_response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "upload chunk for '{}' at offset {offset} failed ({status}): {resp_body}",
                att.filename
            )));
        }
        offset = end;
    }
    Ok(())
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// An attachment for Graph API
pub struct GraphEmailAttachment {
    pub filename: String,
    pub content_type: String,
    pub content_base64: String,
}

/// Parameters for sending an email via Microsoft Graph
pub struct GraphEmailParams {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub reply_to: Option<String>,
    /// Original Message-ID we're replying to. When set, triggers the
    /// createReply → PATCH → send flow so Exchange generates proper
    /// threading headers server-side.
    pub in_reply_to: Option<String>,
    /// Accepted for API symmetry with SMTP/EWS but NOT sent to Graph.
    /// Microsoft Graph's `sendMail` strips non-`x-*` internetMessageHeaders,
    /// so a caller-supplied References header would be silently dropped —
    /// threading is instead driven server-side via the `in_reply_to` reply
    /// flow. Present so callers don't have to special-case Graph.
    #[allow(dead_code)]
    pub references: Option<String>,
    pub attachments: Vec<GraphEmailAttachment>,
    pub save_to_sent: bool,
}

/// Send an email using the Microsoft Graph API.
///
/// When `in_reply_to` is provided, attempts the reply flow:
///   1. Search for the original message by `internetMessageId`
///   2. `POST /me/messages/{id}/createReply` to get a threaded draft
///   3. `PATCH /me/messages/{draftId}` to set body, recipients, attachments
///   4. `POST /me/messages/{draftId}/send` to send the draft
///
/// If the original message is not found (e.g. it was sent from another
/// account), falls back to regular `sendMail` without threading.
///
/// # Errors
///
/// - `AuthFailed` if the token is invalid or lacks permissions
/// - `InvalidInput` if email addresses are malformed (caught by Graph API)
/// - `Internal` for network or API errors
pub async fn send_email(
    token_manager: &TokenManager,
    account_id: &str,
    params: &GraphEmailParams,
) -> AppResult<()> {
    let access_token = token_manager.get_access_token(account_id).await?;
    let client = reqwest::Client::new();

    // If in_reply_to is provided, try the reply flow for proper threading
    if let Some(ref irt) = params.in_reply_to {
        if let Some(graph_msg_id) = find_message_by_internet_id(&client, &access_token, irt).await?
        {
            return send_via_reply(&client, &access_token, &graph_msg_id, params).await;
        }
        // Message not found in this mailbox — threading will be lost. This
        // is expected when replying to a conversation whose original message
        // was deleted or lives in a different mailbox; log at DEBUG so it's
        // visible in troubleshooting without spamming normal operation.
        debug!(
            in_reply_to = %irt,
            "Graph: original message not found; sending without thread reply"
        );
    }

    send_via_sendmail(&client, &access_token, params).await
}

// ─── Private: sendMail flow ─────────────────────────────────────────────────

async fn send_via_sendmail(
    client: &reqwest::Client,
    access_token: &str,
    params: &GraphEmailParams,
) -> AppResult<()> {
    let (content_type, content) = resolve_body(&params.body_html, &params.body_text);

    // Note: Graph API internetMessageHeaders only supports x-* custom headers.
    // Standard headers like In-Reply-To and References are NOT allowed here.
    // Threading is handled via the reply flow instead.

    let message = GraphMessage {
        subject: params.subject.clone(),
        body: GraphBody {
            content_type,
            content,
        },
        to_recipients: recipients(&params.to),
        cc_recipients: recipients(&params.cc),
        bcc_recipients: recipients(&params.bcc),
        reply_to: params.reply_to.as_ref().map(|addr| vec![recipient(addr)]),
        internet_message_headers: None,
        attachments: build_attachments(&params.attachments),
    };

    let request_body = SendMailRequest {
        message,
        save_to_sent_items: params.save_to_sent,
    };

    let response = client
        .post(format!("{GRAPH_API_BASE}/me/sendMail"))
        .bearer_auth(access_token)
        .json(&request_body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Graph API request failed: {e}")))?;

    handle_response(response).await
}

// ─── Private: reply flow (createReply → patch → send) ───────────────────────

/// Search for a message by its RFC `Message-ID` header.
/// Returns the Graph API internal ID if found.
async fn find_message_by_internet_id(
    client: &reqwest::Client,
    access_token: &str,
    internet_message_id: &str,
) -> AppResult<Option<String>> {
    // Strip angle brackets for the filter if present
    let clean_id = internet_message_id
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>');

    let url = format!(
        "{}/me/messages?$filter=internetMessageId eq '<{}>'&$select=id&$top=1",
        GRAPH_API_BASE, clean_id
    );

    let response = client
        .get(&url)
        .bearer_auth(access_token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Graph search request failed: {e}")))?;

    if !response.status().is_success() {
        // Search failed (permissions, rate limit, 5xx…) — we don't propagate
        // the error so the caller can still send (without threading), but we
        // WARN so operators see that threading degraded due to a real error.
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read body>".to_owned());
        warn!(
            status = %status,
            body = %body,
            internet_message_id = %clean_id,
            "Graph: message lookup for threading failed; falling back to sendMail without thread"
        );
        return Ok(None);
    }

    let list: MessageListResponse = response
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse Graph search response: {e}")))?;

    Ok(list.value.into_iter().next().map(|m| m.id))
}

/// Send a properly threaded reply using Graph API.
///   1. createReply → gets a draft with correct threading headers
///   2. PATCH the draft with our body, recipients, attachments
///   3. Send the draft
async fn send_via_reply(
    client: &reqwest::Client,
    access_token: &str,
    original_msg_id: &str,
    params: &GraphEmailParams,
) -> AppResult<()> {
    // Step 1: Create reply draft
    let create_reply_url = format!(
        "{}/me/messages/{}/createReply",
        GRAPH_API_BASE, original_msg_id
    );

    let response = client
        .post(&create_reply_url)
        .bearer_auth(access_token)
        .header("Content-Type", "application/json")
        .body("{}")
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Graph createReply failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "Graph createReply failed ({status}): {body}"
        )));
    }

    let draft: DraftResponse = response
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse createReply response: {e}")))?;

    let draft_id = draft.id;

    // Step 2: PATCH the draft with our content (body + recipients only).
    // Attachments are deliberately NOT set here — see PatchDraftRequest's
    // doc comment for the rationale.
    let (content_type, content) = resolve_body(&params.body_html, &params.body_text);

    let patch_body = PatchDraftRequest {
        subject: params.subject.clone(),
        body: GraphBody {
            content_type,
            content,
        },
        to_recipients: recipients(&params.to),
        cc_recipients: recipients(&params.cc),
        bcc_recipients: recipients(&params.bcc),
    };

    let patch_url = format!("{}/me/messages/{}", GRAPH_API_BASE, draft_id);

    let response = client
        .patch(&patch_url)
        .bearer_auth(access_token)
        .json(&patch_body)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Graph PATCH draft failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "Graph PATCH draft failed ({status}): {body}"
        )));
    }

    // Step 2.5: Upload each attachment via the dedicated endpoint.
    // This is the load-bearing step for the v0.4.7 fix — without it the
    // PATCH-only flow loses attachments silently because Graph treats
    // `Message.attachments` as a navigation property and ignores it on PATCH.
    for att in &params.attachments {
        upload_attachment_to_draft(client, access_token, &draft_id, att).await?;
    }

    // Step 3: Send the draft
    let send_url = format!("{}/me/messages/{}/send", GRAPH_API_BASE, draft_id);

    let response = client
        .post(&send_url)
        .bearer_auth(access_token)
        .header("Content-Length", "0")
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Graph send draft failed: {e}")))?;

    handle_response(response).await
}

// ─── Read/mutate wire types ──────────────────────────────────────────────────

/// An OData collection response.
#[derive(Debug, Deserialize)]
struct GraphList<T> {
    #[serde(default = "Vec::new")]
    value: Vec<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEmailAddress {
    name: Option<String>,
    address: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRecipient {
    email_address: Option<RawEmailAddress>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawBody {
    content_type: Option<String>,
    content: Option<String>,
}

/// A message as returned by Graph.
///
/// Every field is optional: Graph omits properties not named in `$select`, and
/// genuinely absent ones (a draft has no `from`, a bare notification may have
/// no `subject`). Deserialization must never fail on a real mailbox.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMessage {
    id: String,
    subject: Option<String>,
    from: Option<RawRecipient>,
    #[serde(default = "Vec::new")]
    to_recipients: Vec<RawRecipient>,
    #[serde(default = "Vec::new")]
    cc_recipients: Vec<RawRecipient>,
    received_date_time: Option<String>,
    is_read: Option<bool>,
    has_attachments: Option<bool>,
    body: Option<RawBody>,
    body_preview: Option<String>,
    internet_message_id: Option<String>,
    web_link: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawFolder {
    id: String,
    display_name: Option<String>,
    total_item_count: Option<i64>,
    unread_item_count: Option<i64>,
    child_folder_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAttachment {
    #[serde(rename = "@odata.type")]
    odata_type: Option<String>,
    id: String,
    name: Option<String>,
    content_type: Option<String>,
    size: Option<i64>,
    is_inline: Option<bool>,
    content_bytes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDateTimeTz {
    date_time: Option<String>,
    time_zone: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLocation {
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEvent {
    id: String,
    subject: Option<String>,
    start: Option<RawDateTimeTz>,
    end: Option<RawDateTimeTz>,
    location: Option<RawLocation>,
    organizer: Option<RawRecipient>,
    is_all_day: Option<bool>,
}

// ─── Public result types ─────────────────────────────────────────────────────

/// A message summary, shaped to match `ews::EwsMessage` so callers see a
/// consistent surface across protocols.
///
/// `change_key` is deliberately absent: it is an EWS optimistic-concurrency
/// token with no Graph analogue, and emitting an empty one invites callers to
/// use a value that means nothing. `has_attachments` is new — EWS forced a
/// second round trip just to discover it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GraphMessageSummary {
    pub item_id: String,
    pub subject: String,
    pub from_name: String,
    pub from_email: String,
    pub date_received: String,
    pub is_read: bool,
    pub has_attachments: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GraphMessageDetail {
    pub item_id: String,
    pub subject: String,
    pub from_name: String,
    pub from_email: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub date_received: String,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub is_read: bool,
    pub has_attachments: bool,
    pub internet_message_id: Option<String>,
    pub web_link: Option<String>,
}

/// Metadata for one attachment on an existing message.
///
/// Named to distinguish it from the send-side `GraphAttachment`, which is an
/// outbound upload payload rather than a description of stored content.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GraphAttachmentInfo {
    pub attachment_id: String,
    pub name: String,
    pub content_type: String,
    pub size_bytes: usize,
    pub is_inline: bool,
    /// PDF text, when `extract_text` was requested and extraction succeeded.
    pub extracted_text: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GraphCalendarEvent {
    pub item_id: String,
    pub subject: String,
    pub start: String,
    pub end: String,
    /// Timezone the `start`/`end` values are expressed in, as reported by
    /// Graph. Surfaced so a caller can tell at a glance whether the requested
    /// `Prefer: outlook.timezone` was honoured, rather than silently reading
    /// UTC timestamps as local ones.
    pub timezone: String,
    pub location: String,
    pub organizer_name: String,
    pub organizer_email: String,
    pub is_all_day: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GraphFolder {
    pub folder_id: String,
    pub display_name: String,
    pub total_items: i64,
    pub unread_items: i64,
    pub child_folders: i64,
}

// ─── Conversions ─────────────────────────────────────────────────────────────

fn recipient_parts(r: Option<&RawRecipient>) -> (String, String) {
    let addr = r.and_then(|r| r.email_address.as_ref());
    (
        addr.and_then(|a| a.name.clone()).unwrap_or_default(),
        addr.and_then(|a| a.address.clone()).unwrap_or_default(),
    )
}

fn recipient_emails(list: &[RawRecipient]) -> Vec<String> {
    list.iter()
        .filter_map(|r| r.email_address.as_ref().and_then(|a| a.address.clone()))
        .collect()
}

impl From<RawMessage> for GraphMessageSummary {
    fn from(m: RawMessage) -> Self {
        let (from_name, from_email) = recipient_parts(m.from.as_ref());
        Self {
            item_id: m.id,
            subject: m.subject.unwrap_or_default(),
            from_name,
            from_email,
            date_received: m.received_date_time.unwrap_or_default(),
            is_read: m.is_read.unwrap_or(false),
            has_attachments: m.has_attachments.unwrap_or(false),
        }
    }
}

impl From<RawMessage> for GraphMessageDetail {
    fn from(m: RawMessage) -> Self {
        let (from_name, from_email) = recipient_parts(m.from.as_ref());
        let to = recipient_emails(&m.to_recipients);
        let cc = recipient_emails(&m.cc_recipients);

        // Graph reports which representation it returned; route the content to
        // the matching field rather than guessing from what was requested.
        let (mut body_text, mut body_html) = (None, None);
        if let Some(body) = m.body {
            let content = body.content.unwrap_or_default();
            let is_html = body
                .content_type
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("html"));
            if is_html {
                body_html = Some(content);
            } else {
                body_text = Some(sanitize_cdata(&content));
            }
        }
        if body_text.is_none() && body_html.is_none() {
            body_text = m.body_preview;
        }

        Self {
            item_id: m.id,
            subject: m.subject.unwrap_or_default(),
            from_name,
            from_email,
            to,
            cc,
            date_received: m.received_date_time.unwrap_or_default(),
            body_text,
            body_html,
            is_read: m.is_read.unwrap_or(false),
            has_attachments: m.has_attachments.unwrap_or(false),
            internet_message_id: m.internet_message_id,
            web_link: m.web_link,
        }
    }
}

impl From<RawEvent> for GraphCalendarEvent {
    fn from(e: RawEvent) -> Self {
        let (organizer_name, organizer_email) = recipient_parts(e.organizer.as_ref());
        let timezone = e
            .start
            .as_ref()
            .and_then(|d| d.time_zone.clone())
            .unwrap_or_default();
        Self {
            item_id: e.id,
            subject: e.subject.unwrap_or_default(),
            start: e.start.and_then(|d| d.date_time).unwrap_or_default(),
            end: e.end.and_then(|d| d.date_time).unwrap_or_default(),
            timezone,
            location: e.location.and_then(|l| l.display_name).unwrap_or_default(),
            organizer_name,
            organizer_email,
            is_all_day: e.is_all_day.unwrap_or(false),
        }
    }
}

impl From<RawFolder> for GraphFolder {
    fn from(f: RawFolder) -> Self {
        Self {
            folder_id: f.id,
            display_name: f.display_name.unwrap_or_default(),
            total_items: f.total_item_count.unwrap_or(0),
            unread_items: f.unread_item_count.unwrap_or(0),
            child_folders: f.child_folder_count.unwrap_or(0),
        }
    }
}

// ─── Query construction ──────────────────────────────────────────────────────

/// Fields requested for message summaries.
const MESSAGE_SUMMARY_SELECT: &str = "id,subject,from,receivedDateTime,isRead,hasAttachments";

/// Longest accepted KQL query string.
const MAX_QUERY_LEN: usize = 512;

/// A built query for `/me/messages` or `/me/mailFolders/{id}/messages`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MessageQuery {
    /// Path and query string, already encoded, relative to the API base.
    pub path: String,
    /// Whether `$search` was used (which changes the guarantees below).
    pub used_search: bool,
    /// True when a caller-supplied `offset` had to be dropped.
    ///
    /// Graph does not support `$skip` alongside `$search`. Silently ignoring
    /// it would hand back page 1 forever while the caller believed it was
    /// paging; surfacing it lets the tool say so.
    pub offset_ignored: bool,
}

/// Validate and normalise a caller-supplied KQL query.
fn sanitize_query(query: &str) -> AppResult<String> {
    let trimmed = query.trim();
    if trimmed.len() > MAX_QUERY_LEN {
        return Err(AppError::invalid(format!(
            "query must be at most {MAX_QUERY_LEN} characters"
        )));
    }
    // The whole KQL expression is wrapped in double quotes in the $search
    // parameter, so an embedded quote would terminate it early and produce a
    // confusing server-side parse error.
    if trimmed.contains('"') {
        return Err(AppError::invalid(
            "query must not contain double quotes; use single words or KQL operators (AND, OR, subject:, from:)",
        ));
    }
    Ok(trimmed.to_owned())
}

/// Validate a `YYYY-MM-DD` date.
fn validate_date(label: &str, value: &str) -> AppResult<String> {
    let v = value.trim();
    let ok = v.len() == 10
        && v.as_bytes()[4] == b'-'
        && v.as_bytes()[7] == b'-'
        && v.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        });
    if !ok {
        return Err(AppError::invalid(format!(
            "{label} must be a date in YYYY-MM-DD form, got '{value}'"
        )));
    }
    Ok(v.to_owned())
}

/// Build the query for a message search or listing.
///
/// Graph imposes two constraints that shape this into three mutually exclusive
/// modes, both verified against the live API:
///
/// - `$search` with `$filter` is rejected outright (`SearchWithFilter`).
/// - `$search` with `$orderby` is rejected too, and `$skip` is ignored.
///
/// So when a full-text `query` is present the date range is folded into the
/// KQL expression itself (`received>=…`), which Graph honours and returns
/// newest-first natively. Without a query, ordinary `$filter` + `$orderby`
/// paging applies.
pub(crate) fn build_message_query(
    folder: Option<&str>,
    query: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
    limit: usize,
    offset: usize,
) -> AppResult<MessageQuery> {
    let base = match folder {
        Some(f) => format!("/me/mailFolders/{}/messages", enc(f)),
        None => "/me/messages".to_owned(),
    };

    let query = query
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .map(sanitize_query)
        .transpose()?;
    let since = since
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(|d| validate_date("since", d))
        .transpose()?;
    let until = until
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(|d| validate_date("until", d))
        .transpose()?;

    if let Some(kql) = query {
        // Search mode. Fold dates into KQL, since $filter is unavailable here.
        let mut expr = kql;
        if let Some(s) = &since {
            expr.push_str(&format!(" AND received>={s}"));
        }
        if let Some(u) = &until {
            expr.push_str(&format!(" AND received<={u}"));
        }
        let path = format!(
            "{base}?$search={}&$top={limit}&$select={MESSAGE_SUMMARY_SELECT}",
            enc(&format!("\"{expr}\""))
        );
        return Ok(MessageQuery {
            path,
            used_search: true,
            offset_ignored: offset > 0,
        });
    }

    let mut filters: Vec<String> = Vec::new();
    if let Some(s) = &since {
        filters.push(format!("receivedDateTime ge {s}T00:00:00Z"));
    }
    if let Some(u) = &until {
        filters.push(format!("receivedDateTime le {u}T23:59:59Z"));
    }

    // $orderby is only legal alongside $filter when it names a filtered
    // property; both use receivedDateTime, so this stays valid in either mode.
    let mut path = base;
    path.push_str(&format!(
        "?$top={limit}&$orderby={}&$select={MESSAGE_SUMMARY_SELECT}",
        enc("receivedDateTime desc")
    ));
    if offset > 0 {
        path.push_str(&format!("&$skip={offset}"));
    }
    if !filters.is_empty() {
        path.push_str(&format!("&$filter={}", enc(&filters.join(" and "))));
    }

    Ok(MessageQuery {
        path,
        used_search: false,
        offset_ignored: false,
    })
}

// ─── Folder resolution ───────────────────────────────────────────────────────

/// Map a friendly folder name to a Graph well-known folder name.
///
/// Graph's well-known names are byte-identical to the EWS distinguished folder
/// ids and are usable directly as a path segment (`/me/mailFolders/inbox`), so
/// this is a straight port of `ews::distinguished_folder_id`. It is duplicated
/// rather than shared to keep `ews.rs` untouched — that module is scheduled for
/// removal when EWS shuts down in April 2027.
fn well_known_folder(name: &str) -> Option<&'static str> {
    match name.trim().to_ascii_lowercase().as_str() {
        "inbox" => Some("inbox"),
        "sent" | "sentitems" | "sent items" => Some("sentitems"),
        "drafts" => Some("drafts"),
        "deleted" | "deleteditems" | "deleted items" | "trash" => Some("deleteditems"),
        "junk" | "junkemail" | "junk email" | "spam" => Some("junkemail"),
        "archive" => Some("archive"),
        "outbox" => Some("outbox"),
        "msgfolderroot" | "root" => Some("msgfolderroot"),
        _ => None,
    }
}

/// Heuristic: does this string look like a Graph folder/message id?
///
/// Graph ids are long opaque base64url-ish blobs. Display names are short and
/// frequently contain spaces. Mirrors the same back-compat escape hatch EWS has.
fn looks_like_id(value: &str) -> bool {
    value.len() > 40 && !value.contains(' ') && !value.contains('/')
}

async fn fetch_child_folders(
    tm: &TokenManager,
    account_id: &str,
    parent: Option<&str>,
) -> AppResult<Vec<RawFolder>> {
    let path = match parent {
        Some(id) => format!(
            "/me/mailFolders/{}/childFolders?$top=100&$select=id,displayName,totalItemCount,unreadItemCount,childFolderCount",
            enc(id)
        ),
        None => "/me/mailFolders?$top=100&$select=id,displayName,totalItemCount,unreadItemCount,childFolderCount".to_owned(),
    };
    let list: GraphList<RawFolder> =
        graph_get(tm, account_id, &path, &[], GRAPH_TIMEOUT, "list folders").await?;
    Ok(list.value)
}

/// Resolve a user-supplied folder reference to something addressable.
///
/// Order: well-known name → looks-like-an-id → `"Parent/Child"` path → search
/// by display name.
///
/// Unlike EWS, Graph offers no deep folder traversal, so the display-name case
/// is a bounded breadth-first walk. Results are memoised in [`folder_cache`].
pub async fn resolve_folder(
    tm: &TokenManager,
    account_id: &str,
    folder: &str,
) -> AppResult<String> {
    let folder = folder.trim();
    if folder.is_empty() {
        return Ok("inbox".to_owned());
    }
    if let Some(known) = well_known_folder(folder) {
        return Ok(known.to_owned());
    }
    if looks_like_id(folder) {
        return Ok(folder.to_owned());
    }

    let cache_key = (account_id.to_owned(), folder.to_ascii_lowercase());
    if let Some(hit) = folder_cache().lock().await.get(&cache_key) {
        return Ok(hit.clone());
    }

    let resolved = if folder.contains('/') {
        resolve_folder_path(tm, account_id, folder).await?
    } else {
        resolve_folder_by_name(tm, account_id, folder).await?
    };

    folder_cache()
        .lock()
        .await
        .insert(cache_key, resolved.clone());
    Ok(resolved)
}

/// Walk an explicit `"Parent/Child/Grandchild"` path one level at a time.
async fn resolve_folder_path(tm: &TokenManager, account_id: &str, path: &str) -> AppResult<String> {
    let mut current: Option<String> = None;
    for segment in path.split('/').map(str::trim).filter(|s| !s.is_empty()) {
        // Allow the first segment to be a well-known root such as "archive/2026".
        if current.is_none()
            && let Some(known) = well_known_folder(segment)
        {
            current = Some(known.to_owned());
            continue;
        }
        let children = fetch_child_folders(tm, account_id, current.as_deref()).await?;
        let hit = children
            .into_iter()
            .find(|f| {
                f.display_name
                    .as_deref()
                    .is_some_and(|d| d.eq_ignore_ascii_case(segment))
            })
            .ok_or_else(|| {
                AppError::InvalidInput(format!(
                    "Graph: no folder named '{segment}' while resolving path '{path}'"
                ))
            })?;
        current = Some(hit.id);
    }
    current.ok_or_else(|| AppError::InvalidInput(format!("Graph: empty folder path '{path}'")))
}

/// Bounded breadth-first search of the folder tree by display name.
async fn resolve_folder_by_name(
    tm: &TokenManager,
    account_id: &str,
    name: &str,
) -> AppResult<String> {
    let mut queue: VecDeque<(Option<String>, usize)> = VecDeque::from([(None, 0usize)]);
    let mut requests = 0usize;

    while let Some((parent, depth)) = queue.pop_front() {
        if depth > FOLDER_BFS_MAX_DEPTH || requests >= FOLDER_BFS_MAX_REQUESTS {
            break;
        }
        requests += 1;
        let children = fetch_child_folders(tm, account_id, parent.as_deref()).await?;
        for folder in &children {
            if folder
                .display_name
                .as_deref()
                .is_some_and(|d| d.eq_ignore_ascii_case(name))
            {
                return Ok(folder.id.clone());
            }
        }
        for folder in children {
            if folder.child_folder_count.unwrap_or(0) > 0 {
                queue.push_back((Some(folder.id), depth + 1));
            }
        }
    }

    Err(AppError::InvalidInput(format!(
        "Graph: no folder found with display name '{name}'"
    )))
}

/// List the mailbox folder tree (top level plus one level of children).
pub async fn list_folders(tm: &TokenManager, account_id: &str) -> AppResult<Vec<GraphFolder>> {
    let top = fetch_child_folders(tm, account_id, None).await?;
    let mut out: Vec<GraphFolder> = Vec::new();
    for folder in top {
        let has_children = folder.child_folder_count.unwrap_or(0) > 0;
        let id = folder.id.clone();
        let name = folder.display_name.clone().unwrap_or_default();
        out.push(folder.into());
        if has_children {
            for child in fetch_child_folders(tm, account_id, Some(&id)).await? {
                let mut c: GraphFolder = child.into();
                c.display_name = format!("{name}/{}", c.display_name);
                out.push(c);
            }
        }
    }
    Ok(out)
}

// ─── Operations ──────────────────────────────────────────────────────────────

/// Result of a message search, including whether paging was honoured.
#[derive(Debug, Clone)]
pub struct MessageSearchResult {
    pub messages: Vec<GraphMessageSummary>,
    pub used_search: bool,
    pub offset_ignored: bool,
}

/// Criteria for [`find_messages`].
///
/// Grouped into a struct rather than passed positionally because four of the
/// fields are `Option<&str>` and would otherwise be trivial to transpose at a
/// call site — swapping `since` and `until` silently inverts a date range.
#[derive(Debug, Clone, Copy, Default)]
pub struct MessageSearch<'a> {
    /// Well-known name, display name, `Parent/Child` path, or folder id.
    /// `None` searches the whole mailbox.
    pub folder: Option<&'a str>,
    /// KQL expression (`subject:…`, `from:…`, `AND`/`OR`).
    pub query: Option<&'a str>,
    /// Inclusive lower bound, `YYYY-MM-DD`.
    pub since: Option<&'a str>,
    /// Inclusive upper bound, `YYYY-MM-DD`.
    pub until: Option<&'a str>,
    pub limit: usize,
    pub offset: usize,
}

/// Search or list messages.
pub async fn find_messages(
    tm: &TokenManager,
    account_id: &str,
    search: MessageSearch<'_>,
) -> AppResult<MessageSearchResult> {
    let resolved = match search.folder {
        Some(f) => Some(resolve_folder(tm, account_id, f).await?),
        None => None,
    };
    let built = build_message_query(
        resolved.as_deref(),
        search.query,
        search.since,
        search.until,
        search.limit,
        search.offset,
    )?;
    let list: GraphList<RawMessage> = graph_get(
        tm,
        account_id,
        &built.path,
        &[],
        GRAPH_TIMEOUT,
        "search messages",
    )
    .await?;

    Ok(MessageSearchResult {
        messages: list.value.into_iter().map(Into::into).collect(),
        used_search: built.used_search,
        offset_ignored: built.offset_ignored,
    })
}

/// How to render a message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFormat {
    Text,
    Html,
    Both,
}

impl BodyFormat {
    pub fn parse(value: Option<&str>) -> AppResult<Self> {
        match value
            .map(str::trim)
            .unwrap_or("text")
            .to_ascii_lowercase()
            .as_str()
        {
            "text" => Ok(Self::Text),
            "html" => Ok(Self::Html),
            "both" => Ok(Self::Both),
            other => Err(AppError::invalid(format!(
                "body_format must be one of text, html, both; got '{other}'"
            ))),
        }
    }
}

const MESSAGE_DETAIL_SELECT: &str = "id,subject,from,toRecipients,ccRecipients,receivedDateTime,isRead,hasAttachments,body,bodyPreview,internetMessageId,webLink";

/// Fetch one message.
///
/// Graph converts the stored body on request via the `Prefer:
/// outlook.body-content-type` header, so plain text is available directly even
/// for HTML-only mail. That removes the opt-in-HTML dance and raw-MIME
/// fallback the IMAP path needs.
pub async fn get_message(
    tm: &TokenManager,
    account_id: &str,
    item_id: &str,
    body_format: BodyFormat,
) -> AppResult<GraphMessageDetail> {
    let path = format!(
        "/me/messages/{}?$select={MESSAGE_DETAIL_SELECT}",
        enc(item_id)
    );

    async fn fetch(
        tm: &TokenManager,
        account_id: &str,
        path: &str,
        prefer: &str,
    ) -> AppResult<GraphMessageDetail> {
        let raw: RawMessage = graph_get(
            tm,
            account_id,
            path,
            &[("Prefer", prefer)],
            GRAPH_TIMEOUT,
            "get message",
        )
        .await?;
        Ok(raw.into())
    }

    const AS_TEXT: &str = r#"outlook.body-content-type="text""#;
    const AS_HTML: &str = r#"outlook.body-content-type="html""#;

    match body_format {
        BodyFormat::Text => fetch(tm, account_id, &path, AS_TEXT).await,
        BodyFormat::Html => fetch(tm, account_id, &path, AS_HTML).await,
        BodyFormat::Both => {
            let text = fetch(tm, account_id, &path, AS_TEXT).await?;
            let html = fetch(tm, account_id, &path, AS_HTML).await?;
            Ok(GraphMessageDetail {
                body_html: html.body_html,
                ..text
            })
        }
    }
}

/// List a message's file attachments, optionally extracting PDF text.
///
/// Unlike EWS this needs a single round trip: Graph returns metadata and
/// `contentBytes` together. When text extraction is not requested, the
/// content is excluded from `$select` so multi-MB payloads never cross the
/// wire.
pub async fn get_attachments(
    tm: &TokenManager,
    account_id: &str,
    item_id: &str,
    extract_text: bool,
    max_chars: usize,
) -> AppResult<Vec<GraphAttachmentInfo>> {
    let select = if extract_text {
        "id,name,contentType,size,isInline,contentBytes"
    } else {
        "id,name,contentType,size,isInline"
    };
    let path = format!("/me/messages/{}/attachments?$select={select}", enc(item_id));
    let list: GraphList<RawAttachment> = graph_get(
        tm,
        account_id,
        &path,
        &[],
        GRAPH_ATTACHMENT_TIMEOUT,
        "get attachments",
    )
    .await?;

    let mut out = Vec::new();
    for raw in list.value {
        // Skip embedded messages and reference attachments; only real files
        // have retrievable bytes. Mirrors the EWS FileAttachment-only rule.
        if let Some(t) = raw.odata_type.as_deref()
            && !t.eq_ignore_ascii_case("#microsoft.graph.fileAttachment")
        {
            continue;
        }

        let content_type = raw.content_type.unwrap_or_default();
        let mut info = GraphAttachmentInfo {
            attachment_id: raw.id,
            name: raw.name.unwrap_or_default(),
            size_bytes: raw.size.unwrap_or(0).max(0) as usize,
            is_inline: raw.is_inline.unwrap_or(false),
            extracted_text: None,
            content_type,
        };

        if extract_text
            && info.content_type.eq_ignore_ascii_case("application/pdf")
            && let Some(b64) = raw.content_bytes
            && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&b64)
        {
            info.size_bytes = bytes.len();
            if bytes.len() <= PDF_EXTRACT_MAX_BYTES
                && let Ok(text) = pdf_extract::extract_text_from_mem(&bytes)
            {
                info.extracted_text = Some(truncate_chars(text, max_chars));
            }
        }
        out.push(info);
    }
    Ok(out)
}

/// List calendar events in a date range.
///
/// The `Prefer: outlook.timezone` header matters: without it Graph returns UTC
/// while still labelling the values, which silently shifts every meeting time
/// for a JST mailbox.
pub async fn list_calendar(
    tm: &TokenManager,
    account_id: &str,
    start_date: &str,
    end_date: &str,
    limit: usize,
    timezone: &str,
) -> AppResult<Vec<GraphCalendarEvent>> {
    let start = validate_date("start_date", start_date)?;
    let end = validate_date("end_date", end_date)?;
    let path = format!(
        "/me/calendarView?startDateTime={start}T00:00:00&endDateTime={end}T23:59:59&$top={limit}&$orderby={}&$select=id,subject,start,end,location,organizer,isAllDay",
        enc("start/dateTime")
    );
    let prefer = format!("outlook.timezone=\"{timezone}\"");
    let list: GraphList<RawEvent> = graph_get(
        tm,
        account_id,
        &path,
        &[("Prefer", prefer.as_str())],
        GRAPH_TIMEOUT,
        "list calendar",
    )
    .await?;
    Ok(list.value.into_iter().map(Into::into).collect())
}

/// Move a message to another folder.
///
/// Returns the message's **new** id: Graph, like EWS, re-issues the id on move,
/// so the caller's old handle stops resolving.
pub async fn move_message(
    tm: &TokenManager,
    account_id: &str,
    item_id: &str,
    dest_folder: &str,
) -> AppResult<String> {
    let destination = resolve_folder(tm, account_id, dest_folder).await?;
    let path = format!("/me/messages/{}/move", enc(item_id));
    let body = serde_json::json!({ "destinationId": destination });
    let moved: RawMessage = graph_post_json(tm, account_id, &path, &body, "move message").await?;
    Ok(moved.id)
}

/// Delete a message.
///
/// `hard` selects `permanentDelete`, which is irreversible. The default sends
/// the message to Deleted Items, where it remains recoverable.
pub async fn delete_message(
    tm: &TokenManager,
    account_id: &str,
    item_id: &str,
    hard: bool,
) -> AppResult<()> {
    if hard {
        let path = format!("/me/messages/{}/permanentDelete", enc(item_id));
        graph_post_empty(tm, account_id, &path, "permanently delete message").await
    } else {
        let path = format!("/me/messages/{}", enc(item_id));
        graph_delete(tm, account_id, &path, "delete message").await
    }
}

/// Mark a message read or unread.
pub async fn set_read(
    tm: &TokenManager,
    account_id: &str,
    item_id: &str,
    is_read: bool,
) -> AppResult<()> {
    let path = format!("/me/messages/{}", enc(item_id));
    let body = serde_json::json!({ "isRead": is_read });
    graph_patch_json(tm, account_id, &path, &body, "set read state").await
}

// ─── Shared helpers ─────────────────────────────────────────────────────────

async fn handle_response(response: reqwest::Response) -> AppResult<()> {
    if response.status().is_success() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(AppError::AuthFailed(format!(
                "Graph API authentication failed ({status}): {body}"
            )))
        } else {
            Err(AppError::Internal(format!(
                "Graph API sendMail failed ({status}): {body}"
            )))
        }
    }
}

/// Remove CDATA artifacts that some email clients leak into text.
fn sanitize_cdata(text: &str) -> String {
    text.replace("]]>", "").replace("<![CDATA[", "")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Query builder ───────────────────────────────────────────────────
    //
    // These encode two constraints verified against the live Graph API:
    // $search rejects $filter (error code SearchWithFilter), and $search
    // rejects $orderby / ignores $skip. Getting this wrong produces either a
    // hard 400 or, worse, silently repeated pages.

    fn q(
        folder: Option<&str>,
        query: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
    ) -> MessageQuery {
        build_message_query(folder, query, since, until, 10, 0).unwrap()
    }

    #[test]
    fn search_and_filter_never_coexist() {
        let built = q(None, Some("subject:点検"), Some("2026-05-01"), None);
        assert!(built.used_search);
        assert!(built.path.contains("$search="));
        assert!(
            !built.path.contains("$filter="),
            "combining $search with $filter is rejected by Graph as SearchWithFilter: {}",
            built.path
        );
    }

    #[test]
    fn search_and_orderby_never_coexist() {
        let built = q(None, Some("subject:点検"), None, None);
        assert!(!built.path.contains("$orderby="), "{}", built.path);
    }

    #[test]
    fn search_mode_folds_since_into_kql() {
        let built = q(None, Some("subject:点検"), Some("2026-05-01"), None);
        let decoded = urlencoding::decode(&built.path).unwrap().into_owned();
        assert!(
            decoded.contains("subject:点検 AND received>=2026-05-01"),
            "{decoded}"
        );
    }

    #[test]
    fn search_mode_folds_both_dates() {
        let built = q(None, Some("報告"), Some("2026-05-01"), Some("2026-06-01"));
        let decoded = urlencoding::decode(&built.path).unwrap().into_owned();
        assert!(decoded.contains("received>=2026-05-01"), "{decoded}");
        assert!(decoded.contains("received<=2026-06-01"), "{decoded}");
    }

    #[test]
    fn search_mode_drops_skip_and_flags_it() {
        let built = build_message_query(None, Some("報告"), None, None, 10, 25).unwrap();
        assert!(!built.path.contains("$skip="));
        assert!(
            built.offset_ignored,
            "callers must be told their offset was dropped, or they page forever"
        );
    }

    #[test]
    fn list_mode_emits_orderby_and_skip() {
        let built = build_message_query(None, None, None, None, 10, 25).unwrap();
        assert!(!built.used_search);
        assert!(!built.offset_ignored);
        assert!(built.path.contains("$skip=25"), "{}", built.path);
        let decoded = urlencoding::decode(&built.path).unwrap().into_owned();
        assert!(
            decoded.contains("$orderby=receivedDateTime desc"),
            "{decoded}"
        );
    }

    #[test]
    fn filter_mode_emits_orderby_matching_filter_property() {
        let built = q(None, None, Some("2026-05-01"), Some("2026-06-01"));
        let decoded = urlencoding::decode(&built.path).unwrap().into_owned();
        assert!(
            decoded.contains("receivedDateTime ge 2026-05-01T00:00:00Z"),
            "{decoded}"
        );
        assert!(
            decoded.contains("receivedDateTime le 2026-06-01T23:59:59Z"),
            "{decoded}"
        );
        // Graph only permits $orderby with $filter when the ordered property
        // is also filtered. Both are receivedDateTime, so this is legal.
        assert!(
            decoded.contains("$orderby=receivedDateTime desc"),
            "{decoded}"
        );
    }

    #[test]
    fn japanese_query_survives_encoding() {
        // The whole point of the Graph migration: EWS AQS matched only
        // dictionary word tokens, so multi-word compounds like these returned
        // zero hits. Graph KQL handles them, provided we transport them intact.
        for term in ["定期清掃", "自動ドア", "エレベーター点検"] {
            let built = q(None, Some(term), None, None);
            let decoded = urlencoding::decode(&built.path).unwrap().into_owned();
            assert!(decoded.contains(term), "{term} lost in {decoded}");
        }
    }

    #[test]
    fn search_value_is_quoted() {
        let built = q(None, Some("subject:報告"), None, None);
        let decoded = urlencoding::decode(&built.path).unwrap().into_owned();
        assert!(decoded.contains("$search=\"subject:報告\""), "{decoded}");
    }

    #[test]
    fn rejects_embedded_double_quote() {
        assert!(build_message_query(None, Some("subject:\"a b\""), None, None, 10, 0).is_err());
    }

    #[test]
    fn rejects_overlong_query() {
        let long = "a".repeat(MAX_QUERY_LEN + 1);
        assert!(build_message_query(None, Some(&long), None, None, 10, 0).is_err());
    }

    #[test]
    fn rejects_malformed_dates() {
        for bad in [
            "2026-5-1",
            "20260501",
            "2026/05/01",
            "not-a-date",
            "2026-05-01T00",
        ] {
            assert!(
                build_message_query(None, None, Some(bad), None, 10, 0).is_err(),
                "should reject {bad}"
            );
        }
        assert!(build_message_query(None, None, Some("2026-05-01"), None, 10, 0).is_ok());
    }

    #[test]
    fn folder_scoping_targets_the_folder_collection() {
        let built = q(Some("inbox"), None, None, None);
        assert!(
            built.path.starts_with("/me/mailFolders/inbox/messages?"),
            "{}",
            built.path
        );
        let unscoped = q(None, None, None, None);
        assert!(
            unscoped.path.starts_with("/me/messages?"),
            "{}",
            unscoped.path
        );
    }

    #[test]
    fn blank_query_and_dates_fall_back_to_list_mode() {
        let built = q(None, Some("   "), Some("  "), None);
        assert!(!built.used_search);
        assert!(!built.path.contains("$search="));
        assert!(!built.path.contains("$filter="));
    }

    // ─── Folder helpers ──────────────────────────────────────────────────

    #[test]
    fn well_known_folder_maps_same_aliases_as_ews() {
        assert_eq!(well_known_folder("Inbox"), Some("inbox"));
        assert_eq!(well_known_folder("sent items"), Some("sentitems"));
        assert_eq!(well_known_folder("Deleted Items"), Some("deleteditems"));
        assert_eq!(well_known_folder("junk email"), Some("junkemail"));
        assert_eq!(well_known_folder("ARCHIVE"), Some("archive"));
        assert_eq!(well_known_folder("Temp archive"), None);
        assert_eq!(well_known_folder("Mass"), None);
    }

    #[test]
    fn looks_like_id_distinguishes_ids_from_display_names() {
        assert!(looks_like_id(&"A".repeat(60)));
        assert!(!looks_like_id("Temp archive"));
        assert!(!looks_like_id("Mass"));
        assert!(!looks_like_id("Parent/Child"));
    }

    // ─── Response parsing ────────────────────────────────────────────────

    #[test]
    fn parses_message_summary_with_nested_sender() {
        let raw: RawMessage = serde_json::from_str(
            r#"{"id":"AAA=","subject":"点検のお知らせ",
                "from":{"emailAddress":{"name":"施設課","address":"fac@example.jp"}},
                "receivedDateTime":"2026-08-07T01:02:03Z","isRead":false,"hasAttachments":true}"#,
        )
        .unwrap();
        let s: GraphMessageSummary = raw.into();
        assert_eq!(s.item_id, "AAA=");
        assert_eq!(s.subject, "点検のお知らせ");
        assert_eq!(s.from_name, "施設課");
        assert_eq!(s.from_email, "fac@example.jp");
        assert!(!s.is_read);
        assert!(s.has_attachments);
    }

    /// Drafts have no sender, and $select omissions leave fields absent.
    /// Deserialization must not fail on either.
    #[test]
    fn parses_message_missing_optional_fields() {
        let raw: RawMessage = serde_json::from_str(r#"{"id":"BBB="}"#).unwrap();
        let s: GraphMessageSummary = raw.into();
        assert_eq!(s.subject, "");
        assert_eq!(s.from_email, "");
        assert!(!s.has_attachments);
    }

    #[test]
    fn routes_body_by_reported_content_type() {
        let html: RawMessage = serde_json::from_str(
            r#"{"id":"C=","body":{"contentType":"html","content":"<p>hi</p>"}}"#,
        )
        .unwrap();
        let d: GraphMessageDetail = html.into();
        assert_eq!(d.body_html.as_deref(), Some("<p>hi</p>"));
        assert!(d.body_text.is_none());

        let text: RawMessage =
            serde_json::from_str(r#"{"id":"D=","body":{"contentType":"text","content":"plain"}}"#)
                .unwrap();
        let d: GraphMessageDetail = text.into();
        assert_eq!(d.body_text.as_deref(), Some("plain"));
        assert!(d.body_html.is_none());
    }

    #[test]
    fn collects_to_and_cc_addresses() {
        let raw: RawMessage = serde_json::from_str(
            r#"{"id":"E=",
                "toRecipients":[{"emailAddress":{"address":"a@x.jp"}},{"emailAddress":{"address":"b@x.jp"}}],
                "ccRecipients":[{"emailAddress":{"address":"c@x.jp"}}]}"#,
        )
        .unwrap();
        let d: GraphMessageDetail = raw.into();
        assert_eq!(d.to, vec!["a@x.jp", "b@x.jp"]);
        assert_eq!(d.cc, vec!["c@x.jp"]);
    }

    #[test]
    fn parses_folder_list() {
        let list: GraphList<RawFolder> = serde_json::from_str(
            r#"{"value":[{"id":"f1","displayName":"Mass","totalItemCount":776,"childFolderCount":0}]}"#,
        )
        .unwrap();
        let f: GraphFolder = list.value.into_iter().next().unwrap().into();
        assert_eq!(f.display_name, "Mass");
        assert_eq!(f.total_items, 776);
    }

    #[test]
    fn parses_calendar_event() {
        let raw: RawEvent = serde_json::from_str(
            r#"{"id":"ev1","subject":"Meeting","start":{"dateTime":"2026-08-11T01:00:00.0000000","timeZone":"Tokyo Standard Time"},
                "end":{"dateTime":"2026-08-11T02:00:00.0000000","timeZone":"Tokyo Standard Time"},
                "location":{"displayName":"J615"},
                "organizer":{"emailAddress":{"name":"V","address":"v@x.jp"}},"isAllDay":false}"#,
        )
        .unwrap();
        let e: GraphCalendarEvent = raw.into();
        assert_eq!(e.subject, "Meeting");
        assert_eq!(e.location, "J615");
        assert_eq!(e.organizer_email, "v@x.jp");
        assert!(e.start.starts_with("2026-08-11T01:00"));
        // Surfacing the timezone is what lets a caller notice that a requested
        // Prefer: outlook.timezone was ignored, instead of reading UTC times
        // as local ones and being nine hours out.
        assert_eq!(e.timezone, "Tokyo Standard Time");
    }

    #[test]
    fn empty_collection_deserializes() {
        let list: GraphList<RawMessage> = serde_json::from_str(r#"{"value":[]}"#).unwrap();
        assert!(list.value.is_empty());
    }

    #[test]
    fn recipient_builds_correct_structure() {
        let r = recipient("test@example.com");
        assert_eq!(r.email_address.address, "test@example.com");
    }

    #[test]
    fn recipients_builds_list() {
        let addrs = vec!["a@b.com".to_owned(), "c@d.com".to_owned()];
        let rs = recipients(&addrs);
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].email_address.address, "a@b.com");
    }

    /// Regression test for the v0.4.7 fix. `PatchDraftRequest` MUST NOT
    /// serialize an `attachments` field — Graph silently drops it when
    /// set via PATCH on `/me/messages/{id}`, which was the v0.4.6 silent
    /// data-loss bug. Attachments must travel through the dedicated
    /// `/me/messages/{id}/attachments` endpoint instead.
    #[test]
    fn patch_draft_request_never_serializes_attachments() {
        let req = PatchDraftRequest {
            subject: "Re: test".to_owned(),
            body: GraphBody {
                content_type: "HTML",
                content: "<p>x</p>".to_owned(),
            },
            to_recipients: vec![recipient("to@test.com")],
            cc_recipients: vec![],
            bcc_recipients: vec![],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(
            json.get("attachments").is_none(),
            "PatchDraftRequest must not include attachments (Graph PATCH discards them); got: {json}"
        );
        // Sanity-check the fields that DO travel through PATCH.
        assert_eq!(json["subject"], "Re: test");
        assert_eq!(
            json["toRecipients"][0]["emailAddress"]["address"],
            "to@test.com"
        );
    }

    /// The inline-vs-session threshold must match the Microsoft Graph
    /// documented limit (3 MB raw). Hard-codes the constant so a future
    /// edit doesn't silently shift the boundary into an invalid range.
    // The constant-value assertions are the entire point of this test: it pins
    // the constants so a future edit that shifts them out of Graph's valid
    // range fails here rather than at runtime against the live API.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn attachment_inline_threshold_matches_graph_spec() {
        assert_eq!(ATTACHMENT_INLINE_MAX_BYTES, 3 * 1024 * 1024);
        assert!(UPLOAD_CHUNK_BYTES <= 4 * 1024 * 1024);
        assert!(UPLOAD_CHUNK_BYTES > 0);
    }

    #[test]
    fn send_mail_request_serializes_correctly() {
        let req = SendMailRequest {
            message: GraphMessage {
                subject: "Test".to_owned(),
                body: GraphBody {
                    content_type: "Text",
                    content: "Hello".to_owned(),
                },
                to_recipients: vec![recipient("to@test.com")],
                cc_recipients: vec![],
                bcc_recipients: vec![],
                reply_to: None,
                internet_message_headers: None,
                attachments: vec![],
            },
            save_to_sent_items: true,
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["message"]["subject"], "Test");
        assert_eq!(json["message"]["body"]["contentType"], "Text");
        assert_eq!(
            json["message"]["toRecipients"][0]["emailAddress"]["address"],
            "to@test.com"
        );
        assert_eq!(json["saveToSentItems"], true);
        // cc and bcc should be absent (skip_serializing_if)
        assert!(json["message"].get("ccRecipients").is_none());
    }
}
