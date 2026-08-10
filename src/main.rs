//! mail-mcp: Secure IMAP MCP server over stdio
//!
//! This server provides read/write access to IMAP mailboxes via the Model
//! Context Protocol (MCP) over stdio. It features cursor-based pagination,
//! TLS-only connections, and security-first design.
//!
//! # Architecture
//!
//! - [`main`]: Process entry point with env loading and stdio serving
//! - [`config`]: Environment-driven configuration for accounts and server settings
//! - [`errors`]: Application error model with MCP error mapping
//! - [`imap`]: IMAP transport/session operations with timeout wrappers
//! - [`server`]: MCP tool handlers with validation and business orchestration
//! - [`models`]: Input/output DTOs and schema-bearing types
//! - [`mime`]: Message parsing, header/body extraction, and sanitization
//! - [`message_id`]: Stable, opaque message ID parse/encode logic
//! - [`pagination`]: Cursor storage with TTL and eviction behavior

mod config;
mod errors;
mod ews;
mod graph;
mod imap;
mod message_id;
mod mime;
mod models;
mod oauth2;
mod pagination;
mod server;
mod smtp;

use std::collections::BTreeMap;
use std::io::{self, Write};

use config::ServerConfig;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::EnvFilter;

/// Application entry point
///
/// Initializes tracing from environment, loads config, and serves the MCP
/// server over stdio. This process expects to be spawned by an MCP client
/// via `stdio` transport.
///
/// # Environment Variables
///
/// See [`ServerConfig::load_from_env`] for full configuration options.
///
/// # Example
///
/// ```no_run
/// MAIL_IMAP_DEFAULT_HOST=imap.example.com \
/// MAIL_IMAP_DEFAULT_USER=user@example.com \
/// MAIL_IMAP_DEFAULT_PASS=secret \
/// cargo run
/// ```
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install the rustls CryptoProvider globally so that both tokio-rustls (IMAP)
    // and lettre (SMTP) use the same provider without conflicts.
    let _ = rustls::crypto::ring::default_provider().install_default();

    dotenvy::dotenv().ok();

    if should_print_help(std::env::args().skip(1)) {
        print_help_output()?;
        return Ok(());
    }

    // Hidden developer self-test for the EWS mutate ops (move/delete/set_read).
    // Sends a throwaway mail to self, exercises the lifecycle, hard-deletes it.
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--selftest-ews-mutate") {
        let account = args
            .get(pos + 1)
            .cloned()
            .unwrap_or_else(|| "default".to_owned());
        let folder = args
            .get(pos + 2)
            .cloned()
            .unwrap_or_else(|| "archive".to_owned());
        let config = ServerConfig::load_from_env()?;
        return selftest_ews_mutate(config, &account, &folder).await;
    }
    // Hidden developer self-tests for the Microsoft Graph path. These send and
    // then delete their own throwaway mail; see the safety rules above
    // find_marked_message. Pre-existing mail is never touched.
    if let Some(pos) = args.iter().position(|a| a == "--selftest-graph-search") {
        let account = args
            .get(pos + 1)
            .cloned()
            .unwrap_or_else(|| "default".to_owned());
        // Recipient is explicit, never implied: this can send across accounts.
        let recipient = args.get(pos + 2).filter(|s| !s.starts_with('-')).cloned();
        let pdf = args.get(pos + 3).filter(|s| !s.starts_with('-')).cloned();
        let config = ServerConfig::load_from_env()?;
        return selftest_graph_search(config, &account, recipient.as_deref(), pdf.as_deref()).await;
    }
    if let Some(pos) = args.iter().position(|a| a == "--selftest-graph-mutate") {
        let account = args
            .get(pos + 1)
            .cloned()
            .unwrap_or_else(|| "default".to_owned());
        let folder = args
            .get(pos + 2)
            .cloned()
            .unwrap_or_else(|| "archive".to_owned());
        let config = ServerConfig::load_from_env()?;
        return selftest_graph_mutate(config, &account, &folder).await;
    }
    if let Some(pos) = args.iter().position(|a| a == "--ews-probe") {
        let account = args
            .get(pos + 1)
            .cloned()
            .unwrap_or_else(|| "default".to_owned());
        let query = args.get(pos + 2).cloned().unwrap_or_default();
        let folder = args
            .get(pos + 3)
            .cloned()
            .unwrap_or_else(|| "inbox".to_owned());
        let config = ServerConfig::load_from_env()?;
        use std::sync::Arc;
        let tm = Arc::new(oauth2::TokenManager::new(
            config.ews_oauth2_accounts.clone(),
        ));
        let q = if query.is_empty() {
            None
        } else {
            Some(query.as_str())
        };
        let hits = ews::find_items(&tm, &account, &folder, 50, 0, q).await?;
        println!("folder={folder:?} query={query:?} → {} hit(s)", hits.len());
        for m in &hits {
            println!("  - {}", m.subject);
        }
        return Ok(());
    }
    if let Some(pos) = args.iter().position(|a| a == "--ews-cleanup") {
        let account = args
            .get(pos + 1)
            .cloned()
            .unwrap_or_else(|| "default".to_owned());
        let needle = args.get(pos + 2).cloned().unwrap_or_default();
        let folder = args
            .get(pos + 3)
            .cloned()
            .unwrap_or_else(|| "inbox".to_owned());
        let config = ServerConfig::load_from_env()?;
        use std::sync::Arc;
        let tm = Arc::new(oauth2::TokenManager::new(
            config.ews_oauth2_accounts.clone(),
        ));
        let mut total = 0;
        loop {
            let hits = ews::find_items(&tm, &account, &folder, 50, 0, None).await?;
            let targets: Vec<_> = hits
                .iter()
                .filter(|m| m.subject.contains(&needle))
                .collect();
            if targets.is_empty() {
                break;
            }
            for m in targets {
                ews::delete_item(&tm, &account, &m.item_id, true).await?;
                println!("deleted: {}", m.subject);
                total += 1;
            }
        }
        println!("cleanup done: {total} message(s) hard-deleted matching {needle:?}");
        return Ok(());
    }
    if let Some(pos) = args.iter().position(|a| a == "--selftest-ews-search") {
        let account = args
            .get(pos + 1)
            .cloned()
            .unwrap_or_else(|| "default".to_owned());
        let pdf = args.get(pos + 2).cloned();
        let config = ServerConfig::load_from_env()?;
        return selftest_ews_search(config, &account, pdf.as_deref()).await;
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("starting MCP server transport=Stdio");
    let config = ServerConfig::load_from_env()?;
    let update_notice = check_for_updates().await;
    let service = server::MailImapServer::new(config, update_notice)
        .serve(stdio())
        .await?;
    service.waiting().await?;
    Ok(())
}

/// Hidden self-test: send a throwaway mail to self, then exercise the new EWS
/// move/delete/set_read operations and hard-delete the test message. Touches
/// only a uniquely-marked message it created itself.
async fn selftest_ews_mutate(
    config: ServerConfig,
    account: &str,
    move_folder: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    let tm = Arc::new(oauth2::TokenManager::new(
        config.ews_oauth2_accounts.clone(),
    ));
    let me = config
        .ews_accounts
        .get(account)
        .ok_or_else(|| format!("no EWS account '{account}'"))?
        .user
        .clone();
    println!("Self address: {me}");

    let marker = "EWS-MUTATE-TEST-7f3a9b";
    let subject = format!("{marker} — safe to delete");

    println!("\n[1] Sending test mail to self via EWS…");
    let to = vec![me.clone()];
    let params = ews::EwsSendParams {
        to: &to,
        cc: &[],
        bcc: &[],
        subject: &subject,
        body: "Automated test of ews move/delete/set_read. Deletes itself.",
        body_type: "Text",
        in_reply_to: None,
        references: None,
        attachments: &[],
    };
    ews::send_email(&tm, account, &params).await?;
    println!("    sent.");

    println!("\n[2] Polling inbox for the test message…");
    let mut item_id = String::new();
    for attempt in 1..=20 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let msgs = ews::find_items(&tm, account, "inbox", 15, 0, None).await?;
        if let Some(m) = msgs.iter().find(|m| m.subject.contains(marker)) {
            item_id = m.item_id.clone();
            println!("    found after {attempt} tries (is_read={}).", m.is_read);
            break;
        }
        println!("    not yet (try {attempt})…");
    }
    if item_id.is_empty() {
        return Err("test message never arrived in inbox".into());
    }

    println!("\n[3] Marking read via set_read…");
    ews::set_read(&tm, account, &item_id, true).await?;
    let after = ews::get_item(&tm, account, &item_id).await?;
    println!("    is_read now = {}", after.is_read);
    assert!(after.is_read, "set_read(true) did not stick");

    println!("\n[4] Moving to '{move_folder}'…");
    let moved_id = ews::move_item(&tm, account, &item_id, move_folder).await?;
    // Move re-issues the id; confirm the new id resolves and the message left inbox.
    let moved = ews::get_item(&tm, account, &moved_id).await?;
    println!("    new id resolves, subject = {:?}", moved.subject);
    assert!(
        moved.subject.contains(marker),
        "moved item subject mismatch"
    );
    let inbox = ews::find_items(&tm, account, "inbox", 15, 0, None).await?;
    let in_inbox = inbox.iter().any(|m| m.subject.contains(marker));
    println!("    still in inbox after move: {in_inbox}");
    assert!(!in_inbox, "message still in inbox after move");

    println!("\n[5] Hard-deleting the test message…");
    ews::delete_item(&tm, account, &moved_id, true).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let gone = ews::get_item(&tm, account, &moved_id).await;
    let still = gone.is_ok();
    println!("    item still retrievable after hard delete: {still}");
    assert!(!still, "message still retrievable after hard delete");

    println!("\n✅ Verified: send → set_read → move → hard-delete.");
    Ok(())
}

/// Hidden self-test: send a throwaway mail to self (optionally with a PDF
/// attachment and a Japanese subject token), then exercise AQS search and
/// EWS attachment extraction, and hard-delete the test message.
async fn selftest_ews_search(
    config: ServerConfig,
    account: &str,
    pdf_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    let tm = Arc::new(oauth2::TokenManager::new(
        config.ews_oauth2_accounts.clone(),
    ));
    let me = config
        .ews_accounts
        .get(account)
        .ok_or_else(|| format!("no EWS account '{account}'"))?
        .user
        .clone();
    println!("Self address: {me}");

    let marker = "EWS-SEARCH-TEST-9q2";
    // AQS matches whole word tokens (per Exchange's CJK word-breaker), not
    // arbitrary substrings, so use a real word with surrounding spaces.
    let jp_token = "報告";
    let subject = format!("{marker} {jp_token}");

    // Optional PDF attachment, read from disk.
    let attachments = match pdf_path {
        Some(p) => {
            let bytes = std::fs::read(p)?;
            println!("Attaching PDF: {p} ({} bytes)", bytes.len());
            vec![smtp_email_attachment(p, bytes)]
        }
        None => vec![],
    };

    println!("\n[1] Sending test mail to self (subject has ASCII + Japanese token)…");
    let to = vec![me.clone()];
    let params = ews::EwsSendParams {
        to: &to,
        cc: &[],
        bcc: &[],
        subject: &subject,
        body: "Automated test of ews AQS search + attachments. Deletes itself.",
        body_type: "Text",
        in_reply_to: None,
        references: None,
        attachments: &attachments,
    };
    ews::send_email(&tm, account, &params).await?;
    println!("    sent.");

    // Give the search index a moment to ingest the new message.
    println!("\n[2] AQS search by ASCII subject token…");
    let q_ascii = format!("subject:{marker}");
    let mut item_id = String::new();
    for attempt in 1..=20 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let hits = ews::find_items(&tm, account, "inbox", 15, 0, Some(&q_ascii)).await?;
        if let Some(m) = hits.iter().find(|m| m.subject.contains(marker)) {
            item_id = m.item_id.clone();
            println!(
                "    AQS '{q_ascii}' → {} hit(s), matched after {attempt} tries.",
                hits.len()
            );
            break;
        }
        println!("    not indexed yet (try {attempt})…");
    }
    if item_id.is_empty() {
        return Err("AQS subject search never matched the test message".into());
    }

    println!("\n[3] AQS search by Japanese word token '{jp_token}'…");
    let mut jp_found = false;
    for attempt in 1..=10 {
        let jp_hits = ews::find_items(&tm, account, "inbox", 25, 0, Some(jp_token)).await?;
        if jp_hits.iter().any(|m| m.subject.contains(marker)) {
            println!(
                "    AQS '{jp_token}' → {} hit(s), matched after {attempt} tries.",
                jp_hits.len()
            );
            jp_found = true;
            break;
        }
        println!("    Japanese token not indexed yet (try {attempt})…");
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    assert!(
        jp_found,
        "Japanese AQS search did not find the test message"
    );

    if pdf_path.is_some() {
        println!("\n[4] Extracting attachment text via ews_get_attachments…");
        let atts = ews::get_attachments(&tm, account, &item_id, true, 20_000).await?;
        println!("    {} attachment(s).", atts.len());
        for a in &atts {
            let text_len = a.extracted_text.as_ref().map(|t| t.len()).unwrap_or(0);
            println!(
                "    - {} ({}, {} bytes) extracted_text={} chars",
                a.name, a.content_type, a.size_bytes, text_len
            );
        }
        let any_text = atts
            .iter()
            .any(|a| a.extracted_text.as_ref().is_some_and(|t| !t.is_empty()));
        assert!(any_text, "no PDF text extracted from EWS attachment");
    }

    println!("\n[5] Hard-deleting the test message…");
    ews::delete_item(&tm, account, &item_id, true).await?;
    println!("    deleted.");

    println!("\n✅ Verified: AQS search (ASCII + Japanese) → attachments → cleanup.");
    Ok(())
}

/// Helper: build an `EmailAttachment` from a file path + bytes (filename = base
/// name, content type guessed from extension; good enough for the self-test).
fn smtp_email_attachment(path: &str, bytes: Vec<u8>) -> smtp::EmailAttachment {
    let filename = std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "attachment".to_owned());
    let content_type = if filename.to_ascii_lowercase().ends_with(".pdf") {
        "application/pdf"
    } else {
        "application/octet-stream"
    };
    smtp::EmailAttachment {
        filename,
        content_type: content_type.to_owned(),
        content: bytes,
    }
}

/// Check GitHub for newer releases. Returns a notice string if an update is available.
/// Times out after 2 seconds to avoid blocking startup.
async fn check_for_updates() -> Option<String> {
    let current = env!("CARGO_PKG_VERSION");
    let url = "https://api.github.com/repos/tecnologicachile/mail-mcp/releases/latest";

    let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let client = reqwest::Client::new();
        let resp = client
            .get(url)
            .header("User-Agent", "mail-mcp")
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        let latest_tag = body["tag_name"].as_str()?;
        let latest = latest_tag.trim_start_matches('v');
        if latest != current && latest > current {
            Some(format!(
                "\n\nUpdate available: v{current} -> {latest_tag}. \
                 See https://github.com/tecnologicachile/mail-mcp/releases/tag/{latest_tag}"
            ))
        } else {
            None
        }
    })
    .await;

    match result {
        Ok(notice) => {
            if let Some(ref msg) = notice {
                tracing::info!("update check: {msg}");
            } else {
                tracing::debug!("update check: running latest version v{current}");
            }
            notice
        }
        Err(_) => {
            tracing::debug!("update check: timed out (2s)");
            None
        }
    }
}

// ─── Graph self-tests ────────────────────────────────────────────────────────
//
// These exercise the live Microsoft Graph API with real credentials and real
// mutations, so they carry stricter guards than the EWS equivalents above.
//
// Rules, in order of importance:
//
//  1. Every run generates a fresh UUID marker. The EWS harness hard-codes one
//     (`EWS-MUTATE-TEST-7f3a9b`), which means a leftover message from an
//     earlier aborted run is indistinguishable from this run's.
//  2. Nothing is mutated unless its subject contains *this* run's marker and
//     it arrived after this process started. Pre-existing mail is never
//     touched under any circumstance.
//  3. More than one match aborts the run rather than guessing.
//
// Note there is deliberately no `--graph-cleanup` counterpart to
// `--ews-cleanup`: that one deletes every message matching a user-supplied
// substring, with no marker check and no age check.

/// A message this test run created, and is therefore allowed to mutate.
struct MarkedMessage {
    item_id: String,
    subject: String,
}

/// Find the message carrying this run's marker, refusing anything unsafe.
async fn find_marked_message(
    tm: &std::sync::Arc<oauth2::TokenManager>,
    account: &str,
    folder: &str,
    marker: &str,
    started_at: &str,
) -> Result<Option<MarkedMessage>, Box<dyn std::error::Error>> {
    let result = graph::find_messages(
        tm,
        account,
        graph::MessageSearch {
            folder: Some(folder),
            limit: 50,
            ..Default::default()
        },
    )
    .await?;

    let candidates: Vec<_> = result
        .messages
        .iter()
        .filter(|m| m.subject.contains(marker))
        .collect();

    if candidates.is_empty() {
        return Ok(None);
    }
    if candidates.len() > 1 {
        return Err(format!(
            "refusing to continue: {} messages match marker {marker}; expected exactly 1",
            candidates.len()
        )
        .into());
    }

    let hit = candidates[0];
    // Guard against a clock-skewed or recycled marker matching old mail.
    if !hit.date_received.is_empty() && hit.date_received.as_str() < started_at {
        return Err(format!(
            "refusing to touch message received {}, before this run started at {started_at}",
            hit.date_received
        )
        .into());
    }

    Ok(Some(MarkedMessage {
        item_id: hit.item_id.clone(),
        subject: hit.subject.clone(),
    }))
}

/// Delete every message carrying this run's marker, mailbox-wide.
///
/// Sending with `save_to_sent` leaves a copy in Sent Items as well as the one
/// delivered to the inbox, so deleting the delivered copy alone leaks one
/// message per run.
///
/// Each candidate is re-checked for the marker before deletion — the search
/// index decides what comes back, and this must never widen into "delete
/// whatever the query matched".
async fn cleanup_marked(
    tm: &std::sync::Arc<oauth2::TokenManager>,
    account: &str,
    marker: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    let found = graph::find_messages(
        tm,
        account,
        graph::MessageSearch {
            // Bare term: build_message_query supplies the surrounding quotes.
            query: Some(marker),
            limit: 50,
            ..Default::default()
        },
    )
    .await?;

    let mut deleted = 0;
    for msg in &found.messages {
        if !msg.subject.contains(marker) {
            continue;
        }
        graph::delete_message(tm, account, &msg.item_id, true).await?;
        deleted += 1;
    }
    Ok(deleted)
}

/// Re-assert ownership immediately before a mutating call.
fn assert_ours(msg: &MarkedMessage, marker: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !msg.subject.contains(marker) {
        return Err(format!(
            "refusing to mutate '{}': subject does not carry marker {marker}",
            msg.subject
        )
        .into());
    }
    Ok(())
}

async fn poll_for_marked(
    tm: &std::sync::Arc<oauth2::TokenManager>,
    account: &str,
    folder: &str,
    marker: &str,
    started_at: &str,
) -> Result<MarkedMessage, Box<dyn std::error::Error>> {
    use std::time::Duration;
    for attempt in 1..=20 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if let Some(found) = find_marked_message(tm, account, folder, marker, started_at).await? {
            println!("    found in {folder} after {attempt} tries.");
            return Ok(found);
        }
        println!("    not yet in {folder} (try {attempt})…");
    }
    Err(format!("test message never arrived in {folder}").into())
}

fn graph_tm_for(
    config: &ServerConfig,
    account: &str,
) -> Result<std::sync::Arc<oauth2::TokenManager>, Box<dyn std::error::Error>> {
    if !config.graph_oauth2_accounts.contains_key(account) {
        return Err(format!(
            "no Graph credentials for account '{account}'; set MAIL_GRAPH_{}_* (see mail-mcp-setup.py)",
            account.to_ascii_uppercase()
        )
        .into());
    }
    Ok(std::sync::Arc::new(oauth2::TokenManager::new(
        config.graph_oauth2_accounts.clone(),
    )))
}

/// Exercise the Graph search path, including the two behaviours that justify
/// the migration off EWS: Japanese compound matching, and date folding.
async fn selftest_graph_search(
    config: ServerConfig,
    account: &str,
    recipient: Option<&str>,
    pdf_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tm = graph_tm_for(&config, account)?;
    let started_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    // No hyphen in the marker: KQL treats a leading `-` on a term as NOT, so
    // `subject:GRAPHTEST-abc123` searches for GRAPHTEST while *excluding*
    // abc123 — which silently excludes the very message we just sent.
    let marker = format!(
        "GRAPHTEST{}",
        uuid::Uuid::new_v4().simple().to_string()[..8].to_ascii_uppercase()
    );

    let me = config
        .ews_accounts
        .get(account)
        .map(|a| a.user.clone())
        .or_else(|| config.accounts.get(account).map(|a| a.user.clone()))
        .ok_or_else(|| format!("cannot determine self address for '{account}'"))?;
    let to_addr = recipient.unwrap_or(&me).to_owned();

    // The Japanese compound is the point: EWS/AQS matched only dictionary word
    // tokens, so this exact term returned zero hits there.
    let subject = format!("{marker} 定期清掃 — automated test, safe to delete");
    println!("Run marker: {marker}");
    println!("Started at: {started_at}");
    println!("Sending to: {to_addr}");

    println!("\n[1] Sending test mail via Graph…");
    let mut attachments = Vec::new();
    if let Some(path) = pdf_path {
        let bytes = std::fs::read(path)?;
        attachments.push(graph::GraphEmailAttachment {
            filename: std::path::Path::new(path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "attachment.pdf".to_owned()),
            content_type: "application/pdf".to_owned(),
            content_base64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &bytes,
            ),
        });
        println!("    with attachment: {path} ({} bytes)", bytes.len());
    }
    graph::send_email(
        &tm,
        account,
        &graph::GraphEmailParams {
            to: vec![to_addr.clone()],
            cc: vec![],
            bcc: vec![],
            subject: subject.clone(),
            body_text: Some("Automated Graph self-test. Deletes itself.".to_owned()),
            body_html: None,
            reply_to: None,
            in_reply_to: None,
            references: None,
            save_to_sent: true,
            attachments,
        },
    )
    .await?;
    println!("    sent.");

    if recipient.is_some() {
        println!("\n    Cross-account send requested; the message lands in another mailbox.");
        println!("    Skipping search assertions here. Marker: {marker}");
        return Ok(());
    }

    println!("\n[2] Polling inbox for the message…");
    let found = poll_for_marked(&tm, account, "inbox", &marker, &started_at).await?;

    // Delivery and search indexing are separate: a message can be readable via
    // the inbox listing well before the search index knows about it, and how
    // long that takes varies by tenant. Poll rather than assert once.
    println!("\n[3] Searching by ASCII marker (waiting for the search index)…");
    let mut indexed = false;
    for attempt in 1..=20 {
        let by_marker = graph::find_messages(
            &tm,
            account,
            graph::MessageSearch {
                query: Some(&format!("subject:{marker}")),
                limit: 10,
                ..Default::default()
            },
        )
        .await?;
        if by_marker
            .messages
            .iter()
            .any(|m| m.subject.contains(&marker))
        {
            println!(
                "    indexed after {attempt} tries ({} hit(s)).",
                by_marker.messages.len()
            );
            indexed = true;
            break;
        }
        println!("    not indexed yet (try {attempt})…");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    assert!(indexed, "marker search never returned our message");

    // Multi-word Japanese compound search — the capability EWS/AQS lacked,
    // where these terms matched nothing at all.
    //
    // This asserts against the mailbox's existing corpus rather than the
    // message we just sent. Exchange's CJK word-breaker segments a term
    // according to its surrounding text, and a synthetic subject that mixes
    // ASCII and Japanese does not tokenize the same way real mail does: our
    // own test subject matches 定期 but not 清掃. Asserting on it would be
    // testing Microsoft's tokenizer, not this client, and would fail for
    // reasons no code change here could fix.
    println!("\n[4] Searching Japanese compounds (EWS/AQS returned 0 for these)…");
    let mut compound_hits = 0;
    for term in ["定期清掃", "自動ドア"] {
        let jp = graph::find_messages(
            &tm,
            account,
            graph::MessageSearch {
                query: Some(&format!("subject:{term}")),
                limit: 50,
                ..Default::default()
            },
        )
        .await?;
        println!("    subject:{term} → {} hit(s)", jp.messages.len());
        compound_hits += jp.messages.len();
    }
    assert!(
        compound_hits > 0,
        "no multi-word Japanese compound matched anything; KQL search may be broken \
         (this mailbox is expected to contain such mail)"
    );

    println!("\n[5] Verifying since/until folding (the $search + $filter workaround)…");
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let tomorrow = (chrono::Utc::now() + chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();

    let since_today = graph::find_messages(
        &tm,
        account,
        graph::MessageSearch {
            query: Some(&format!("subject:{marker}")),
            since: Some(&today),
            limit: 10,
            ..Default::default()
        },
    )
    .await?;
    assert!(
        since_today
            .messages
            .iter()
            .any(|m| m.subject.contains(&marker)),
        "since=today should still match a message sent today"
    );
    println!("    since=today  → {} hit(s) ✓", since_today.messages.len());

    let since_tomorrow = graph::find_messages(
        &tm,
        account,
        graph::MessageSearch {
            query: Some(&format!("subject:{marker}")),
            since: Some(&tomorrow),
            limit: 10,
            ..Default::default()
        },
    )
    .await?;
    assert!(
        !since_tomorrow
            .messages
            .iter()
            .any(|m| m.subject.contains(&marker)),
        "since=tomorrow must exclude a message sent today — date folding is broken"
    );
    println!("    since=tomorrow → excluded ✓");

    println!("\n[6] Reading the body as text (no HTML opt-in needed)…");
    let detail = graph::get_message(&tm, account, &found.item_id, graph::BodyFormat::Text).await?;
    println!(
        "    body_text present: {}, html: {}",
        detail.body_text.is_some(),
        detail.body_html.is_some()
    );
    assert!(detail.body_text.is_some(), "text body should be populated");

    if pdf_path.is_some() {
        println!("\n[7] Extracting attachment text…");
        let atts = graph::get_attachments(&tm, account, &found.item_id, true, 10_000).await?;
        for a in &atts {
            println!(
                "    {} ({} bytes, {}), extracted {} chars",
                a.name,
                a.size_bytes,
                a.content_type,
                a.extracted_text.as_deref().map(str::len).unwrap_or(0)
            );
        }
        assert!(!atts.is_empty(), "expected at least one attachment");
    }

    println!("\n[8] Cleaning up (hard delete of every copy we created)…");
    assert_ours(&found, &marker)?;
    graph::delete_message(&tm, account, &found.item_id, true).await?;
    let extra = cleanup_marked(&tm, account, &marker).await?;
    println!("    deleted inbox copy + {extra} other copy/copies (e.g. Sent Items).");

    println!("\n✅ selftest-graph-search passed.");
    Ok(())
}

/// Exercise the Graph mutation path: set_read, move, hard delete.
async fn selftest_graph_mutate(
    config: ServerConfig,
    account: &str,
    move_folder: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let tm = graph_tm_for(&config, account)?;
    let started_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    // No hyphen in the marker: KQL treats a leading `-` on a term as NOT, so
    // `subject:GRAPHTEST-abc123` searches for GRAPHTEST while *excluding*
    // abc123 — which silently excludes the very message we just sent.
    let marker = format!(
        "GRAPHTEST{}",
        uuid::Uuid::new_v4().simple().to_string()[..8].to_ascii_uppercase()
    );

    let me = config
        .ews_accounts
        .get(account)
        .map(|a| a.user.clone())
        .or_else(|| config.accounts.get(account).map(|a| a.user.clone()))
        .ok_or_else(|| format!("cannot determine self address for '{account}'"))?;

    let subject = format!("{marker} — automated test, safe to delete");
    println!("Run marker: {marker}");
    println!("Self address: {me}");
    println!("Move target: {move_folder}");

    println!("\n[1] Sending test mail to self via Graph…");
    graph::send_email(
        &tm,
        account,
        &graph::GraphEmailParams {
            to: vec![me.clone()],
            cc: vec![],
            bcc: vec![],
            subject: subject.clone(),
            body_text: Some("Automated Graph mutate test. Deletes itself.".to_owned()),
            body_html: None,
            reply_to: None,
            in_reply_to: None,
            references: None,
            save_to_sent: true,
            attachments: vec![],
        },
    )
    .await?;
    println!("    sent.");

    println!("\n[2] Polling inbox…");
    let found = poll_for_marked(&tm, account, "inbox", &marker, &started_at).await?;

    println!("\n[3] Marking read…");
    assert_ours(&found, &marker)?;
    graph::set_read(&tm, account, &found.item_id, true).await?;
    let after = graph::get_message(&tm, account, &found.item_id, graph::BodyFormat::Text).await?;
    println!("    is_read now = {}", after.is_read);
    assert!(after.is_read, "set_read(true) did not stick");

    println!("\n[4] Moving to {move_folder}…");
    assert_ours(&found, &marker)?;
    let new_id = graph::move_message(&tm, account, &found.item_id, move_folder).await?;
    println!("    new item id: {}…", &new_id[..new_id.len().min(24)]);
    assert_ne!(new_id, found.item_id, "move should re-issue the id");

    let moved = graph::get_message(&tm, account, &new_id, graph::BodyFormat::Text).await?;
    assert!(
        moved.subject.contains(&marker),
        "new id resolved to the wrong message"
    );
    println!("    new id resolves to our message ✓");

    let still_inbox = find_marked_message(&tm, account, "inbox", &marker, &started_at).await?;
    assert!(still_inbox.is_none(), "message should have left the inbox");
    println!("    gone from inbox ✓");

    println!("\n[5] Hard delete (permanentDelete)…");
    let moved_msg = MarkedMessage {
        item_id: new_id.clone(),
        subject: moved.subject.clone(),
    };
    assert_ours(&moved_msg, &marker)?;
    graph::delete_message(&tm, account, &new_id, true).await?;
    println!("    deleted.");

    let gone = graph::get_message(&tm, account, &new_id, graph::BodyFormat::Text).await;
    assert!(gone.is_err(), "message should no longer be retrievable");
    println!("    confirmed unretrievable ✓");

    println!("\n[6] Removing remaining copies (Sent Items)…");
    let extra = cleanup_marked(&tm, account, &marker).await?;
    println!("    deleted {extra} additional copy/copies.");

    println!("\n✅ selftest-graph-mutate passed.");
    Ok(())
}

fn should_print_help<I>(args: I) -> bool
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    args.into_iter().any(|arg| {
        let arg = arg.as_ref();
        arg == "--help" || arg == "-h"
    })
}

fn print_help_output() -> io::Result<()> {
    let env_map: BTreeMap<String, String> = std::env::vars().collect();
    let output = build_help_output(&env_map);
    let mut stdout = io::stdout().lock();
    stdout.write_all(output.as_bytes())?;
    stdout.flush()
}

fn build_help_output(env_map: &BTreeMap<String, String>) -> String {
    let account_sections = discover_account_sections(env_map);
    let mut out = String::new();

    out.push_str("mail-mcp\n");
    out.push_str("Secure IMAP MCP server over stdio\n\n");

    out.push_str("Usage:\n");
    out.push_str("  mail-mcp\n");
    out.push_str("  mail-mcp --help\n\n");

    out.push_str("IMAP environment setup\n");
    out.push_str("  Required per account section MAIL_IMAP_<ACCOUNT>_:\n");
    out.push_str("    MAIL_IMAP_<ACCOUNT>_HOST\n");
    out.push_str("    MAIL_IMAP_<ACCOUNT>_USER\n");
    out.push_str("    MAIL_IMAP_<ACCOUNT>_PASS\n");
    out.push_str("  Optional per account section:\n");
    out.push_str("    MAIL_IMAP_<ACCOUNT>_PORT (default: 993)\n");
    out.push_str("    MAIL_IMAP_<ACCOUNT>_SECURE (default: true)\n");
    out.push_str(
        "  If no account section is discovered from environment, DEFAULT is used by convention.\n\n",
    );

    out.push_str("Discovered account sections (from current environment)\n");
    if account_sections.is_empty() {
        out.push_str("  (none discovered)\n");
    } else {
        for section in &account_sections {
            out.push_str(&format!("  [{}]\n", section));
            for suffix in ["HOST", "USER", "PASS", "PORT", "SECURE"] {
                let key = format!("MAIL_IMAP_{}_{}", section, suffix);
                let value = env_map.get(&key).map(String::as_str);
                out.push_str(&format!("    {}={}\n", key, redact_value(&key, value)));
            }
        }
    }
    out.push('\n');

    // OAuth2 section
    let oauth2_sections = discover_oauth2_sections(env_map);
    out.push_str("OAuth2 environment setup (optional, per account)\n");
    out.push_str("  MAIL_OAUTH2_<ACCOUNT>_PROVIDER    (google | microsoft)\n");
    out.push_str("  MAIL_OAUTH2_<ACCOUNT>_CLIENT_ID\n");
    out.push_str("  MAIL_OAUTH2_<ACCOUNT>_CLIENT_SECRET\n");
    out.push_str("  MAIL_OAUTH2_<ACCOUNT>_REFRESH_TOKEN\n");
    out.push_str(
        "  When set, IMAP PASS becomes optional and XOAUTH2 is used for authentication.\n\n",
    );

    out.push_str("Discovered OAuth2 sections (from current environment)\n");
    if oauth2_sections.is_empty() {
        out.push_str("  (none discovered)\n");
    } else {
        for section in &oauth2_sections {
            out.push_str(&format!("  [{}]\n", section));
            for suffix in ["PROVIDER", "CLIENT_ID", "CLIENT_SECRET", "REFRESH_TOKEN"] {
                let key = format!("MAIL_OAUTH2_{}_{}", section, suffix);
                let value = env_map.get(&key).map(String::as_str);
                out.push_str(&format!("    {}={}\n", key, redact_value(&key, value)));
            }
        }
    }
    out.push('\n');

    // SMTP section
    let smtp_sections = discover_smtp_sections(env_map);
    out.push_str("SMTP environment setup (optional, per account)\n");
    out.push_str("  MAIL_SMTP_<ACCOUNT>_HOST\n");
    out.push_str("  MAIL_SMTP_<ACCOUNT>_PORT       (default: 587)\n");
    out.push_str("  MAIL_SMTP_<ACCOUNT>_USER\n");
    out.push_str("  MAIL_SMTP_<ACCOUNT>_PASS       (optional if OAuth2 configured)\n");
    out.push_str(
        "  MAIL_SMTP_<ACCOUNT>_SECURE     (starttls | tls | plain, default: starttls)\n\n",
    );

    out.push_str("Discovered SMTP sections (from current environment)\n");
    if smtp_sections.is_empty() {
        out.push_str("  (none discovered)\n");
    } else {
        for section in &smtp_sections {
            out.push_str(&format!("  [{}]\n", section));
            for suffix in ["HOST", "PORT", "USER", "PASS", "SECURE"] {
                let key = format!("MAIL_SMTP_{}_{}", section, suffix);
                let value = env_map.get(&key).map(String::as_str);
                out.push_str(&format!("    {}={}\n", key, redact_value(&key, value)));
            }
        }
    }
    out.push('\n');

    out.push_str("Global policy defaults\n");
    out.push_str("  MAIL_IMAP_WRITE_ENABLED=false\n");
    out.push_str("  MAIL_IMAP_CONNECT_TIMEOUT_MS=30000\n");
    out.push_str("  MAIL_IMAP_GREETING_TIMEOUT_MS=15000\n");
    out.push_str("  MAIL_IMAP_SOCKET_TIMEOUT_MS=300000\n");
    out.push_str("  MAIL_IMAP_CURSOR_TTL_SECONDS=600\n");
    out.push_str("  MAIL_IMAP_CURSOR_MAX_ENTRIES=512\n");
    out.push_str("  MAIL_SMTP_WRITE_ENABLED=false\n");
    out.push_str("  MAIL_SMTP_SAVE_SENT=true\n");
    out.push_str("  MAIL_SMTP_CONNECT_TIMEOUT_MS=30000\n");
    out.push_str("  MAIL_SMTP_SEND_TIMEOUT_MS=300000\n");
    out.push_str("  # MAIL_SMTP_TIMEOUT_MS (deprecated; use MAIL_SMTP_SEND_TIMEOUT_MS)\n");
    out.push_str("  MAIL_EWS_ENABLED=false\n\n");

    out.push_str("Send/write gate policy\n");
    out.push_str("  IMAP write tools are blocked unless MAIL_IMAP_WRITE_ENABLED=true.\n");
    out.push_str("  SMTP send tools are blocked unless MAIL_SMTP_WRITE_ENABLED=true.\n");
    out.push_str("  Graph mutations follow MAIL_IMAP_WRITE_ENABLED; graph_send_message\n");
    out.push_str("  follows MAIL_SMTP_WRITE_ENABLED.\n");
    out.push_str("  These gates protect against accidental mutations and sending.\n\n");

    out.push_str("Protocol policy\n");
    out.push_str("  Microsoft Graph (graph_* tools) is the default for Microsoft accounts.\n");
    out.push_str("  The legacy ews_* tools are only registered when MAIL_EWS_ENABLED=true;\n");
    out.push_str("  Microsoft disables EWS by default in Oct 2026 and removes it Apr 2027.\n");

    out
}

fn discover_account_sections(env_map: &BTreeMap<String, String>) -> Vec<String> {
    let mut sections: Vec<String> = env_map
        .keys()
        .filter_map(|key| {
            let remainder = key.strip_prefix("MAIL_IMAP_")?;
            for suffix in ["_HOST", "_USER", "_PASS", "_PORT", "_SECURE"] {
                if let Some(section) = remainder.strip_suffix(suffix)
                    && !section.is_empty()
                {
                    return Some(section.to_owned());
                }
            }
            None
        })
        .collect();

    sections.sort();
    sections.dedup();
    sections
}

fn discover_oauth2_sections(env_map: &BTreeMap<String, String>) -> Vec<String> {
    let mut sections: Vec<String> = env_map
        .keys()
        .filter_map(|key| {
            let remainder = key.strip_prefix("MAIL_OAUTH2_")?;
            for suffix in [
                "_PROVIDER",
                "_CLIENT_ID",
                "_CLIENT_SECRET",
                "_REFRESH_TOKEN",
            ] {
                if let Some(section) = remainder.strip_suffix(suffix)
                    && !section.is_empty()
                {
                    return Some(section.to_owned());
                }
            }
            None
        })
        .collect();

    sections.sort();
    sections.dedup();
    sections
}

fn discover_smtp_sections(env_map: &BTreeMap<String, String>) -> Vec<String> {
    let mut sections: Vec<String> = env_map
        .keys()
        .filter_map(|key| {
            let remainder = key.strip_prefix("MAIL_SMTP_")?;
            for suffix in ["_HOST", "_PORT", "_USER", "_PASS", "_SECURE"] {
                if let Some(section) = remainder.strip_suffix(suffix)
                    && !section.is_empty()
                {
                    return Some(section.to_owned());
                }
            }
            None
        })
        .collect();

    sections.sort();
    sections.dedup();
    sections
}

fn redact_value(key: &str, value: Option<&str>) -> String {
    match value {
        Some(v) if is_secret_key(key) && !v.is_empty() => "<redacted>".to_owned(),
        Some("") => "<empty>".to_owned(),
        Some(v) => v.to_owned(),
        None => "<unset>".to_owned(),
    }
}

fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    key.contains("PASS") || key.contains("SECRET") || key.contains("TOKEN")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        build_help_output, discover_account_sections, is_secret_key, redact_value,
        should_print_help,
    };

    #[test]
    fn detects_short_and_long_help_flags() {
        assert!(should_print_help(["-h"]));
        assert!(should_print_help(["--help"]));
        assert!(should_print_help(["--verbose", "-h"]));
        assert!(!should_print_help(["--verbose"]));
    }

    #[test]
    fn discovers_account_sections_from_env_like_keys() {
        let mut env_map = BTreeMap::new();
        env_map.insert(
            "MAIL_IMAP_DEFAULT_HOST".to_owned(),
            "imap.example.com".to_owned(),
        );
        env_map.insert(
            "MAIL_IMAP_WORK_USER".to_owned(),
            "work@example.com".to_owned(),
        );
        env_map.insert("MAIL_IMAP_WORK_PASS".to_owned(), "secret".to_owned());
        env_map.insert("MAIL_IMAP_WRITE_ENABLED".to_owned(), "true".to_owned());

        assert_eq!(
            discover_account_sections(&env_map),
            vec!["DEFAULT".to_owned(), "WORK".to_owned()]
        );
    }

    #[test]
    fn redacts_secret_values_and_marks_unset() {
        assert_eq!(
            redact_value("MAIL_IMAP_DEFAULT_PASS", Some("abc")),
            "<redacted>"
        );
        assert_eq!(redact_value("MAIL_IMAP_DEFAULT_HOST", Some("imap")), "imap");
        assert_eq!(redact_value("MAIL_IMAP_DEFAULT_USER", None), "<unset>");
    }

    #[test]
    fn detects_secret_keys_case_insensitively() {
        assert!(is_secret_key("mail_imap_default_pass"));
        assert!(is_secret_key("MAIL_IMAP_API_TOKEN"));
        assert!(!is_secret_key("MAIL_IMAP_DEFAULT_HOST"));
    }

    #[test]
    fn help_output_includes_policy_defaults_and_redaction() {
        let mut env_map = BTreeMap::new();
        env_map.insert(
            "MAIL_IMAP_DEFAULT_HOST".to_owned(),
            "imap.example.com".to_owned(),
        );
        env_map.insert(
            "MAIL_IMAP_DEFAULT_USER".to_owned(),
            "user@example.com".to_owned(),
        );
        env_map.insert("MAIL_IMAP_DEFAULT_PASS".to_owned(), "top-secret".to_owned());

        let help = build_help_output(&env_map);
        assert!(help.contains("Global policy defaults"));
        assert!(help.contains("MAIL_IMAP_WRITE_ENABLED=false"));
        assert!(help.contains("Send/write gate policy"));
        assert!(help.contains("MAIL_IMAP_DEFAULT_PASS=<redacted>"));
    }
}
