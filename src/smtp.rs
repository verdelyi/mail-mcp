//! SMTP transport for sending emails
//!
//! Provides async SMTP sending via `lettre`, supporting both password and
//! OAuth2 (XOAUTH2) authentication. Connections use STARTTLS or direct TLS
//! with `rustls` to match the project's existing TLS stack.
//!
//! # Configuration
//!
//! Per-account SMTP settings are loaded from environment variables:
//! ```text
//! MAIL_SMTP_<SEGMENT>_HOST=smtp.gmail.com
//! MAIL_SMTP_<SEGMENT>_PORT=587
//! MAIL_SMTP_<SEGMENT>_USER=user@gmail.com
//! MAIL_SMTP_<SEGMENT>_PASS=app-password
//! MAIL_SMTP_<SEGMENT>_SECURE=starttls
//! ```

use std::time::Duration;

use lettre::address::Envelope;
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, MessageBuilder, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use secrecy::{ExposeSecret, SecretString};

use crate::config::AuthMethod;
use crate::errors::{AppError, AppResult};
use crate::oauth2::TokenManager;

// ─── SMTP account config ────────────────────────────────────────────────────

/// SMTP connection security mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// Direct TLS connection (typically port 465)
    Tls,
    /// STARTTLS upgrade after plaintext connection (typically port 587)
    Starttls,
    /// Plaintext connection (only for trusted local networks)
    Plain,
}

impl SmtpSecurity {
    /// Parse security mode from configuration value
    pub fn parse(value: &str) -> AppResult<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tls" | "ssl" => Ok(Self::Tls),
            "starttls" => Ok(Self::Starttls),
            "plain" | "none" => Ok(Self::Plain),
            other => Err(AppError::InvalidInput(format!(
                "unsupported SMTP security mode '{other}'; expected 'tls', 'starttls', or 'plain'"
            ))),
        }
    }
}

/// SMTP account configuration
#[derive(Debug, Clone)]
pub struct SmtpAccountConfig {
    /// Account identifier (matches IMAP account_id)
    pub account_id: String,
    /// SMTP server hostname
    pub host: String,
    /// SMTP server port
    pub port: u16,
    /// SMTP username
    pub user: String,
    /// SMTP password (optional when OAuth2 is used)
    pub pass: Option<SecretString>,
    /// Connection security mode
    pub security: SmtpSecurity,
    /// Authentication method
    pub auth_method: AuthMethod,
    /// Per-account override for saving sent mail to the IMAP Sent folder.
    ///
    /// `None` = not set for this account; the effective value falls back to
    /// the global `MAIL_SMTP_SAVE_SENT`, and if that is also unset, to a
    /// provider-aware default (see `ServerConfig::should_save_sent`).
    /// `Some(true/false)` = explicit per-account choice via
    /// `MAIL_SMTP_<ID>_SAVE_SENT`.
    pub save_sent: Option<bool>,
    /// From (sender) email address, independent of `user` (SMTP auth username).
    ///
    /// `None` = not set; the From address falls back to `user`.
    /// `Some(addr)` = use `addr` as the From/Reply-to-self address instead of
    /// `user`. Set via `MAIL_SMTP_<ID>_FROM_EMAIL`. Needed when the SMTP auth
    /// username differs from the desired sender address (e.g. shared/group
    /// mailboxes where auth uses a personal account but the From should be
    /// the group address).
    pub from_email: Option<String>,
}

impl SmtpAccountConfig {
    /// Effective From (sender) / Reply-to-self address.
    ///
    /// Returns `from_email` when set, otherwise falls back to `user` (the
    /// SMTP auth username). Centralises the fallback that was previously
    /// repeated at every call site (send, reply, reply-all, forward).
    pub fn effective_from(&self) -> &str {
        self.from_email.as_deref().unwrap_or(&self.user)
    }
}

// ─── Email composition ───────────────────────────────────────────────────────

/// A file attachment for an email
pub struct EmailAttachment {
    pub filename: String,
    pub content_type: String,
    pub content: Vec<u8>,
}

/// Parameters for composing and sending an email
pub struct EmailComposition {
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub reply_to: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    pub attachments: Vec<EmailAttachment>,
}

// ─── Send email ──────────────────────────────────────────────────────────────

/// Result of a successful SMTP send.
///
/// `rfc822` contains the exact bytes that went over the wire — suitable for
/// `IMAP APPEND` to the Sent folder. This guarantees the archived copy is
/// byte-identical to what the recipient received (same Message-ID, Date,
/// MIME structure, boundaries, encoded headers, attachments).
pub struct SentMessage {
    pub message_id: String,
    pub rfc822: Vec<u8>,
}

/// Send an email via SMTP.
///
/// Builds the MIME message and sends it through the configured SMTP transport.
/// Supports both password and OAuth2 authentication.
///
/// Returns the generated Message-ID plus the full serialized RFC822 bytes so
/// the caller can archive the exact message that was sent (e.g., via IMAP
/// APPEND to a Sent folder).
///
/// # Errors
///
/// - `InvalidInput` if email addresses are malformed
/// - `AuthFailed` if SMTP authentication fails
/// - `Timeout` if connection or sending times out
/// - `Internal` for other SMTP errors
pub async fn send_email(
    smtp_config: &SmtpAccountConfig,
    token_manager: Option<&TokenManager>,
    connect_timeout_ms: u64,
    send_timeout_ms: u64,
    composition: &EmailComposition,
) -> AppResult<SentMessage> {
    let message = build_message(composition, false)?;
    let message_id = message
        .headers()
        .get_raw("Message-ID")
        .unwrap_or_default()
        .to_owned();
    // Serialize BEFORE sending so we can archive the exact bytes even though
    // `transport.send(message)` consumes the Message by value.
    let rfc822 = message.formatted();

    let transport = build_transport(smtp_config, token_manager, connect_timeout_ms).await?;

    tokio::time::timeout(
        Duration::from_millis(send_timeout_ms),
        transport.send(message),
    )
    .await
    .map_err(|_| AppError::Timeout("SMTP send timed out".to_owned()))
    .and_then(|r| r.map_err(map_send_error))?;

    Ok(SentMessage { message_id, rfc822 })
}

/// Serialize a composition as a draft: same MIME layout as a sent message,
/// but the `Bcc` header is kept so the draft still carries its blind
/// recipients when it is sent later.
pub fn render_draft(composition: &EmailComposition) -> AppResult<SentMessage> {
    let message = build_message(composition, true)?;
    let message_id = message
        .headers()
        .get_raw("Message-ID")
        .unwrap_or_default()
        .to_owned();
    Ok(SentMessage {
        message_id,
        rfc822: message.formatted(),
    })
}

/// Send already-serialized RFC822 bytes with an explicit SMTP envelope.
///
/// Used to send a stored draft byte-for-byte. The caller is responsible for
/// stripping the `Bcc` header from `rfc822`; the blind recipients travel in
/// `recipients` only.
pub async fn send_raw_email(
    smtp_config: &SmtpAccountConfig,
    token_manager: Option<&TokenManager>,
    connect_timeout_ms: u64,
    send_timeout_ms: u64,
    envelope_from: &str,
    recipients: &[String],
    rfc822: &[u8],
) -> AppResult<()> {
    let from: Address = envelope_from.parse().map_err(|e| {
        AppError::InvalidInput(format!("invalid envelope sender '{envelope_from}': {e}"))
    })?;
    let to = recipients
        .iter()
        .map(|addr| {
            addr.parse::<Address>().map_err(|e| {
                AppError::InvalidInput(format!("invalid recipient address '{addr}': {e}"))
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    let envelope = Envelope::new(Some(from), to)
        .map_err(|e| AppError::InvalidInput(format!("invalid SMTP envelope: {e}")))?;

    let transport = build_transport(smtp_config, token_manager, connect_timeout_ms).await?;

    tokio::time::timeout(
        Duration::from_millis(send_timeout_ms),
        transport.send_raw(&envelope, rfc822),
    )
    .await
    .map_err(|_| AppError::Timeout("SMTP send timed out".to_owned()))
    .and_then(|r| r.map_err(map_send_error))?;

    Ok(())
}

/// Classify an SMTP send failure as an auth error or an internal error.
fn map_send_error(error: lettre::transport::smtp::Error) -> AppError {
    let msg = error.to_string();
    if msg.to_ascii_lowercase().contains("auth") || msg.contains("535") || msg.contains("534") {
        AppError::AuthFailed(format!("SMTP authentication failed: {msg}"))
    } else {
        AppError::Internal(format!("SMTP send failed: {msg}"))
    }
}

/// Verify SMTP connectivity and authentication.
///
/// Attempts to connect and authenticate without sending any email.
pub async fn verify_smtp(
    smtp_config: &SmtpAccountConfig,
    token_manager: Option<&TokenManager>,
    connect_timeout_ms: u64,
) -> AppResult<()> {
    let transport = build_transport(smtp_config, token_manager, connect_timeout_ms).await?;

    tokio::time::timeout(
        Duration::from_millis(connect_timeout_ms),
        transport.test_connection(),
    )
    .await
    .map_err(|_| AppError::Timeout("SMTP connection test timed out".to_owned()))
    .and_then(|r| {
        r.map_err(|e| {
            let msg = e.to_string();
            if msg.to_ascii_lowercase().contains("auth") {
                AppError::AuthFailed(format!("SMTP authentication failed: {msg}"))
            } else {
                AppError::Internal(format!("SMTP connection test failed: {msg}"))
            }
        })
    })?;

    Ok(())
}

// ─── Internals ───────────────────────────────────────────────────────────────

/// Build a lettre Message from composition parameters.
///
/// `keep_bcc` keeps the `Bcc` header in the serialized message (drafts);
/// sent messages drop it so blind recipients stay hidden.
fn build_message(comp: &EmailComposition, keep_bcc: bool) -> AppResult<Message> {
    let from_mailbox: Mailbox = comp.from.parse().map_err(|e| {
        AppError::InvalidInput(format!("invalid From address '{}': {e}", comp.from))
    })?;

    let message_id = generate_message_id(from_mailbox.email.as_ref());
    let mut builder: MessageBuilder = Message::builder()
        .from(from_mailbox)
        .message_id(Some(message_id));
    if keep_bcc {
        builder = builder.keep_bcc();
    }

    for addr in &comp.to {
        let mb: Mailbox = addr
            .parse()
            .map_err(|e| AppError::InvalidInput(format!("invalid To address '{addr}': {e}")))?;
        builder = builder.to(mb);
    }

    for addr in &comp.cc {
        let mb: Mailbox = addr
            .parse()
            .map_err(|e| AppError::InvalidInput(format!("invalid Cc address '{addr}': {e}")))?;
        builder = builder.cc(mb);
    }

    for addr in &comp.bcc {
        let mb: Mailbox = addr
            .parse()
            .map_err(|e| AppError::InvalidInput(format!("invalid Bcc address '{addr}': {e}")))?;
        builder = builder.bcc(mb);
    }

    builder = builder.subject(&comp.subject);

    if let Some(ref reply_to) = comp.reply_to {
        let mb: Mailbox = reply_to.parse().map_err(|e| {
            AppError::InvalidInput(format!("invalid Reply-To address '{reply_to}': {e}"))
        })?;
        builder = builder.reply_to(mb);
    }

    if let Some(ref in_reply_to) = comp.in_reply_to {
        builder = builder.in_reply_to(in_reply_to.clone());
    }

    if let Some(ref references) = comp.references {
        builder = builder.references(references.clone());
    }

    // Sanitize CDATA artifacts from body text (Zoho bug: ]]> leaks into plain text)
    let body_text = comp.body_text.as_ref().map(|t| sanitize_cdata(t));
    let body_html = comp.body_html.as_ref().map(|h| sanitize_cdata(h));

    // Build body part
    let body_part = match (&body_text, &body_html) {
        (Some(text), Some(html)) => MultiPart::alternative()
            .singlepart(
                SinglePart::builder()
                    .content_type(ContentType::TEXT_PLAIN)
                    .body(text.clone()),
            )
            .singlepart(
                SinglePart::builder()
                    .content_type(ContentType::TEXT_HTML)
                    .body(html.clone()),
            ),
        (Some(text), None) => MultiPart::alternative().singlepart(
            SinglePart::builder()
                .content_type(ContentType::TEXT_PLAIN)
                .body(text.clone()),
        ),
        (None, Some(html)) => MultiPart::alternative().singlepart(
            SinglePart::builder()
                .content_type(ContentType::TEXT_HTML)
                .body(html.clone()),
        ),
        (None, None) => MultiPart::alternative().singlepart(
            SinglePart::builder()
                .content_type(ContentType::TEXT_PLAIN)
                .body(String::new()),
        ),
    };

    // If attachments, wrap in multipart/mixed; otherwise just use body
    let message = if comp.attachments.is_empty() {
        builder
            .multipart(body_part)
            .map_err(|e| AppError::Internal(format!("failed to build message: {e}")))?
    } else {
        let mut mixed = MultiPart::mixed().multipart(body_part);
        for att in &comp.attachments {
            let ct: ContentType = att
                .content_type
                .parse()
                .unwrap_or(ContentType::parse("application/octet-stream").unwrap());
            mixed = mixed.singlepart(
                lettre::message::Attachment::new(att.filename.clone())
                    .body(att.content.clone(), ct),
            );
        }
        builder.multipart(mixed).map_err(|e| {
            AppError::Internal(format!("failed to build message with attachments: {e}"))
        })?
    };

    Ok(message)
}

/// Build the async SMTP transport with appropriate auth and security.
///
/// `connect_timeout_ms` bounds the TCP/TLS/auth phase via lettre's internal
/// I/O timeout. The DATA transmission timeout is enforced separately by the
/// caller via `tokio::time::timeout`.
async fn build_transport(
    config: &SmtpAccountConfig,
    token_manager: Option<&TokenManager>,
    connect_timeout_ms: u64,
) -> AppResult<AsyncSmtpTransport<Tokio1Executor>> {
    let timeout_duration = Duration::from_millis(connect_timeout_ms);

    let mut builder = match config.security {
        SmtpSecurity::Starttls => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .map_err(|e| AppError::Internal(format!("SMTP STARTTLS relay error: {e}")))?
        }
        SmtpSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
            .map_err(|e| AppError::Internal(format!("SMTP TLS relay error: {e}")))?,
        SmtpSecurity::Plain => {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
        }
    };

    builder = builder.port(config.port).timeout(Some(timeout_duration));

    // Set up authentication
    match config.auth_method {
        AuthMethod::OAuth2 => {
            let tm = token_manager.ok_or_else(|| {
                AppError::Internal(format!(
                    "SMTP account '{}' requires OAuth2 but no token manager available",
                    config.account_id
                ))
            })?;
            let access_token = tm.get_access_token(&config.account_id).await?;
            // For XOAUTH2, lettre builds the SASL string internally from
            // Credentials(user, access_token) when using Mechanism::Xoauth2
            let credentials = Credentials::new(config.user.clone(), access_token);
            builder = builder
                .credentials(credentials)
                .authentication(vec![Mechanism::Xoauth2]);
        }
        AuthMethod::Password => {
            if let Some(ref pass) = config.pass {
                let credentials =
                    Credentials::new(config.user.clone(), pass.expose_secret().to_owned());
                builder = builder.credentials(credentials);
            }
        }
    }

    Ok(builder.build())
}

/// Build an RFC 5322 Message-ID on the sender's domain.
///
/// lettre only adds a Message-ID when asked to, and its default uses the
/// local hostname. Setting it here means the id returned to the caller, the
/// copy archived in Sent and the message the recipient gets all agree, and
/// drafts can be found again by it.
fn generate_message_id(from_address: &str) -> String {
    let domain = from_address
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .filter(|domain| !domain.is_empty())
        .unwrap_or("localhost");
    format!("<{}@{domain}>", uuid::Uuid::new_v4().simple())
}

/// Remove CDATA artifacts (]]>) that some email clients (notably Zoho)
/// leak into plain text when converting from HTML templates.
fn sanitize_cdata(text: &str) -> String {
    text.replace("]]>", "").replace("<![CDATA[", "")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_security_parse_accepts_valid_values() {
        assert_eq!(SmtpSecurity::parse("tls").unwrap(), SmtpSecurity::Tls);
        assert_eq!(SmtpSecurity::parse("ssl").unwrap(), SmtpSecurity::Tls);
        assert_eq!(
            SmtpSecurity::parse("STARTTLS").unwrap(),
            SmtpSecurity::Starttls
        );
        assert_eq!(SmtpSecurity::parse("plain").unwrap(), SmtpSecurity::Plain);
        assert_eq!(SmtpSecurity::parse("none").unwrap(), SmtpSecurity::Plain);
    }

    #[test]
    fn smtp_security_parse_rejects_invalid() {
        assert!(SmtpSecurity::parse("invalid").is_err());
    }

    #[test]
    fn build_message_sets_message_id_on_sender_domain() {
        let comp = EmailComposition {
            from: "Me <me@example.org>".to_owned(),
            to: vec!["a@example.com".to_owned()],
            cc: vec![],
            bcc: vec!["hidden@example.com".to_owned()],
            subject: "Hi".to_owned(),
            body_text: Some("Body".to_owned()),
            body_html: None,
            reply_to: None,
            in_reply_to: None,
            references: None,
            attachments: vec![],
        };
        let sent = build_message(&comp, false).unwrap();
        let id = sent.headers().get_raw("Message-ID").unwrap().to_owned();
        assert!(id.starts_with('<') && id.ends_with("@example.org>"), "{id}");
        let sent_text = String::from_utf8(sent.formatted()).unwrap();
        assert!(sent_text.contains(&id), "{sent_text}");
        assert!(!sent_text.contains("hidden@example.com"), "{sent_text}");

        let draft = render_draft(&comp).unwrap();
        let draft_text = String::from_utf8(draft.rfc822).unwrap();
        assert!(draft_text.contains(&draft.message_id), "{draft_text}");
        assert!(draft_text.contains("hidden@example.com"), "{draft_text}");
    }

    #[test]
    fn build_message_text_only() {
        let comp = EmailComposition {
            from: "sender@example.com".to_owned(),
            to: vec!["recipient@example.com".to_owned()],
            cc: vec![],
            bcc: vec![],
            subject: "Test subject".to_owned(),
            body_text: Some("Hello, world!".to_owned()),
            body_html: None,
            reply_to: None,
            in_reply_to: None,
            references: None,
            attachments: vec![],
        };
        let msg = build_message(&comp, false).unwrap();
        let binding = msg.formatted();
        let formatted = String::from_utf8_lossy(&binding);
        assert!(formatted.contains("Subject: Test subject"));
        assert!(formatted.contains("Hello, world!"));
    }

    #[test]
    fn build_message_multipart() {
        let comp = EmailComposition {
            from: "sender@example.com".to_owned(),
            to: vec!["recipient@example.com".to_owned()],
            cc: vec![],
            bcc: vec![],
            subject: "Multipart test".to_owned(),
            body_text: Some("Plain text".to_owned()),
            body_html: Some("<p>HTML text</p>".to_owned()),
            reply_to: None,
            in_reply_to: None,
            references: None,
            attachments: vec![],
        };
        let msg = build_message(&comp, false).unwrap();
        let binding = msg.formatted();
        let formatted = String::from_utf8_lossy(&binding);
        assert!(formatted.contains("multipart/alternative"));
        assert!(formatted.contains("Plain text"));
        assert!(formatted.contains("<p>HTML text</p>"));
    }

    #[test]
    fn formatted_bytes_are_suitable_for_imap_append() {
        // Regression: previously save_to_sent_folder hand-rolled a minimal
        // RFC822 that lacked MIME headers, dropped the HTML body and left
        // non-ASCII headers un-encoded. The fix serializes the real lettre
        // Message and APPENDs those bytes. This verifies the serialization
        // is usable.
        let comp = EmailComposition {
            from: "sender@example.com".to_owned(),
            to: vec!["recipient@example.com".to_owned()],
            cc: vec![],
            bcc: vec![],
            subject: "Asunto con acentos — ñ".to_owned(),
            body_text: Some("Texto plano".to_owned()),
            body_html: Some("<p>HTML <strong>rich</strong></p>".to_owned()),
            reply_to: None,
            in_reply_to: None,
            references: None,
            attachments: vec![],
        };
        let msg = build_message(&comp, false).unwrap();
        let bytes = msg.formatted();
        let formatted = String::from_utf8_lossy(&bytes);

        assert!(formatted.contains("MIME-Version: 1.0"));
        assert!(formatted.contains("Content-Type: multipart/alternative"));
        assert!(formatted.contains("boundary="));
        // Non-ASCII subject must be MIME-encoded (RFC 2047) so it survives
        // IMAP/ENVELOPE decoding — otherwise search results show "???".
        assert!(
            formatted.contains("=?utf-8?") || formatted.contains("=?UTF-8?"),
            "subject must be RFC 2047-encoded; got:\n{formatted}"
        );
        assert!(!formatted.contains("Subject: Asunto con acentos — ñ"));
        // Both bodies present.
        assert!(formatted.contains("Texto plano"));
        assert!(formatted.contains("<p>HTML <strong>rich</strong></p>"));
        // Proper multipart closure.
        assert!(formatted.contains("Content-Type: text/plain"));
        assert!(formatted.contains("Content-Type: text/html"));
    }

    #[test]
    fn build_message_with_reply_headers() {
        let comp = EmailComposition {
            from: "sender@example.com".to_owned(),
            to: vec!["recipient@example.com".to_owned()],
            cc: vec![],
            bcc: vec![],
            subject: "Re: Original".to_owned(),
            body_text: Some("Reply body".to_owned()),
            body_html: None,
            reply_to: None,
            in_reply_to: Some("<original@example.com>".to_owned()),
            references: Some("<original@example.com>".to_owned()),
            attachments: vec![],
        };
        let msg = build_message(&comp, false).unwrap();
        let binding = msg.formatted();
        let formatted = String::from_utf8_lossy(&binding);
        assert!(formatted.contains("In-Reply-To: <original@example.com>"));
        assert!(formatted.contains("References: <original@example.com>"));
    }

    #[test]
    fn build_message_rejects_invalid_from() {
        let comp = EmailComposition {
            from: "not-an-email".to_owned(),
            to: vec!["recipient@example.com".to_owned()],
            cc: vec![],
            bcc: vec![],
            subject: "Test".to_owned(),
            body_text: Some("body".to_owned()),
            body_html: None,
            reply_to: None,
            in_reply_to: None,
            references: None,
            attachments: vec![],
        };
        assert!(build_message(&comp, false).is_err());
    }

    /// Helper to generate a real RFC822 blob at /tmp/mail-mcp-sample.eml so
    /// the bytes can be fed to `imap_append_message` for manual end-to-end
    /// verification of the Sent-folder MIME fix. Run with:
    ///   cargo test --release -- --ignored generate_sample_rfc822 --nocapture
    #[test]
    #[ignore]
    fn generate_sample_rfc822_for_append() {
        let comp = EmailComposition {
            from: "soporte@tecnologicachile.cl".to_owned(),
            to: vec!["soporte@tecnologicachile.cl".to_owned()],
            cc: vec![],
            bcc: vec![],
            subject: "Test MIME fix — v0.4.1 (acentos y ñ)".to_owned(),
            body_text: Some(
                "Prueba del fix de save_to_sent_folder.\n\n\
                 Si se ve subject con acentos y cuerpo multipart correcto,\n\
                 el fix funciona.\n\n\
                 Lista:\n- Uno\n- Dos"
                    .to_owned(),
            ),
            body_html: Some(
                "<h3>Prueba del fix</h3>\
                 <p>Multipart/alternative con <strong>HTML</strong> + texto plano.</p>\
                 <ul><li>Uno</li><li>Dos</li></ul>"
                    .to_owned(),
            ),
            reply_to: None,
            in_reply_to: None,
            references: None,
            attachments: vec![],
        };
        let msg = build_message(&comp, false).unwrap();
        let bytes = msg.formatted();
        std::fs::write("/tmp/mail-mcp-sample.eml", &bytes).unwrap();
        println!("wrote /tmp/mail-mcp-sample.eml — {} bytes", bytes.len());
    }

    #[test]
    fn build_message_multiple_recipients() {
        let comp = EmailComposition {
            from: "sender@example.com".to_owned(),
            to: vec!["a@example.com".to_owned(), "b@example.com".to_owned()],
            cc: vec!["c@example.com".to_owned()],
            bcc: vec!["d@example.com".to_owned()],
            subject: "Multi-recipient".to_owned(),
            body_text: Some("body".to_owned()),
            body_html: None,
            reply_to: None,
            in_reply_to: None,
            references: None,
            attachments: vec![],
        };
        let msg = build_message(&comp, false).unwrap();
        let binding = msg.formatted();
        let formatted = String::from_utf8_lossy(&binding);
        assert!(formatted.contains("a@example.com"));
        assert!(formatted.contains("b@example.com"));
        assert!(formatted.contains("Cc:"));
        // Bcc headers are intentionally stripped from formatted output per RFC 2822
    }
}
