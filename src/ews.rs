//! Exchange Web Services (EWS) client for Microsoft Exchange/Office 365
//!
//! Uses SOAP/XML over HTTPS with OAuth2 Bearer tokens. Works with both
//! personal and enterprise Microsoft accounts, including tenants that
//! have blocked Graph API and IMAP.
//!
//! # Configuration
//!
//! ```text
//! MAIL_EWS_<SEGMENT>_USER=user@company.com
//! MAIL_EWS_<SEGMENT>_CLIENT_ID=d3590ed6-52b3-4102-aeff-aad2292ab01c
//! MAIL_EWS_<SEGMENT>_CLIENT_SECRET=none
//! MAIL_EWS_<SEGMENT>_REFRESH_TOKEN=<token>
//! ```

use std::time::Duration;

use crate::errors::{AppError, AppResult};
use crate::oauth2::TokenManager;

/// EWS endpoint
const EWS_URL: &str = "https://outlook.office365.com/EWS/Exchange.asmx";

/// EWS XML namespaces
const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const TYPES_NS: &str = "http://schemas.microsoft.com/exchange/services/2006/types";
const MESSAGES_NS: &str = "http://schemas.microsoft.com/exchange/services/2006/messages";

// ─── EWS account config ─────────────────────────────────────────────────────

/// EWS account configuration.
///
/// The account identifier lives in the outer `HashMap<String,
/// EwsAccountConfig>` key (see `config::ServerConfig::ews_accounts`), so
/// it is not duplicated inside the struct.
#[derive(Debug, Clone)]
pub struct EwsAccountConfig {
    pub user: String,
}

// ─── Response types ──────────────────────────────────────────────────────────

/// A message from EWS FindItem
#[derive(Debug, Clone, serde::Serialize)]
pub struct EwsMessage {
    pub item_id: String,
    pub change_key: String,
    pub subject: String,
    pub from_name: String,
    pub from_email: String,
    pub date_received: String,
    pub is_read: bool,
}

/// A message body from EWS GetItem
#[derive(Debug, Clone, serde::Serialize)]
pub struct EwsMessageDetail {
    pub item_id: String,
    pub subject: String,
    pub from_name: String,
    pub from_email: String,
    pub to: String,
    pub cc: String,
    pub date_received: String,
    pub body_text: String,
    pub is_read: bool,
    pub has_attachments: bool,
}

/// A calendar event from EWS CalendarView
#[derive(Debug, Clone, serde::Serialize)]
pub struct EwsCalendarEvent {
    pub item_id: String,
    pub change_key: String,
    pub subject: String,
    pub start: String,
    pub end: String,
    pub location: String,
    pub organizer_name: String,
    pub organizer_email: String,
    pub is_all_day: bool,
}

// ─── Client ──────────────────────────────────────────────────────────────────

/// Send a SOAP request to EWS with OAuth2 Bearer token.
async fn ews_request(
    token_manager: &TokenManager,
    account_id: &str,
    soap_body: &str,
) -> AppResult<String> {
    let access_token = token_manager.get_access_token(account_id).await?;

    let envelope = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="{SOAP_NS}"
               xmlns:t="{TYPES_NS}"
               xmlns:m="{MESSAGES_NS}">
  <soap:Body>
    {soap_body}
  </soap:Body>
</soap:Envelope>"#
    );

    let client = reqwest::Client::new();
    let response = client
        .post(EWS_URL)
        .header("Content-Type", "text/xml")
        .bearer_auth(&access_token)
        .body(envelope)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("EWS request failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(AppError::AuthFailed(format!(
                "EWS authentication failed ({status})"
            )));
        }
        return Err(AppError::Internal(format!(
            "EWS request failed ({status}): {body}"
        )));
    }

    response
        .text()
        .await
        .map_err(|e| AppError::Internal(format!("EWS response read failed: {e}")))
}

// ─── Operations ──────────────────────────────────────────────────────────────

/// List or search messages in a folder (default: inbox).
///
/// When `query` is `Some`, it is sent as an EWS *AQS QueryString* — the same
/// Advanced Query Syntax Outlook search uses (e.g. `subject:報告`, `from:tanaka`,
/// `安全保障`). AQS runs against the mailbox search index and handles Unicode
/// natively, so it solves the Japanese-subject search that IMAP cannot do on
/// Exchange Online. Per the FindItem schema, `QueryString` is the last child
/// (after `ParentFolderIds`); it cannot be combined with a `Restriction` (we
/// use none) and is incompatible with `SortOrder`, so we drop the explicit sort
/// when searching (AQS returns by relevance/recency).
pub async fn find_items(
    token_manager: &TokenManager,
    account_id: &str,
    folder: &str,
    max_items: usize,
    offset: usize,
    query: Option<&str>,
) -> AppResult<Vec<EwsMessage>> {
    // Resolve the folder: well-known name → DistinguishedFolderId; otherwise try
    // to match a custom folder's display name via FindFolder; failing that, treat
    // the string as a raw FolderId (back-compat for callers passing ids directly).
    let folder_xml = match distinguished_folder_id(folder) {
        Some(dist) => format!(r#"<t:DistinguishedFolderId Id="{dist}"/>"#),
        None => match find_folder_id_by_name(token_manager, account_id, folder).await {
            Ok(id) => format!(r#"<t:FolderId Id="{}"/>"#, escape_xml(&id)),
            Err(_) => format!(r#"<t:FolderId Id="{}"/>"#, escape_xml(folder)),
        },
    };

    // SortOrder and QueryString are mutually exclusive in FindItem.
    let sort_xml = if query.is_some() {
        String::new()
    } else {
        r#"<m:SortOrder>
        <t:FieldOrder Order="Descending">
          <t:FieldURI FieldURI="item:DateTimeReceived"/>
        </t:FieldOrder>
      </m:SortOrder>"#
            .to_owned()
    };
    let query_xml = match query {
        Some(q) => format!("<m:QueryString>{}</m:QueryString>", escape_xml(q)),
        None => String::new(),
    };

    let soap = format!(
        r#"<m:FindItem Traversal="Shallow">
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Subject"/>
          <t:FieldURI FieldURI="item:DateTimeReceived"/>
          <t:FieldURI FieldURI="message:From"/>
          <t:FieldURI FieldURI="message:IsRead"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:IndexedPageItemView MaxEntriesReturned="{max_items}" Offset="{offset}" BasePoint="Beginning"/>
      {sort_xml}
      <m:ParentFolderIds>
        {folder_xml}
      </m:ParentFolderIds>
      {query_xml}
    </m:FindItem>"#
    );

    let xml = ews_request(token_manager, account_id, &soap).await?;
    if xml.contains("ResponseClass=\"Error\"") {
        let msg = extract_xml_text(&xml, "MessageText").unwrap_or_default();
        return Err(AppError::Internal(format!("EWS FindItem failed: {msg}")));
    }
    parse_find_items_response(&xml)
}

/// List calendar events in a date range using EWS CalendarView.
pub async fn find_calendar_items(
    token_manager: &TokenManager,
    account_id: &str,
    start_date: &str,
    end_date: &str,
    max_items: usize,
) -> AppResult<Vec<EwsCalendarEvent>> {
    let soap = format!(
        r#"<m:FindItem Traversal="Shallow">
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Subject"/>
          <t:FieldURI FieldURI="calendar:Start"/>
          <t:FieldURI FieldURI="calendar:End"/>
          <t:FieldURI FieldURI="calendar:Location"/>
          <t:FieldURI FieldURI="calendar:Organizer"/>
          <t:FieldURI FieldURI="calendar:IsAllDayEvent"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:CalendarView MaxEntriesReturned="{max_items}" StartDate="{start_date}" EndDate="{end_date}"/>
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="calendar"/>
      </m:ParentFolderIds>
    </m:FindItem>"#
    );

    let xml = ews_request(token_manager, account_id, &soap).await?;
    parse_calendar_items_response(&xml)
}

/// Get full message details
pub async fn get_item(
    token_manager: &TokenManager,
    account_id: &str,
    item_id: &str,
) -> AppResult<EwsMessageDetail> {
    let soap = format!(
        r#"<m:GetItem>
      <m:ItemShape>
        <t:BaseShape>Default</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Body"/>
          <t:FieldURI FieldURI="item:HasAttachments"/>
          <t:FieldURI FieldURI="message:ToRecipients"/>
          <t:FieldURI FieldURI="message:CcRecipients"/>
        </t:AdditionalProperties>
        <t:BodyType>Text</t:BodyType>
      </m:ItemShape>
      <m:ItemIds>
        <t:ItemId Id="{item_id}"/>
      </m:ItemIds>
    </m:GetItem>"#
    );

    let xml = ews_request(token_manager, account_id, &soap).await?;
    parse_get_item_response(&xml)
}

// ─── Attachments ─────────────────────────────────────────────────────────────

/// Metadata + (optionally) extracted text for one file attachment.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EwsAttachment {
    pub attachment_id: String,
    pub name: String,
    pub content_type: String,
    pub size_bytes: usize,
    /// PDF text, when `extract_text` was requested and extraction succeeded.
    pub extracted_text: Option<String>,
}

/// List a message's file attachments, downloading each one's bytes to report a
/// true size and (for PDFs, when `extract_text`) extracted text. Inline/embedded
/// item attachments (e.g. attached emails) are skipped — only `FileAttachment`s.
pub async fn get_attachments(
    token_manager: &TokenManager,
    account_id: &str,
    item_id: &str,
    extract_text: bool,
    max_chars: usize,
) -> AppResult<Vec<EwsAttachment>> {
    // Step 1: list attachment ids + metadata from the item.
    let item_id_escaped = escape_xml(item_id);
    let soap = format!(
        r#"<m:GetItem>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Attachments"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:ItemIds>
        <t:ItemId Id="{item_id_escaped}"/>
      </m:ItemIds>
    </m:GetItem>"#
    );
    let xml = ews_request(token_manager, account_id, &soap).await?;
    if xml.contains("ResponseClass=\"Error\"") {
        let msg = extract_xml_text(&xml, "MessageText").unwrap_or_default();
        return Err(AppError::Internal(format!("EWS GetItem (attachments) failed: {msg}")));
    }
    let mut attachments = parse_attachment_list(&xml)?;

    // Step 2: download each attachment's content to fill size + extracted text.
    for att in &mut attachments {
        let (bytes, content_type) =
            fetch_attachment_content(token_manager, account_id, &att.attachment_id).await?;
        att.size_bytes = bytes.len();
        if !content_type.is_empty() {
            att.content_type = content_type;
        }
        if extract_text
            && att.content_type.eq_ignore_ascii_case("application/pdf")
            && bytes.len() <= 5_000_000
            && let Ok(text) = pdf_extract::extract_text_from_mem(&bytes)
        {
            att.extracted_text = Some(truncate_chars(text, max_chars));
        }
    }
    Ok(attachments)
}

/// Download one attachment's raw bytes via `GetAttachment`. Returns
/// `(content_bytes, content_type)`.
async fn fetch_attachment_content(
    token_manager: &TokenManager,
    account_id: &str,
    attachment_id: &str,
) -> AppResult<(Vec<u8>, String)> {
    use base64::Engine;
    let id_escaped = escape_xml(attachment_id);
    let soap = format!(
        r#"<m:GetAttachment>
      <m:AttachmentIds>
        <t:AttachmentId Id="{id_escaped}"/>
      </m:AttachmentIds>
    </m:GetAttachment>"#
    );
    let xml = ews_request(token_manager, account_id, &soap).await?;
    if xml.contains("ResponseClass=\"Error\"") {
        let msg = extract_xml_text(&xml, "MessageText").unwrap_or_default();
        return Err(AppError::Internal(format!("EWS GetAttachment failed: {msg}")));
    }
    let content_type = extract_xml_text(&xml, "ContentType").unwrap_or_default();
    let b64 = extract_xml_text(&xml, "Content").unwrap_or_default();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim().as_bytes())
        .map_err(|e| AppError::Internal(format!("EWS attachment base64 decode failed: {e}")))?;
    Ok((bytes, content_type))
}

/// Truncate a string to at most `max` characters (not bytes), appending an
/// ellipsis note when truncated. Mirrors the IMAP path's behavior.
fn truncate_chars(s: String, max: usize) -> String {
    if s.chars().count() <= max {
        return s;
    }
    let truncated: String = s.chars().take(max).collect();
    format!("{truncated}… [truncated]")
}

/// Parse the `<t:Attachments>` block of a GetItem response into `EwsAttachment`
/// metadata (size is filled in later by downloading). Only `FileAttachment`
/// entries are collected; `ItemAttachment`s are skipped.
fn parse_attachment_list(xml: &str) -> AppResult<Vec<EwsAttachment>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut out = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if local_name_eq(&e, "FileAttachment") => {
                if let Some(att) = parse_one_file_attachment(&mut reader)? {
                    out.push(att);
                }
            }
            Ok(Event::Eof) => break,
            Err(err) => {
                return Err(AppError::Internal(format!(
                    "EWS attachment list parse error at position {}: {err}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }
    Ok(out)
}

/// After a `Start(<t:FileAttachment>)`, read AttachmentId / Name / ContentType /
/// Size until the matching End. Returns `None` if it has no AttachmentId.
fn parse_one_file_attachment(reader: &mut Reader<&[u8]>) -> AppResult<Option<EwsAttachment>> {
    let mut buf = Vec::new();
    let mut att = EwsAttachment {
        attachment_id: String::new(),
        name: String::new(),
        content_type: String::new(),
        size_bytes: 0,
        extracted_text: None,
    };
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match local_name(&e).as_str() {
                "AttachmentId" if att.attachment_id.is_empty() => {
                    att.attachment_id = attr_value(&e, "Id").unwrap_or_default();
                }
                "Name" => att.name = read_text_until_end(reader),
                "ContentType" => att.content_type = read_text_until_end(reader),
                "Size" => {
                    att.size_bytes = read_text_until_end(reader).parse().unwrap_or(0);
                }
                _ => {}
            },
            Ok(Event::End(e)) if local_name_bytes_eq(e.name().as_ref(), "FileAttachment") => break,
            Ok(Event::Eof) => break,
            Err(err) => {
                return Err(AppError::Internal(format!(
                    "EWS FileAttachment parse error at position {}: {err}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }
    if att.attachment_id.is_empty() {
        Ok(None)
    } else {
        Ok(Some(att))
    }
}

// ─── Mutating operations: move / delete / mark-read ──────────────────────────

/// Map a friendly folder name to its EWS *DistinguishedFolderId* id, if it is
/// one of the well-known folders. Returns `None` for custom folders (whose
/// names must be resolved to a `FolderId` via `find_folder_id_by_name`) or for
/// raw folder ids passed straight through.
fn distinguished_folder_id(folder: &str) -> Option<&'static str> {
    match folder.to_ascii_lowercase().as_str() {
        "inbox" => Some("inbox"),
        "sent" | "sentitems" | "sent items" => Some("sentitems"),
        "drafts" => Some("drafts"),
        "deleted" | "deleteditems" | "deleted items" => Some("deleteditems"),
        "junk" | "junkemail" | "junk email" => Some("junkemail"),
        "archive" => Some("archive"),
        "outbox" => Some("outbox"),
        _ => None,
    }
}

/// Resolve a destination folder (for MoveItem) to the XML id element that goes
/// inside `<m:ToFolderId>`. Distinguished folders map directly; everything else
/// is treated as a custom folder *display name* and resolved to a `FolderId`
/// via `FindFolder`.
async fn resolve_dest_folder_xml(
    token_manager: &TokenManager,
    account_id: &str,
    folder: &str,
) -> AppResult<String> {
    if let Some(dist) = distinguished_folder_id(folder) {
        return Ok(format!(r#"<t:DistinguishedFolderId Id="{dist}"/>"#));
    }
    let id = find_folder_id_by_name(token_manager, account_id, folder).await?;
    Ok(format!(r#"<t:FolderId Id="{}"/>"#, escape_xml(&id)))
}

/// Find a mail folder's `FolderId` by its display name, searching the whole
/// mailbox tree (Deep traversal under the message-folder root). Matches the
/// display name case-insensitively. Errors if no folder matches.
async fn find_folder_id_by_name(
    token_manager: &TokenManager,
    account_id: &str,
    name: &str,
) -> AppResult<String> {
    let soap = r#"<m:FindFolder Traversal="Deep">
      <m:FolderShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="folder:DisplayName"/>
        </t:AdditionalProperties>
      </m:FolderShape>
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="msgfolderroot"/>
      </m:ParentFolderIds>
    </m:FindFolder>"#;

    let xml = ews_request(token_manager, account_id, soap).await?;
    if xml.contains("ResponseClass=\"Error\"") {
        let msg = extract_xml_text(&xml, "MessageText").unwrap_or_default();
        return Err(AppError::Internal(format!("EWS FindFolder failed: {msg}")));
    }
    let folders = parse_find_folder_response(&xml)?;
    folders
        .into_iter()
        .find(|(_, disp)| disp.eq_ignore_ascii_case(name))
        .map(|(id, _)| id)
        .ok_or_else(|| {
            AppError::InvalidInput(format!("EWS: no folder found with display name '{name}'"))
        })
}

/// Move a message to another folder. `dest_folder` may be a well-known folder
/// name (inbox, archive, deleted, junk, …) or a custom folder's display name.
/// Returns the message's new EWS item id (move re-issues the id).
pub async fn move_item(
    token_manager: &TokenManager,
    account_id: &str,
    item_id: &str,
    dest_folder: &str,
) -> AppResult<String> {
    let dest_xml = resolve_dest_folder_xml(token_manager, account_id, dest_folder).await?;
    let item_id_escaped = escape_xml(item_id);
    let soap = format!(
        r#"<m:MoveItem>
      <m:ToFolderId>{dest_xml}</m:ToFolderId>
      <m:ItemIds>
        <t:ItemId Id="{item_id_escaped}"/>
      </m:ItemIds>
    </m:MoveItem>"#
    );
    let xml = ews_request(token_manager, account_id, &soap).await?;
    if xml.contains("ResponseClass=\"Error\"") {
        let msg = extract_xml_text(&xml, "MessageText").unwrap_or_default();
        return Err(AppError::Internal(format!("EWS MoveItem failed: {msg}")));
    }
    // The moved item gets a fresh ItemId; return it (fall back to the old id).
    Ok(extract_attr(&xml, "ItemId", "Id").unwrap_or_else(|| item_id.to_owned()))
}

/// Delete a message. `hard = false` moves it to Deleted Items (recoverable);
/// `hard = true` permanently deletes it.
pub async fn delete_item(
    token_manager: &TokenManager,
    account_id: &str,
    item_id: &str,
    hard: bool,
) -> AppResult<()> {
    let delete_type = if hard { "HardDelete" } else { "MoveToDeletedItems" };
    let item_id_escaped = escape_xml(item_id);
    let soap = format!(
        r#"<m:DeleteItem DeleteType="{delete_type}">
      <m:ItemIds>
        <t:ItemId Id="{item_id_escaped}"/>
      </m:ItemIds>
    </m:DeleteItem>"#
    );
    let xml = ews_request(token_manager, account_id, &soap).await?;
    if xml.contains("ResponseClass=\"Error\"") {
        let msg = extract_xml_text(&xml, "MessageText").unwrap_or_default();
        return Err(AppError::Internal(format!("EWS DeleteItem failed: {msg}")));
    }
    Ok(())
}

/// Mark a message read or unread by setting the `message:IsRead` field.
/// `ConflictResolution="AlwaysOverwrite"` means we don't need a fresh ChangeKey.
pub async fn set_read(
    token_manager: &TokenManager,
    account_id: &str,
    item_id: &str,
    is_read: bool,
) -> AppResult<()> {
    let item_id_escaped = escape_xml(item_id);
    let value = if is_read { "true" } else { "false" };
    let soap = format!(
        r#"<m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="AlwaysOverwrite">
      <m:ItemChanges>
        <t:ItemChange>
          <t:ItemId Id="{item_id_escaped}"/>
          <t:Updates>
            <t:SetItemField>
              <t:FieldURI FieldURI="message:IsRead"/>
              <t:Message><t:IsRead>{value}</t:IsRead></t:Message>
            </t:SetItemField>
          </t:Updates>
        </t:ItemChange>
      </m:ItemChanges>
    </m:UpdateItem>"#
    );
    let xml = ews_request(token_manager, account_id, &soap).await?;
    if xml.contains("ResponseClass=\"Error\"") {
        let msg = extract_xml_text(&xml, "MessageText").unwrap_or_default();
        return Err(AppError::Internal(format!("EWS UpdateItem failed: {msg}")));
    }
    Ok(())
}

/// `true` for the EWS folder *item* element names (the containers that carry a
/// FolderId + DisplayName). Deliberately excludes wrappers like `RootFolder` /
/// `Folders`, which also end in "Folder" but would otherwise swallow the tree.
fn is_folder_element(local: &str) -> bool {
    matches!(
        local,
        "Folder" | "CalendarFolder" | "ContactsFolder" | "SearchFolder" | "TasksFolder"
    )
}

/// Parse a FindFolder response into `(folder_id, display_name)` pairs.
/// Matches any `*Folder` container element (mail folders are `<t:Folder>`).
fn parse_find_folder_response(xml: &str) -> AppResult<Vec<(String, String)>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut folders = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if is_folder_element(&local_name(&e)) => {
                if let Some(pair) = parse_folder_block(&mut reader, &local_name(&e))? {
                    folders.push(pair);
                }
            }
            Ok(Event::Eof) => break,
            Err(err) => {
                return Err(AppError::Internal(format!(
                    "EWS FindFolder XML parse error at position {}: {err}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }
    Ok(folders)
}

/// After a `Start(<t:Folder>)` (or other `*Folder`) event, read its `FolderId`
/// and `DisplayName`, stopping at the matching `End`. Returns `None` if the
/// block has no FolderId.
fn parse_folder_block(
    reader: &mut Reader<&[u8]>,
    end_tag: &str,
) -> AppResult<Option<(String, String)>> {
    let mut buf = Vec::new();
    let mut id = String::new();
    let mut display = String::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match local_name(&e).as_str() {
                "FolderId" if id.is_empty() => {
                    id = attr_value(&e, "Id").unwrap_or_default();
                }
                "DisplayName" => {
                    display = read_text_until_end(reader);
                }
                _ => {}
            },
            Ok(Event::End(e)) if local_name_bytes_eq(e.name().as_ref(), end_tag) => break,
            Ok(Event::Eof) => break,
            Err(err) => {
                return Err(AppError::Internal(format!(
                    "EWS folder block parse error at position {}: {err}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }
    if id.is_empty() {
        Ok(None)
    } else {
        Ok(Some((id, display)))
    }
}

/// Parameters for sending an email via EWS.
///
/// Groups the many optional inputs so the function signature stays stable
/// as we add features like threading or BCC.
pub struct EwsSendParams<'a> {
    pub to: &'a [String],
    pub cc: &'a [String],
    pub bcc: &'a [String],
    pub subject: &'a str,
    pub body: &'a str,
    pub body_type: &'a str,
    pub in_reply_to: Option<&'a str>,
    pub references: Option<&'a str>,
    pub attachments: &'a [crate::smtp::EmailAttachment],
}

/// Send an email via EWS.
///
/// Without attachments: single `CreateItem` with `SendAndSaveCopy`.
/// With attachments: `CreateItem` as draft → `CreateAttachment` per file → `SendItem`.
/// EWS does not allow setting `Attachments` inline in `CreateItem` — that property
/// is read-only on the Message type and must go through the dedicated attachment endpoint.
pub async fn send_email(
    token_manager: &TokenManager,
    account_id: &str,
    params: &EwsSendParams<'_>,
) -> AppResult<()> {
    let to_xml = render_mailboxes(params.to);
    let cc_xml = render_mailboxes(params.cc);
    let bcc_xml = render_mailboxes(params.bcc);

    let cc_section = if params.cc.is_empty() {
        String::new()
    } else {
        format!("<t:CcRecipients>{cc_xml}</t:CcRecipients>")
    };
    let bcc_section = if params.bcc.is_empty() {
        String::new()
    } else {
        format!("<t:BccRecipients>{bcc_xml}</t:BccRecipients>")
    };

    // EWS takes RFC 2822 threading headers via InternetMessageHeaders. They
    // must be placed BEFORE ToRecipients in the XML — EWS is order-sensitive
    // and will reject out-of-order elements with a schema error.
    let headers_section = build_internet_headers(params.in_reply_to, params.references);

    let body_escaped = escape_xml(params.body);
    let subject_escaped = escape_xml(params.subject);
    let body_type = params.body_type;

    if params.attachments.is_empty() {
        // Fast path: single CreateItem with SendAndSaveCopy.
        let soap = format!(
            r#"<m:CreateItem MessageDisposition="SendAndSaveCopy">
          <m:SavedItemFolderId>
            <t:DistinguishedFolderId Id="sentitems"/>
          </m:SavedItemFolderId>
          <m:Items>
            <t:Message>
              <t:Subject>{subject_escaped}</t:Subject>
              <t:Body BodyType="{body_type}">{body_escaped}</t:Body>
              {headers_section}
              <t:ToRecipients>{to_xml}</t:ToRecipients>
              {cc_section}
              {bcc_section}
            </t:Message>
          </m:Items>
        </m:CreateItem>"#
        );
        let xml = ews_request(token_manager, account_id, &soap).await?;
        if xml.contains("ResponseClass=\"Error\"") {
            let msg = extract_xml_text(&xml, "MessageText").unwrap_or_default();
            return Err(AppError::Internal(format!("EWS send failed: {msg}")));
        }
        return Ok(());
    }

    // Attachment path: CreateItem as draft → CreateAttachment × N → SendItem.

    // Step 1: create draft in Drafts folder.
    let soap = format!(
        r#"<m:CreateItem MessageDisposition="SaveOnly">
      <m:SavedItemFolderId>
        <t:DistinguishedFolderId Id="drafts"/>
      </m:SavedItemFolderId>
      <m:Items>
        <t:Message>
          <t:Subject>{subject_escaped}</t:Subject>
          <t:Body BodyType="{body_type}">{body_escaped}</t:Body>
          {headers_section}
          <t:ToRecipients>{to_xml}</t:ToRecipients>
          {cc_section}
          {bcc_section}
        </t:Message>
      </m:Items>
    </m:CreateItem>"#
    );
    let xml = ews_request(token_manager, account_id, &soap).await?;
    if xml.contains("ResponseClass=\"Error\"") {
        let msg = extract_xml_text(&xml, "MessageText").unwrap_or_default();
        return Err(AppError::Internal(format!("EWS create draft failed: {msg}")));
    }
    let item_id = extract_attr(&xml, "ItemId", "Id").ok_or_else(|| {
        AppError::Internal("EWS CreateItem response missing ItemId".to_owned())
    })?;
    let change_key = extract_attr(&xml, "ItemId", "ChangeKey").unwrap_or_default();

    // Step 2: attach each file — each CreateAttachment returns a new ChangeKey.
    let mut change_key = change_key;
    for att in params.attachments {
        change_key = create_attachment(token_manager, account_id, &item_id, &change_key, att).await?;
    }

    // Step 3: fetch the current ChangeKey — Exchange updates it server-side during
    // attachment indexing so the key from CreateAttachment is already stale.
    let current_change_key =
        fetch_change_key(token_manager, account_id, &item_id).await?;
    let item_id_escaped = escape_xml(&item_id);
    let change_key_escaped = escape_xml(&current_change_key);
    let soap = format!(
        r#"<m:SendItem SaveItemToFolder="true">
      <m:ItemIds>
        <t:ItemId Id="{item_id_escaped}" ChangeKey="{change_key_escaped}"/>
      </m:ItemIds>
      <m:SavedItemFolderId>
        <t:DistinguishedFolderId Id="sentitems"/>
      </m:SavedItemFolderId>
    </m:SendItem>"#
    );
    let xml = ews_request(token_manager, account_id, &soap).await?;
    if xml.contains("ResponseClass=\"Error\"") {
        let msg = extract_xml_text(&xml, "MessageText").unwrap_or_default();
        return Err(AppError::Internal(format!("EWS send failed: {msg}")));
    }

    Ok(())
}

/// Attach a single file to an existing draft item via `CreateAttachment`.
/// Returns the updated ChangeKey from the response (EWS increments it on each mutation).
async fn create_attachment(
    token_manager: &TokenManager,
    account_id: &str,
    item_id: &str,
    change_key: &str,
    att: &crate::smtp::EmailAttachment,
) -> AppResult<String> {
    use base64::Engine;
    let name = escape_xml(&att.filename);
    let content_type = escape_xml(&att.content_type);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&att.content);
    let item_id_escaped = escape_xml(item_id);
    let change_key_escaped = escape_xml(change_key);

    let soap = format!(
        r#"<m:CreateAttachment>
      <m:ParentItemId Id="{item_id_escaped}" ChangeKey="{change_key_escaped}"/>
      <m:Attachments>
        <t:FileAttachment>
          <t:Name>{name}</t:Name>
          <t:ContentType>{content_type}</t:ContentType>
          <t:Content>{b64}</t:Content>
        </t:FileAttachment>
      </m:Attachments>
    </m:CreateAttachment>"#
    );
    let xml = ews_request(token_manager, account_id, &soap).await?;
    if xml.contains("ResponseClass=\"Error\"") {
        let msg = extract_xml_text(&xml, "MessageText").unwrap_or_default();
        return Err(AppError::Internal(format!(
            "EWS CreateAttachment failed for '{}': {msg}",
            att.filename
        )));
    }
    // RootItemChangeKey reflects the updated ChangeKey of the parent item.
    let new_change_key = extract_attr(&xml, "RootItemId", "RootItemChangeKey")
        .unwrap_or_else(|| change_key.to_owned());
    Ok(new_change_key)
}

/// Fetch the current ChangeKey for an item by doing a minimal GetItem.
/// Used before SendItem to get a fresh key after attachment indexing mutates it.
async fn fetch_change_key(
    token_manager: &TokenManager,
    account_id: &str,
    item_id: &str,
) -> AppResult<String> {
    let item_id_escaped = escape_xml(item_id);
    let soap = format!(
        r#"<m:GetItem>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
      </m:ItemShape>
      <m:ItemIds>
        <t:ItemId Id="{item_id_escaped}"/>
      </m:ItemIds>
    </m:GetItem>"#
    );
    let xml = ews_request(token_manager, account_id, &soap).await?;
    extract_attr(&xml, "ItemId", "ChangeKey").ok_or_else(|| {
        AppError::Internal("EWS GetItem response missing ChangeKey".to_owned())
    })
}

/// Render a list of recipient addresses as EWS `<t:Mailbox>` elements.
fn render_mailboxes(addrs: &[String]) -> String {
    addrs
        .iter()
        .map(|addr| {
            let escaped = escape_xml(addr);
            format!(r#"<t:Mailbox><t:EmailAddress>{escaped}</t:EmailAddress></t:Mailbox>"#)
        })
        .collect()
}



/// Build an `<t:InternetMessageHeaders>` block for threading headers.
/// Returns an empty string if neither header is set.
fn build_internet_headers(in_reply_to: Option<&str>, references: Option<&str>) -> String {
    if in_reply_to.is_none() && references.is_none() {
        return String::new();
    }
    let mut headers = String::from("<t:InternetMessageHeaders>");
    if let Some(irt) = in_reply_to {
        headers.push_str(&format!(
            r#"<t:InternetMessageHeader HeaderName="In-Reply-To">{}</t:InternetMessageHeader>"#,
            escape_xml(irt)
        ));
    }
    if let Some(refs) = references {
        headers.push_str(&format!(
            r#"<t:InternetMessageHeader HeaderName="References">{}</t:InternetMessageHeader>"#,
            escape_xml(refs)
        ));
    }
    headers.push_str("</t:InternetMessageHeaders>");
    headers
}

/// XML-escape the five predefined entities plus quotes (for attribute-safe
/// content). Order matters: `&` must be replaced first.
fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ─── XML Parsing helpers ─────────────────────────────────────────────────────
//
// Backed by `quick-xml`'s pull parser. Matches by *local name* (ignoring
// the `t:` / `m:` namespace prefix), correctly handles XML entities, CDATA
// and nested tags, and short-circuits at the first match for the
// `extract_*` helpers.

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

/// Return the (unescaped) text content of the first element whose local
/// name matches `tag`. Returns `None` if the tag is not found or if XML is
/// malformed.
fn extract_xml_text(xml: &str, tag: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if local_name_eq(&e, tag) => {
                return Some(read_text_until_end(&mut reader));
            }
            Ok(Event::Eof) => return None,
            Err(_) => return None,
            _ => {}
        }
    }
}

/// Return the value of `attr` on the first element whose local name is `tag`.
/// Works on both `Start` and `Empty` events (so `<t:ItemId Id="x"/>` parses).
///
/// Kept as a general helper for future parsers (and for tests that
/// regression-check the XML parsing); marked `#[allow(dead_code)]` because
/// current parsers inline `attr_value` on their own event walk.
fn extract_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) if local_name_eq(&e, tag) => {
                return attr_value(&e, attr);
            }
            Ok(Event::Eof) => return None,
            Err(_) => return None,
            _ => {}
        }
    }
}

/// Parse a FindItem response — walks `<Message>` blocks and collects
/// subject / date / is_read / item_id / change_key / from (name + email).
fn parse_find_items_response(xml: &str) -> AppResult<Vec<EwsMessage>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut messages = Vec::new();

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e))
                if local_name_eq(&e, "Message")
                    || local_name_eq(&e, "MeetingRequest")
                    || local_name_eq(&e, "MeetingResponse")
                    || local_name_eq(&e, "MeetingCancellation")
                    || local_name_eq(&e, "CalendarItem") =>
            {
                messages.push(parse_message_block(&mut reader)?);
            }
            Ok(Event::Eof) => break,
            Err(err) => {
                return Err(AppError::Internal(format!(
                    "EWS FindItem XML parse error at position {}: {err}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }
    Ok(messages)
}

/// Parse a FindItem CalendarView response — walks `<CalendarItem>` blocks.
fn parse_calendar_items_response(xml: &str) -> AppResult<Vec<EwsCalendarEvent>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut events = Vec::new();

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if local_name_eq(&e, "CalendarItem") => {
                events.push(parse_calendar_item_block(&mut reader)?);
            }
            Ok(Event::Eof) => break,
            Err(err) => {
                return Err(AppError::Internal(format!(
                    "EWS CalendarView XML parse error at position {}: {err}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }
    Ok(events)
}

fn parse_calendar_item_block(reader: &mut Reader<&[u8]>) -> AppResult<EwsCalendarEvent> {
    let mut buf = Vec::new();
    let mut evt = EwsCalendarEvent {
        item_id: String::new(),
        change_key: String::new(),
        subject: String::new(),
        start: String::new(),
        end: String::new(),
        location: String::new(),
        organizer_name: String::new(),
        organizer_email: String::new(),
        is_all_day: false,
    };
    let mut in_organizer = false;
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match local_name(&e).as_str() {
                "ItemId" => {
                    evt.item_id = attr_value(&e, "Id").unwrap_or_default();
                    evt.change_key = attr_value(&e, "ChangeKey").unwrap_or_default();
                }
                "Subject" => evt.subject = read_text_until_end(reader),
                "Start" => evt.start = read_text_until_end(reader),
                "End" => evt.end = read_text_until_end(reader),
                "Location" => evt.location = read_text_until_end(reader),
                "IsAllDayEvent" => evt.is_all_day = read_text_until_end(reader) == "true",
                "Organizer" => in_organizer = true,
                "Name" if in_organizer && evt.organizer_name.is_empty() => {
                    evt.organizer_name = read_text_until_end(reader);
                }
                "EmailAddress" if in_organizer && evt.organizer_email.is_empty() => {
                    evt.organizer_email = read_text_until_end(reader);
                }
                _ => {}
            },
            Ok(Event::End(e)) => {
                if local_name_bytes_eq(e.name().as_ref(), "Organizer") {
                    in_organizer = false;
                } else if local_name_bytes_eq(e.name().as_ref(), "CalendarItem") {
                    return Ok(evt);
                }
            }
            Ok(Event::Eof) => return Ok(evt),
            Err(err) => {
                return Err(AppError::Internal(format!(
                    "EWS CalendarItem block parse error at position {}: {err}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }
}

/// Parse a GetItem response into a single `EwsMessageDetail`.
///
/// Walks the outer envelope until it finds `<t:Message>`, then delegates
/// extraction to `parse_message_detail_block`. This avoids accidentally
/// matching outer-namespace elements like `<soap:Body>` against the local
/// name `Body` (which would otherwise swallow the entire payload).
fn parse_get_item_response(xml: &str) -> AppResult<EwsMessageDetail> {
    if xml.contains("ResponseClass=\"Error\"") {
        let msg =
            extract_xml_text(xml, "MessageText").unwrap_or_else(|| "unknown error".to_owned());
        return Err(AppError::Internal(format!("EWS GetItem failed: {msg}")));
    }

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e))
                if local_name_eq(&e, "Message")
                    || local_name_eq(&e, "MeetingRequest")
                    || local_name_eq(&e, "MeetingResponse")
                    || local_name_eq(&e, "MeetingCancellation")
                    || local_name_eq(&e, "CalendarItem") =>
            {
                return parse_message_detail_block(&mut reader);
            }
            Ok(Event::Eof) => break,
            Err(err) => {
                return Err(AppError::Internal(format!(
                    "EWS GetItem XML parse error at position {}: {err}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }

    // No <t:Message> found — return empty defaults (matches historical behavior
    // when the response was structurally unexpected).
    Ok(EwsMessageDetail {
        item_id: String::new(),
        subject: String::new(),
        from_name: String::new(),
        from_email: String::new(),
        to: String::new(),
        cc: String::new(),
        date_received: String::new(),
        body_text: String::new(),
        is_read: false,
        has_attachments: false,
    })
}

/// After a `Start(<t:Message>)` event, extract all fields for a single
/// `EwsMessageDetail` by reading child elements until the matching End.
fn parse_message_detail_block(reader: &mut Reader<&[u8]>) -> AppResult<EwsMessageDetail> {
    let mut buf = Vec::new();
    let mut detail = EwsMessageDetail {
        item_id: String::new(),
        subject: String::new(),
        from_name: String::new(),
        from_email: String::new(),
        to: String::new(),
        cc: String::new(),
        date_received: String::new(),
        body_text: String::new(),
        is_read: false,
        has_attachments: false,
    };
    let mut captured_from_name = false;
    let mut captured_from_email = false;

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match local_name(&e).as_str() {
                "ItemId" => {
                    if detail.item_id.is_empty() {
                        detail.item_id = attr_value(&e, "Id").unwrap_or_default();
                    }
                }
                "Subject" => {
                    detail.subject = read_text_until_end(reader);
                }
                "DateTimeReceived" => {
                    detail.date_received = read_text_until_end(reader);
                }
                "IsRead" => {
                    detail.is_read = read_text_until_end(reader) == "true";
                }
                "HasAttachments" => {
                    detail.has_attachments = read_text_until_end(reader) == "true";
                }
                "Body" => {
                    detail.body_text = read_text_until_end(reader);
                }
                "Name" if !captured_from_name => {
                    detail.from_name = read_text_until_end(reader);
                    captured_from_name = true;
                }
                "EmailAddress" if !captured_from_email => {
                    detail.from_email = read_text_until_end(reader);
                    captured_from_email = true;
                }
                "ToRecipients" => {
                    detail.to = collect_recipient_emails(reader)?;
                }
                "CcRecipients" => {
                    detail.cc = collect_recipient_emails(reader)?;
                }
                _ => {}
            },
            Ok(Event::End(e)) if local_name_bytes_eq(e.name().as_ref(), "Message") => {
                return Ok(detail);
            }
            Ok(Event::Eof) => return Ok(detail),
            Err(err) => {
                return Err(AppError::Internal(format!(
                    "EWS Message detail parse error at position {}: {err}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }
}

// ─── Parser primitives ───────────────────────────────────────────────────────

/// `true` if the local name of `e` (without namespace prefix) equals `name`.
fn local_name_eq(e: &BytesStart<'_>, name: &str) -> bool {
    local_name_bytes_eq(e.name().as_ref(), name)
}

/// `true` if a raw qualified-name byte slice (e.g. `b"t:Subject"`)
/// has a local part equal to `name`.
fn local_name_bytes_eq(qname: &[u8], name: &str) -> bool {
    let local = match qname.iter().position(|&b| b == b':') {
        Some(i) => &qname[i + 1..],
        None => qname,
    };
    local == name.as_bytes()
}

/// Extract the local name of a `Start`/`Empty` element (strips any
/// `prefix:` namespace).
fn local_name(e: &BytesStart<'_>) -> String {
    let qname = e.name();
    let bytes = qname.as_ref();
    let local = match bytes.iter().position(|&b| b == b':') {
        Some(i) => &bytes[i + 1..],
        None => bytes,
    };
    String::from_utf8_lossy(local).into_owned()
}

/// Read the first attribute of `e` matching `attr_name` (local name match).
/// Returns the unescaped value.
fn attr_value(e: &BytesStart<'_>, attr_name: &str) -> Option<String> {
    for raw in e.attributes().flatten() {
        let key = raw.key;
        let key_bytes = key.as_ref();
        let local = match key_bytes.iter().position(|&b| b == b':') {
            Some(i) => &key_bytes[i + 1..],
            None => key_bytes,
        };
        if local == attr_name.as_bytes() {
            return Some(
                raw.unescape_value()
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|_| String::from_utf8_lossy(raw.value.as_ref()).into_owned()),
            );
        }
    }
    None
}

/// After a `Start` event, drain events accumulating Text/CData until we
/// see the matching `End` event (handles one level of nesting — sufficient
/// for leaf-like text elements in EWS responses). On malformed XML, returns
/// whatever we collected so far rather than erroring (lossy but forward-
/// compatible with the previous substring-based helpers).
fn read_text_until_end(reader: &mut Reader<&[u8]>) -> String {
    let mut buf = Vec::new();
    let mut text = String::new();
    let mut depth = 1;
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(_)) => depth += 1,
            Ok(Event::End(_)) => {
                depth -= 1;
                if depth == 0 {
                    return text;
                }
            }
            Ok(Event::Text(t)) => {
                if let Ok(s) = t.unescape() {
                    text.push_str(&s);
                }
            }
            Ok(Event::CData(t)) => {
                text.push_str(&String::from_utf8_lossy(t.as_ref()));
            }
            Ok(Event::Eof) | Err(_) => return text,
            _ => {}
        }
    }
}

/// After a `Start(Message)` event, accumulate one `EwsMessage` by reading
/// child elements until the matching `End(Message)`.
fn parse_message_block(reader: &mut Reader<&[u8]>) -> AppResult<EwsMessage> {
    let mut buf = Vec::new();
    let mut msg = EwsMessage {
        item_id: String::new(),
        change_key: String::new(),
        subject: String::new(),
        from_name: String::new(),
        from_email: String::new(),
        date_received: String::new(),
        is_read: false,
    };
    let mut captured_name = false;
    let mut captured_email = false;
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match local_name(&e).as_str() {
                "ItemId" => {
                    msg.item_id = attr_value(&e, "Id").unwrap_or_default();
                    msg.change_key = attr_value(&e, "ChangeKey").unwrap_or_default();
                }
                "Subject" => {
                    msg.subject = read_text_until_end(reader);
                }
                "DateTimeReceived" => {
                    msg.date_received = read_text_until_end(reader);
                }
                "IsRead" => {
                    msg.is_read = read_text_until_end(reader) == "true";
                }
                "Name" if !captured_name => {
                    msg.from_name = read_text_until_end(reader);
                    captured_name = true;
                }
                "EmailAddress" if !captured_email => {
                    msg.from_email = read_text_until_end(reader);
                    captured_email = true;
                }
                _ => {}
            },
            Ok(Event::End(e)) if local_name_bytes_eq(e.name().as_ref(), "Message") => {
                return Ok(msg);
            }
            Ok(Event::Eof) => return Ok(msg),
            Err(err) => {
                return Err(AppError::Internal(format!(
                    "EWS Message block parse error at position {}: {err}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }
}

/// Inside a `ToRecipients` / `CcRecipients` Start event, collect all
/// child `<EmailAddress>` text values and join them with ", ".
fn collect_recipient_emails(reader: &mut Reader<&[u8]>) -> AppResult<String> {
    let mut buf = Vec::new();
    let mut emails = Vec::new();
    // We're positioned right AFTER a Start("ToRecipients") / ("CcRecipients")
    // event, so depth starts at 1. Track depth to know when we exit.
    let mut depth = 1i32;
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if local_name_eq(&e, "EmailAddress") {
                    emails.push(read_text_until_end(reader));
                } else {
                    depth += 1;
                }
            }
            Ok(Event::Empty(_)) => {}
            Ok(Event::End(_)) => {
                depth -= 1;
                if depth == 0 {
                    return Ok(emails.join(", "));
                }
            }
            Ok(Event::Eof) => return Ok(emails.join(", ")),
            Err(err) => {
                return Err(AppError::Internal(format!(
                    "EWS recipients parse error at position {}: {err}",
                    reader.buffer_position()
                )));
            }
            _ => {}
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_xml_text_works_with_t_prefix() {
        let xml = r#"<t:Subject>Hello World</t:Subject>"#;
        assert_eq!(
            extract_xml_text(xml, "Subject").as_deref(),
            Some("Hello World")
        );
    }

    #[test]
    fn extract_xml_text_works_with_m_prefix() {
        let xml = r#"<m:MessageText>boom</m:MessageText>"#;
        assert_eq!(
            extract_xml_text(xml, "MessageText").as_deref(),
            Some("boom")
        );
    }

    #[test]
    fn extract_xml_text_unescapes_entities() {
        // Regression: previous substring impl returned raw entities. The new
        // quick-xml parser must decode &amp; / &lt; / &gt; / &quot; / &apos;.
        let xml = r#"<t:Subject>A &amp; B &lt;C&gt;</t:Subject>"#;
        assert_eq!(
            extract_xml_text(xml, "Subject").as_deref(),
            Some("A & B <C>")
        );
    }

    #[test]
    fn extract_xml_text_handles_cdata() {
        // CDATA should be preserved verbatim (not interpreted as XML).
        let xml = r#"<t:Body><![CDATA[<div>raw</div>]]></t:Body>"#;
        assert_eq!(
            extract_xml_text(xml, "Body").as_deref(),
            Some("<div>raw</div>")
        );
    }

    #[test]
    fn extract_attr_works() {
        let xml = r#"<t:ItemId Id="abc123" ChangeKey="xyz"/>"#;
        assert_eq!(extract_attr(xml, "ItemId", "Id").as_deref(), Some("abc123"));
        assert_eq!(
            extract_attr(xml, "ItemId", "ChangeKey").as_deref(),
            Some("xyz")
        );
    }

    #[test]
    fn extract_attr_unescapes_value() {
        let xml = r#"<t:Foo Val="a &amp; b"/>"#;
        assert_eq!(extract_attr(xml, "Foo", "Val").as_deref(), Some("a & b"));
    }

    #[test]
    fn extract_attr_handles_equals_in_value() {
        // base64-ish values often have trailing '=' which must survive parsing.
        let xml = r#"<t:ItemId Id="AAMk=" ChangeKey="CQA="/>"#;
        assert_eq!(extract_attr(xml, "ItemId", "Id").as_deref(), Some("AAMk="));
        assert_eq!(
            extract_attr(xml, "ItemId", "ChangeKey").as_deref(),
            Some("CQA=")
        );
    }

    #[test]
    fn parse_get_item_finds_itemid_through_nested_envelope() {
        // Strip down the GetItem failing case: verify just the ItemId path.
        let xml = r#"<m:GetItemResponse><m:ResponseMessages>
            <m:GetItemResponseMessage ResponseClass="Success">
              <m:Items><t:Message>
                <t:ItemId Id="X=" ChangeKey="Y="/>
                <t:Subject>s</t:Subject>
              </t:Message></m:Items>
            </m:GetItemResponseMessage>
          </m:ResponseMessages></m:GetItemResponse>"#;
        let d = parse_get_item_response(xml).unwrap();
        assert_eq!(
            d.item_id, "X=",
            "item_id extraction failed; got {:?}",
            d.item_id
        );
    }

    #[test]
    fn parse_find_items_empty() {
        let xml = r#"<soap:Envelope><soap:Body><m:FindItemResponse></m:FindItemResponse></soap:Body></soap:Envelope>"#;
        let result = parse_find_items_response(xml).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_find_items_parses_single_message() {
        let xml = r#"<soap:Envelope><soap:Body><m:FindItemResponse><m:ResponseMessages>
            <m:FindItemResponseMessage ResponseClass="Success">
              <m:RootFolder>
                <t:Items>
                  <t:Message>
                    <t:ItemId Id="AAMk=" ChangeKey="CQAA"/>
                    <t:Subject>Hola — acentos</t:Subject>
                    <t:DateTimeReceived>2026-04-21T15:00:00Z</t:DateTimeReceived>
                    <t:From><t:Mailbox>
                      <t:Name>Juan Pérez</t:Name>
                      <t:EmailAddress>juan@example.com</t:EmailAddress>
                    </t:Mailbox></t:From>
                    <t:IsRead>false</t:IsRead>
                  </t:Message>
                </t:Items>
              </m:RootFolder>
            </m:FindItemResponseMessage>
          </m:ResponseMessages></m:FindItemResponse></soap:Body></soap:Envelope>"#;
        let result = parse_find_items_response(xml).unwrap();
        assert_eq!(result.len(), 1);
        let m = &result[0];
        assert_eq!(m.item_id, "AAMk=");
        assert_eq!(m.change_key, "CQAA");
        assert_eq!(m.subject, "Hola — acentos");
        assert_eq!(m.from_name, "Juan Pérez");
        assert_eq!(m.from_email, "juan@example.com");
        assert_eq!(m.date_received, "2026-04-21T15:00:00Z");
        assert!(!m.is_read);
    }

    #[test]
    fn parse_get_item_extracts_body_and_recipients() {
        let xml = r#"<soap:Envelope><soap:Body><m:GetItemResponse><m:ResponseMessages>
            <m:GetItemResponseMessage ResponseClass="Success">
              <m:Items><t:Message>
                <t:ItemId Id="X=" ChangeKey="Y="/>
                <t:Subject>Re: Test</t:Subject>
                <t:DateTimeReceived>2026-04-21T15:00:00Z</t:DateTimeReceived>
                <t:Body BodyType="Text">Hola &amp; adiós</t:Body>
                <t:HasAttachments>true</t:HasAttachments>
                <t:From><t:Mailbox>
                  <t:Name>Alice</t:Name>
                  <t:EmailAddress>alice@x.com</t:EmailAddress>
                </t:Mailbox></t:From>
                <t:ToRecipients>
                  <t:Mailbox><t:EmailAddress>bob@x.com</t:EmailAddress></t:Mailbox>
                  <t:Mailbox><t:EmailAddress>carol@x.com</t:EmailAddress></t:Mailbox>
                </t:ToRecipients>
                <t:CcRecipients>
                  <t:Mailbox><t:EmailAddress>dan@x.com</t:EmailAddress></t:Mailbox>
                </t:CcRecipients>
                <t:IsRead>true</t:IsRead>
              </t:Message></m:Items>
            </m:GetItemResponseMessage>
          </m:ResponseMessages></m:GetItemResponse></soap:Body></soap:Envelope>"#;
        let d = parse_get_item_response(xml).unwrap();
        assert_eq!(d.item_id, "X=");
        assert_eq!(d.subject, "Re: Test");
        assert_eq!(d.from_name, "Alice");
        assert_eq!(d.from_email, "alice@x.com");
        assert_eq!(d.body_text, "Hola & adiós");
        assert_eq!(d.to, "bob@x.com, carol@x.com");
        assert_eq!(d.cc, "dan@x.com");
        assert!(d.is_read);
        assert!(d.has_attachments);
    }

    #[test]
    fn parse_get_item_surfaces_error_response() {
        let xml = r#"<m:GetItemResponse><m:ResponseMessages>
            <m:GetItemResponseMessage ResponseClass="Error">
              <m:MessageText>The specified object was not found.</m:MessageText>
              <m:ResponseCode>ErrorItemNotFound</m:ResponseCode>
            </m:GetItemResponseMessage>
          </m:ResponseMessages></m:GetItemResponse>"#;
        let err = parse_get_item_response(xml).unwrap_err();
        assert!(
            err.to_string()
                .contains("The specified object was not found")
        );
    }

    #[test]
    fn escape_xml_escapes_all_predefined_entities() {
        assert_eq!(escape_xml("&"), "&amp;");
        assert_eq!(escape_xml("<"), "&lt;");
        assert_eq!(escape_xml(">"), "&gt;");
        assert_eq!(escape_xml("\""), "&quot;");
        assert_eq!(escape_xml("'"), "&apos;");
        // Order: & must be escaped first so we don't double-escape
        assert_eq!(escape_xml("a&b<c"), "a&amp;b&lt;c");
    }

    #[test]
    fn render_mailboxes_escapes_addresses() {
        // Addresses with XML-special chars (shouldn't happen in practice, but
        // prevents injection if the caller passes malformed input).
        let addrs = vec!["a&b@example.com".to_owned()];
        let xml = render_mailboxes(&addrs);
        assert!(xml.contains("a&amp;b@example.com"));
        assert!(!xml.contains("a&b@example.com"));
    }

    #[test]
    fn distinguished_folder_id_maps_known_names() {
        assert_eq!(distinguished_folder_id("Inbox"), Some("inbox"));
        assert_eq!(distinguished_folder_id("archive"), Some("archive"));
        assert_eq!(distinguished_folder_id("Deleted Items"), Some("deleteditems"));
        assert_eq!(distinguished_folder_id("junk email"), Some("junkemail"));
        assert_eq!(distinguished_folder_id("Project Archive"), None);
    }

    #[test]
    fn parse_find_folder_extracts_id_and_name() {
        let xml = r#"<soap:Envelope><soap:Body><m:FindFolderResponse><m:ResponseMessages>
            <m:FindFolderResponseMessage ResponseClass="Success">
              <m:RootFolder>
                <t:Folders>
                  <t:Folder>
                    <t:FolderId Id="AAA=" ChangeKey="CQ="/>
                    <t:DisplayName>Project Archive</t:DisplayName>
                  </t:Folder>
                  <t:Folder>
                    <t:FolderId Id="BBB=" ChangeKey="CQ="/>
                    <t:DisplayName>連絡 — 古い</t:DisplayName>
                  </t:Folder>
                </t:Folders>
              </m:RootFolder>
            </m:FindFolderResponseMessage>
          </m:ResponseMessages></m:FindFolderResponse></soap:Body></soap:Envelope>"#;
        let folders = parse_find_folder_response(xml).unwrap();
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0], ("AAA=".to_owned(), "Project Archive".to_owned()));
        assert_eq!(folders[1], ("BBB=".to_owned(), "連絡 — 古い".to_owned()));
    }

    #[test]
    fn build_internet_headers_empty_when_no_threading() {
        assert_eq!(build_internet_headers(None, None), "");
    }

    #[test]
    fn build_internet_headers_includes_in_reply_to() {
        let headers = build_internet_headers(Some("<abc@example.com>"), None);
        assert!(headers.contains("<t:InternetMessageHeaders>"));
        assert!(headers.contains(r#"HeaderName="In-Reply-To""#));
        assert!(headers.contains("&lt;abc@example.com&gt;"));
        assert!(!headers.contains("References"));
    }

    #[test]
    fn build_internet_headers_includes_both_threading_headers() {
        let headers = build_internet_headers(Some("<a@x.com>"), Some("<a@x.com> <b@x.com>"));
        assert!(headers.contains("In-Reply-To"));
        assert!(headers.contains("References"));
        assert!(headers.contains("&lt;a@x.com&gt; &lt;b@x.com&gt;"));
    }
}
