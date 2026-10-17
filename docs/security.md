# Security Considerations

This document outlines security features and considerations for the `mail-mcp` MCP server.

## TLS Enforcement

All IMAP connections require TLS encryption by default. Insecure connections are rejected.

### Configuration

```bash
# Per-account (default: true)
MAIL_IMAP_<ACCOUNT>_SECURE=true

# Common IMAP TLS ports
MAIL_IMAP_<ACCOUNT>_PORT=993   # IMAPS (implicit TLS)
```

### Behavior

- TLS certificate verification is enforced
- Hostname verification is performed
- Connection failures occur if certificates cannot be validated
- STARTTLS is not supported; use implicit TLS (IMAPS) on port 993

## Password Secrecy

Passwords are handled with strict secrecy guarantees:

### Storage

- Passwords are stored using Rust's `SecretString` type
- Passwords are never included in log output
- Passwords are never returned in tool responses

### Environment Variables

```bash
# Password in environment (never logged)
MAIL_IMAP_DEFAULT_PASS=your-app-password
```

### Best Practices

- Use app-specific passwords instead of account passwords when available
- Never commit `.env` files to version control
- Use secure credential managers for production deployments
- Rotate credentials periodically

## Write Operation Gating

Destructive operations are disabled by default and require explicit opt-in.

### Enabling Write Operations

```bash
MAIL_IMAP_WRITE_ENABLED=true
```

### Affected Tools

When `MAIL_IMAP_WRITE_ENABLED=false`, these tools return errors:
- `imap_update_message_flags` - Add/remove flags
- `imap_copy_message` - Copy messages
- `imap_move_message` - Move messages
- `imap_delete_message` - Delete messages

### Delete Confirmation

`imap_delete_message` requires explicit confirmation regardless of write gating:

```json
{
  "account_id": "default",
  "message_id": "imap:default:INBOX:12345:42",
  "confirm": true  // Required literal true
}
```

## Output Bounding

All potentially large outputs are bounded to prevent resource exhaustion.

### Body Text

```json
{
  "body_max_chars": 2000  // Range: 100..20000, default: 2000
}
```

### HTML Output

- HTML is sanitized using `ammonia` before return
- Potentially dangerous tags and attributes are stripped
- CSS styles are removed
- JavaScript is completely removed

### Attachment Text Extraction

```json
{
  "extract_attachment_text": true,
  "attachment_text_max_chars": 10000  // Range: 100..50000, default: 10000
}
```

### Raw Message Source

```json
{
  "max_bytes": 200000  // Range: 1024..1000000, default: 200000
}
```

### Attachment Size Limits

PDF text extraction is limited to attachments ≤ 5MB. Larger attachments are skipped but do not fail the tool call.

## Input Validation

All inputs are validated before IMAP operations:

### Length Bounds

- `query`, `from`, `to`, `subject`: 1..256 characters
- `account_id`: 1..64 characters, pattern `^[A-Za-z0-9_-]+$`
- `mailbox`: 1..256 characters
- `limit`: 1..50 messages

### Content Sanitization

- Search text fields must not contain ASCII control characters
- Mailbox names must not contain ASCII control characters

### Search Result Limits

Searches matching more than 20,000 messages are rejected:

```
Error: invalid input: search matched 25000 messages; narrow filters to at most 20000 results
```

Resolution: Add tighter filters (`last_days`, `from`, `subject`, date ranges).

## Timeout Protection

All network operations have configurable timeouts:

```bash
# Connection establishment
MAIL_IMAP_CONNECT_TIMEOUT_MS=30000      # 30 seconds

# Server greeting
MAIL_IMAP_GREETING_TIMEOUT_MS=15000     # 15 seconds

# Socket operations (idle, read, write)
MAIL_IMAP_SOCKET_TIMEOUT_MS=300000     # 5 minutes
```

Timeouts prevent indefinite hanging and ensure the server remains responsive.

## Outbound Attachment Scope

Send tools accept `file_path` attachments that the server reads from local
disk. Without a restriction, a prompt-injected model could attach any file the
server process can read (SSH keys, cloud credentials, `.env` files).

Set `MAIL_ATTACHMENT_UPLOAD_DIR` to confine `file_path` attachments to one
directory:

```bash
MAIL_ATTACHMENT_UPLOAD_DIR=/Users/me/mail-outbox
```

- The directory must exist; the server refuses to start otherwise.
- Each `file_path` is canonicalized (`..` and symlinks resolved) and must land
  inside the directory. Symlinks pointing outside are rejected.
- Missing and out-of-scope files return the same error, so the check cannot be
  used to probe for file existence.
- When unset, any readable file may be attached (backwards-compatible default).

This limits what the server itself reads. `content_base64` attachments are
still accepted, so a model that can read files through *other* tools could
still inline them — scope those tools separately.

## Logging and Auditing

### Log Redaction

- Passwords are never logged
- Secret-like keys (`*_PASS`, `*_TOKEN`, `*_KEY`) are redacted in logs
- Message bodies and attachments are not logged

### Response Metadata

All tool responses include metadata for auditing:

```json
{
  "meta": {
    "now_utc": "2024-02-26T10:30:45.123Z",
    "duration_ms": 245
  }
}
```

## Security Best Practices

### For End Users

1. **Use app passwords**: For Gmail, Outlook, and other services, use app-specific passwords rather than account passwords
2. **Enable 2FA**: Require two-factor authentication on email accounts
3. **Review access logs**: Periodically review email account access logs for suspicious activity
4. **Restrict write access**: Keep `MAIL_IMAP_WRITE_ENABLED=false` unless needed
5. **Secure .env files**: Ensure `.env` files have restrictive permissions (`chmod 600 .env`)

### For Operators

1. **Principle of least privilege**: Run the server with minimal required permissions
2. **Network isolation**: Deploy in isolated network segments where possible
3. **Regular updates**: Keep dependencies and the server updated
4. **Audit logs**: Monitor server logs for unusual patterns or errors
5. **Rate limiting**: Consider implementing additional rate limiting at the infrastructure layer

### For Development

1. **Security review**: Changes to security-sensitive code should be reviewed
2. **Dependency auditing**: Regularly audit dependencies for vulnerabilities
3. **Test boundaries**: Test input validation and output bounding thoroughly
4. **Secret management**: Never hardcode credentials in code or tests

## Known Limitations

1. **No STARTTLS support**: Only implicit TLS (IMAPS) is supported
2. **No certificate pinning**: Certificates are validated per standard PKI; custom CA chains are not supported
3. **No client authentication**: Client certificates are not supported
4. **No encryption at rest**: Credentials are in memory only; disk encryption is the user's responsibility
