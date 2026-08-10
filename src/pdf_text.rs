//! PDF text extraction via the system `pdftotext` binary (poppler-utils).
//!
//! The pure-Rust `pdf_extract` crate silently returns empty/no text on PDFs
//! that `pdftotext` reads fine (verified live on both a TI datasheet and a
//! Japanese university PDF) — a real-world blind spot, not a hypothetical
//! one. There's no in-process fallback: if `pdftotext` isn't installed, this
//! errors out with an actionable message rather than pretending extraction
//! ran and silently returning nothing.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::errors::{AppError, AppResult};

/// Extract text from PDF bytes by piping them through `pdftotext -layout`.
///
/// # Errors
///
/// - `Internal` if `pdftotext` is not on `PATH` (names the `dnf install
///   poppler-utils` fix, since that's the package on this machine)
/// - `Internal` if the process can't be spawned, stdin can't be written, or
///   `pdftotext` exits non-zero
pub fn extract(bytes: &[u8]) -> AppResult<String> {
    let mut child = Command::new("pdftotext")
        .args(["-layout", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::Internal(
                    "pdftotext not found on PATH — install poppler-utils \
                     (e.g. `dnf install poppler-utils`) to enable PDF text extraction"
                        .to_owned(),
                )
            } else {
                AppError::Internal(format!("failed to spawn pdftotext: {e}"))
            }
        })?;

    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(bytes)
        .map_err(|e| AppError::Internal(format!("failed writing PDF bytes to pdftotext: {e}")))?;

    let output = child
        .wait_with_output()
        .map_err(|e| AppError::Internal(format!("failed reading pdftotext output: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Internal(format!(
            "pdftotext exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }

    String::from_utf8(output.stdout)
        .map_err(|e| AppError::Internal(format!("pdftotext output was not valid UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_cleanly_on_garbage_input() {
        // Not a real PDF, but pdftotext is on PATH in this dev/CI environment
        // (poppler-utils), so this exercises the "spawned but pdftotext
        // itself rejects the input" error path rather than the
        // binary-missing path.
        let result = extract(b"not a pdf");
        assert!(result.is_err());
    }
}
