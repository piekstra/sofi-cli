//! `sfi documents …` — statements and tax forms (`documents/v1` profile).
//!
//! # Where these come from
//!
//! `GET /banking-service/api/public/v2/statements` answers a JSON array of
//! `{ statementDate, accountNumber:null, statementType:"COMBINED",
//! documentId, description }` (statements are **combined** across accounts —
//! `accountNumber` is always null). A statement PDF downloads from
//! `GET /banking-service/api/public/v2/statements/{documentId}`. See
//! docs/api.md §3.3. UNVERIFIED-LIVE.
//!
//! Tax forms (a 1099-INT at season) are **not** community-documented — no
//! project maps a tax-document endpoint — so `--type tax` is accepted but
//! currently matches nothing; wiring the tax endpoint is deferred to the
//! first owner-present live session (docs/api.md §3.3, §7).

use std::path::{Path, PathBuf};

use pk_cli_core::{CliError, Paged, RangeArgs};
use pk_cli_documents::{fs_safe, Document, DownloadBatch, SavedDocument};
use serde_json::Value;

use crate::client::STATEMENTS_PATH;
use crate::commands::{str_at, Ctx};

/// Accepted `--type` filter values.
const KNOWN_TYPES: [&str; 2] = ["statement", "tax"];

/// Validate a `--type` filter before it costs a request.
pub fn validate_type(kind: &str) -> Result<(), CliError> {
    if kind.is_empty() {
        return Err(CliError::Usage("--type needs a value".into()));
    }
    if KNOWN_TYPES.contains(&kind) {
        Ok(())
    } else {
        Err(CliError::Usage(format!(
            "`{kind}` is not a valid document type (known: {})",
            KNOWN_TYPES.join(", ")
        )))
    }
}

/// Map a statement row onto the profile DTO.
fn to_document(v: &Value) -> Option<Document> {
    let id = str_at(v, "documentId")?;
    let date = str_at(v, "statementDate");

    let mut doc = Document::new(id.clone(), display_name(v, date.as_deref()));
    doc.date = date.clone();
    doc.category = Some("statement".to_string());
    doc.file = Some(file_name(&id, date.as_deref()));
    Some(doc)
}

/// A human title. The portal ships a `description` ("Month YYYY Statement");
/// fall back to a date-stamped label when it doesn't.
fn display_name(v: &Value, date: Option<&str>) -> String {
    if let Some(desc) = str_at(v, "description") {
        return desc;
    }
    match date {
        Some(d) => format!("Statement {d}"),
        None => "Statement".to_string(),
    }
}

/// A filesystem-safe name for the saved PDF.
fn file_name(id: &str, date: Option<&str>) -> String {
    match date {
        // A real ISO date passes through fs_safe unchanged; anything else was
        // never a date.
        Some(d) => format!("{}-statement.pdf", fs_safe(d)),
        // Fall back to the id so two undated statements can't collide.
        None => format!("statement-{}.pdf", fs_safe(id)),
    }
}

/// The statement rows out of the collection response, which is a bare array.
fn statement_rows(body: &Value) -> Vec<Value> {
    body.as_array().cloned().unwrap_or_default()
}

fn fetch(ctx: &Ctx, range: &RangeArgs, kind: Option<&str>) -> Result<Vec<Document>, CliError> {
    let session = ctx.session()?;
    let body = ctx
        .sofi
        .get(&session, &ctx.sofi.url(STATEMENTS_PATH), &[])?;

    let mut docs: Vec<Document> = statement_rows(&body)
        .iter()
        .filter_map(to_document)
        .collect();

    // `--type tax` matches nothing until the tax endpoint is wired (see the
    // module note); `--type statement` keeps every row.
    if let Some(k) = kind {
        docs.retain(|d| d.category.as_deref() == Some(k));
    }

    // Newest first, per the profile contract.
    docs.sort_by(|a, b| b.date.cmp(&a.date));
    docs.retain(|d| date_in_range(d.date.as_deref(), range));
    if let Some(n) = range.limit {
        docs.truncate(n as usize);
    }
    Ok(docs)
}

/// The date-range rule `list` and `download --all` share.
fn date_in_range(date: Option<&str>, range: &RangeArgs) -> bool {
    match date {
        Some(date) => {
            crate::commands::date_within(date, range.since.as_deref(), range.until.as_deref())
        }
        // With no date there is nothing to compare, so an explicit range
        // excludes it rather than silently including it.
        None => range.since.is_none() && range.until.is_none(),
    }
}

pub fn list(ctx: &Ctx, range: &RangeArgs, kind: Option<&str>) -> Result<(), CliError> {
    let docs = fetch(ctx, range, kind)?;
    Paged::new("document", docs).emit(ctx.common.json);
    Ok(())
}

pub fn download(
    ctx: &Ctx,
    id: Option<&str>,
    output: Option<&Path>,
    all: bool,
    range: &RangeArgs,
    kind: Option<&str>,
) -> Result<(), CliError> {
    let session = ctx.session()?;

    if all {
        let docs = fetch(ctx, range, kind)?;
        let dir = output.unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir)
            .map_err(|e| CliError::Other(format!("creating {}: {e}", dir.display())))?;

        let mut saved = Vec::new();
        for doc in &docs {
            let bytes = ctx
                .sofi
                .get_document(&session, &statement_url(ctx, &doc.id))?;
            let path = dir.join(doc.file.clone().unwrap_or_else(|| fs_safe(&doc.id)));
            write_file(&path, &bytes)?;
            saved.push(SavedDocument::from_document(
                doc,
                path.display().to_string(),
                bytes.len() as u64,
            ));
        }
        let batch = DownloadBatch::new(dir.display().to_string(), saved);
        crate::commands::emit_self_tagged(&batch, ctx.common.json);
        return Ok(());
    }

    let wanted = id.expect("validated in main: an id or --all is required");
    // The listing carries the ids and dates; find the row so the saved file is
    // named the same way `list` would show it.
    let doc = fetch(ctx, &RangeArgs::default(), None)?
        .into_iter()
        .find(|d| d.id == wanted)
        .ok_or_else(|| {
            CliError::NotFound(format!(
                "no document `{wanted}` — run `sfi documents list` to see the ids"
            ))
        })?;

    let bytes = ctx
        .sofi
        .get_document(&session, &statement_url(ctx, &doc.id))?;

    // `-` means stdout, the one case that writes no file.
    if output.map(|p| p == Path::new("-")).unwrap_or(false) {
        use std::io::Write;
        return std::io::stdout()
            .write_all(&bytes)
            .map_err(|e| CliError::Other(format!("writing to stdout: {e}")));
    }

    let path: PathBuf = match output {
        Some(p) if p.is_dir() => p.join(doc.file.clone().unwrap_or_else(|| fs_safe(&doc.id))),
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(doc.file.clone().unwrap_or_else(|| fs_safe(&doc.id))),
    };
    write_file(&path, &bytes)?;

    let saved = SavedDocument::from_document(&doc, path.display().to_string(), bytes.len() as u64);
    crate::commands::emit_self_tagged(&saved, ctx.common.json);
    Ok(())
}

/// The download URL for a statement id. The id is provider-controlled and
/// joins a URL path, so it goes through `fs_safe` first — a crafted id can
/// neither traverse nor escape the statements path.
fn statement_url(ctx: &Ctx, id: &str) -> String {
    ctx.sofi.url(&format!("{STATEMENTS_PATH}/{}", fs_safe(id)))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    std::fs::write(path, bytes)
        .map_err(|e| CliError::Other(format!("writing {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn statement() -> Value {
        json!({
            "statementDate": "2026-06-30",
            "accountNumber": null,
            "statementType": "COMBINED",
            "documentId": "00000000-0000-4000-8000-000000000001",
            "description": "June 2026 Statement"
        })
    }

    #[test]
    fn a_statement_maps_onto_the_profile_dto() {
        let d = to_document(&statement()).unwrap();
        assert_eq!(d.category.as_deref(), Some("statement"));
        assert_eq!(d.date.as_deref(), Some("2026-06-30"));
        assert_eq!(d.name, "June 2026 Statement");
        assert_eq!(d.file.as_deref(), Some("2026-06-30-statement.pdf"));
    }

    #[test]
    fn a_statement_without_a_description_gets_a_dated_name() {
        let mut v = statement();
        v.as_object_mut().unwrap().remove("description");
        let d = to_document(&v).unwrap();
        assert_eq!(d.name, "Statement 2026-06-30");
    }

    #[test]
    fn a_row_without_a_document_id_is_dropped() {
        assert!(to_document(&json!({"statementDate": "2026-06-30"})).is_none());
    }

    #[test]
    fn statement_rows_are_pulled_from_the_bare_array() {
        assert_eq!(statement_rows(&json!([statement()])).len(), 1);
        assert!(statement_rows(&json!({})).is_empty());
    }

    #[test]
    fn the_type_filter_validates() {
        assert!(validate_type("statement").is_ok());
        assert!(validate_type("tax").is_ok());
        for wrong in ["1099", "invoice", ""] {
            assert_eq!(validate_type(wrong).unwrap_err().exit_code(), 2);
        }
    }

    /// A provider-controlled id becomes part of the download URL path, so it
    /// must not be able to traverse out of the statements endpoint.
    #[test]
    fn a_crafted_id_cannot_shape_the_path() {
        let name = file_name("../../etc/passwd", Some("2026-06-30"));
        assert!(!name.contains('/'), "{name}");
        assert!(!name.contains(".."), "{name}");
        // Undated fallback interpolates the id.
        let name = file_name("../../etc/passwd", None);
        assert!(!name.contains('/'), "{name}");
        assert!(!name.contains(".."), "{name}");
    }

    #[test]
    fn undated_documents_get_collision_free_filenames() {
        let a = file_name("id-a", None);
        let b = file_name("id-b", None);
        assert_ne!(a, b);
        assert!(a.ends_with(".pdf"));
    }

    #[test]
    fn the_date_range_excludes_undated_docs_only_when_a_range_is_set() {
        let no_range = RangeArgs::default();
        assert!(date_in_range(None, &no_range));
        let ranged = RangeArgs {
            limit: None,
            since: Some("2026-01-01".into()),
            until: None,
        };
        assert!(!date_in_range(None, &ranged));
        assert!(date_in_range(Some("2026-06-30"), &ranged));
        assert!(!date_in_range(Some("2025-12-31"), &ranged));
    }

    #[test]
    fn the_list_envelope_is_tagged() {
        let page = Paged::new("document", vec![to_document(&statement()).unwrap()]);
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "document-list/v1");
        assert_eq!(v["items"][0]["category"], "statement");
    }
}
