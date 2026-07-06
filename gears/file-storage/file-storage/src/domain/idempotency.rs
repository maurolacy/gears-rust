//! Domain types for upload idempotency.
//!
//! @cpt-cf-file-storage-fr-upload-idempotency

use toolkit_macros::domain_model;
use uuid::Uuid;

/// The stored response for an idempotency key lookup.
/// Returned to a retrying caller unchanged.
#[domain_model]
#[derive(Debug, Clone)]
pub struct IdempotencyRecord {
    pub file_id: Uuid,
    /// The authenticated subject that created this record
    /// (`ctx.subject_id()` at insert time). The domain layer must verify this
    /// matches the replaying caller before handing back `response_body` —
    /// see `FileService::create_file`.
    pub subject_id: Uuid,
    /// HTTP status code of the original response (e.g. 201).
    pub response_status: u16,
    /// JSON-serialized `UploadTicketDto` body.
    pub response_body: String,
    pub response_etag: String,
}
