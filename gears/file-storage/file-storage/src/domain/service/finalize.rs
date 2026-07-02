//! Upload finalization, authorization preflight, and the bind CAS.

use time::OffsetDateTime;
use toolkit_security::SecurityContext;
use uuid::Uuid;

use file_storage_sdk::File;

use crate::domain::audit::AuditOperation;
use crate::domain::authz::actions;
use crate::domain::error::DomainError;
use crate::domain::etag;
use crate::domain::policy::PolicyResolver;
use crate::domain::service::{FileService, VersionRef};
use crate::infra::signed_url::{Op, UploadConstraints};

impl FileService {
    /// Authorize a write to `file_id` (WRITE action) without mutating anything.
    /// The data plane calls this as a preflight **before** writing bytes to a
    /// backend, so a rejected request never persists/overwrites blob content
    /// (the post-write `finalize_upload` re-checks as defense-in-depth).
    pub async fn authorize_write(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
    ) -> Result<(), DomainError> {
        let file = self
            .store
            .require_file(&Self::tenant_scope(ctx), file_id)
            .await?;
        self.authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;
        Ok(())
    }

    /// Record an uploaded version's size+hash and mark it available. Called by
    /// the sidecar after streaming bytes to the backend (write action).
    ///
    /// @cpt-cf-file-storage-fr-audit-trail
    pub async fn finalize_upload(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        version_id: Uuid,
        size: i64,
        hash_value: Vec<u8>,
    ) -> Result<(), DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let _scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        // @cpt-cf-file-storage-fr-size-limits-policy
        // Defense-in-depth size check: re-enforce the policy size ceiling at
        // finalization time even though the sidecar already checked the
        // upload constraint in the signed URL.
        let version = self.store.get_version(file_id, version_id).await?;
        let (version_mime, backend_id) = version.as_ref().map_or_else(
            || ("application/octet-stream".to_owned(), String::new()),
            |v| (v.mime_type.clone(), v.backend_id.clone()),
        );
        let policy = self
            .get_effective_policy_internal(ctx.subject_tenant_id(), file.owner_id)
            .await?;
        let backend = if backend_id.is_empty() {
            self.backends.default_backend()
        } else {
            self.backends.get(&backend_id)?
        };
        let effective_max = PolicyResolver::compute_effective_max_bytes(
            &policy,
            &version_mime,
            backend.capabilities().max_size_bytes,
        );
        if let Some(limit) = effective_max
            && size > 0
            && size.cast_unsigned() > limit
        {
            return Err(DomainError::policy_size_exceeded(
                limit,
                "policy size limit",
            ));
        }

        // @cpt-cf-file-storage-fr-audit-trail
        let audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::FinalizeVersion,
            serde_json::json!({ "version_id": version_id, "size": size }),
        );

        let ok = self
            .store
            .finalize_version(file_id, version_id, size, hash_value, audit)
            .await?;
        if !ok {
            return Err(DomainError::version_not_found(file_id, version_id));
        }
        Ok(())
    }

    /// `POST /files/{id}/bind`: swap the content pointer to `version_id` under
    /// optimistic CAS guarded by the `If-Match` content ETag. Returns the
    /// updated file; `412` on conflict (re-read the ETag and rebind).
    ///
    /// `if_match` is the opaque content ETag (or `*`, or `None` for the first
    /// bind). The server recomputes the current ETag and compares — it never
    /// reverses the ETag back to a `content_id`.
    ///
    /// @cpt-cf-file-storage-fr-audit-trail
    pub async fn bind(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        version_id: Uuid,
        if_match: Option<&str>,
    ) -> Result<File, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        // The version must exist and be available.
        let version = self
            .store
            .get_version(file_id, version_id)
            .await?
            .ok_or_else(|| DomainError::version_not_found(file_id, version_id))?;
        if version.status != file_storage_sdk::VersionStatus::Available {
            return Err(DomainError::conflict(
                "cannot bind a version whose upload has not been finalized",
            ));
        }

        // Validate the If-Match precondition against the current content ETag.
        let expected_content_id = file.content_id;
        let current_etag = expected_content_id.map(|c| etag::content_etag(file_id, c));
        match if_match {
            // The first bind (no content yet) may omit If-Match; rebinding
            // already-bound content MUST carry it, otherwise the advertised
            // conditional update degrades into an unconditional overwrite.
            None => {
                if expected_content_id.is_some() {
                    return Err(DomainError::precondition_failed(
                        "If-Match is required to rebind already-bound content",
                    ));
                }
            }
            Some(m) => {
                let m = m.trim();
                if m != "*" && Some(m) != current_etag.as_deref() {
                    return Err(DomainError::precondition_failed(
                        "If-Match does not match the current content ETag",
                    ));
                }
            }
        }

        // @cpt-cf-file-storage-fr-audit-trail
        let audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::PatchContent,
            serde_json::json!({ "version_id": version_id }),
        );

        // @cpt-cf-file-storage-fr-file-events
        let event = Some(Self::make_file_event(
            file.tenant_id,
            file.owner_id,
            file_id,
            "file.content_updated",
            serde_json::json!({ "version_id": version_id }),
        ));

        // Swap the content pointer (CAS) and flip `is_current` in a SINGLE
        // transaction so `files.content_id` and `file_versions.is_current` can
        // never diverge if a later write fails (DESIGN §3.7 bind invariant).
        let now = OffsetDateTime::now_utc();
        let swapped = self
            .store
            .bind_atomic_with_event(
                &scope,
                file_id,
                expected_content_id,
                version_id,
                now,
                audit,
                event,
            )
            .await?;
        if !swapped {
            return Err(DomainError::precondition_failed(
                "content pointer changed concurrently; re-read the ETag and rebind",
            ));
        }

        self.store.require_file(&scope, file_id).await
    }

    /// Issue a signed download URL for a version (shared helper used by
    /// `versioning.rs`). Visibility is `pub(super)` so only sibling modules use it.
    pub(super) fn build_download_url(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        backend_id: String,
        backend_path: String,
    ) -> Result<String, DomainError> {
        self.sign_url(
            Op::Get,
            &VersionRef {
                file_id,
                version_id,
                backend_id,
                backend_path,
            },
            UploadConstraints::default(),
        )
    }
}
