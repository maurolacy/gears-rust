//! Metadata update — `PATCH /files/{id}`.

use std::collections::HashMap;

use time::OffsetDateTime;
use toolkit_security::SecurityContext;
use uuid::Uuid;

use file_storage_sdk::{CustomMetadataPatch, File};

use crate::domain::audit::AuditOperation;
use crate::domain::authz::actions;
use crate::domain::error::DomainError;
use crate::domain::policy::PolicyResolver;
use crate::domain::service::FileService;

impl FileService {
    // ── metadata update ────────────────────────────────────────────────────────

    /// `PATCH /files/{id}`: JSON-merge-patch the custom metadata and bump
    /// `meta_version`, optionally guarded by `If-Match-Metadata`.
    ///
    /// @cpt-cf-file-storage-fr-audit-trail
    pub async fn update_metadata(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        patch: CustomMetadataPatch,
        expected_meta_version: Option<i64>,
    ) -> Result<File, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        // @cpt-cf-file-storage-fr-metadata-limits
        // Compute what the resulting metadata will look like after this patch,
        // then validate against the effective policy.
        let policy = self
            .get_effective_policy_internal(ctx.subject_tenant_id(), file.owner_id)
            .await?;
        let existing = self.store.list_metadata(file_id).await?;
        // Build a map from existing entries and apply the patch (merge semantics).
        let mut merged: HashMap<String, String> =
            existing.into_iter().map(|e| (e.key, e.value)).collect();
        for (key, value) in &patch.entries {
            match value {
                Some(v) => {
                    merged.insert(key.clone(), v.clone());
                }
                None => {
                    merged.remove(key);
                }
            }
        }
        let result_pairs: Vec<(String, String)> = merged.into_iter().collect();
        PolicyResolver::check_metadata_limits(&policy, &result_pairs)?;

        // @cpt-cf-file-storage-fr-audit-trail
        let audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::PatchMetadata,
            serde_json::json!({ "expected_meta_version": expected_meta_version }),
        );

        // Apply the meta-version CAS and the patch in ONE transaction. The CAS
        // runs first, so a stale `expected_meta_version` aborts before any row
        // is touched and the rollback guarantees no partial metadata change is
        // committed (the optimistic-concurrency guard cannot be bypassed). The
        // per-key delete-then-insert upsert is also covered by the rollback, so
        // a failed insert can never leave a key permanently removed.
        let now = OffsetDateTime::now_utc();
        let bumped = self
            .store
            .patch_metadata_atomic(&scope, file_id, expected_meta_version, patch, now, audit)
            .await?;
        if !bumped {
            return Err(DomainError::precondition_failed(
                "metadata revision changed concurrently (If-Match-Metadata)",
            ));
        }
        self.store.require_file(&scope, file_id).await
    }
}
