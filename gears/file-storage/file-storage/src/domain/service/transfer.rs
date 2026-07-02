//! Ownership transfer and backend best-effort blob delete helper.

use time::OffsetDateTime;
use toolkit_security::SecurityContext;
use uuid::Uuid;

use file_storage_sdk::File;

use crate::domain::audit::AuditOperation;
use crate::domain::authz::actions;
use crate::domain::error::DomainError;
use crate::domain::service::FileService;
use crate::infra::external_clients::UsageDelta;

impl FileService {
    // ── ownership transfer (P2-M5) ────────────────────────────────────────────

    /// `POST /files/{id}/transfer`: transfer ownership of a file to a new owner.
    ///
    /// The new owner's `owner_kind` and `owner_id` replace the current values.
    /// An audit row (`TransferOwnership`) and a file event (`file.owner_transferred`)
    /// are enqueued in the same transaction as the update.
    ///
    /// @cpt-cf-file-storage-fr-ownership-transfer
    /// @cpt-cf-file-storage-fr-usage-reporting
    /// @cpt-cf-file-storage-fr-file-events
    /// @cpt-cf-file-storage-fr-audit-trail
    pub async fn transfer_ownership(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        new_owner_kind: file_storage_sdk::OwnerKind,
        new_owner_id: Uuid,
    ) -> Result<File, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        let now = OffsetDateTime::now_utc();
        let tenant_id = file.tenant_id;
        let old_owner_id = file.owner_id;
        let new_owner_kind_str = new_owner_kind.as_str().to_owned();

        // @cpt-cf-file-storage-fr-audit-trail
        let audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::TransferOwnership,
            serde_json::json!({
                "from_owner_kind": file.owner_kind.as_str(),
                "from_owner_id": old_owner_id,
                "to_owner_kind": new_owner_kind_str,
                "to_owner_id": new_owner_id,
            }),
        );

        // @cpt-cf-file-storage-fr-file-events
        let event = Some(Self::make_file_event(
            tenant_id,
            new_owner_id,
            file_id,
            "file.owner_transferred",
            serde_json::json!({
                "from_owner_kind": file.owner_kind.as_str(),
                "from_owner_id": old_owner_id,
                "to_owner_kind": new_owner_kind_str,
                "to_owner_id": new_owner_id,
            }),
        ));

        let updated = self
            .store
            .transfer_ownership_atomic(
                &scope,
                file_id,
                &new_owner_kind_str,
                new_owner_id,
                now,
                audit,
                event,
            )
            .await?;

        if !updated {
            return Err(DomainError::file_not_found(file_id));
        }

        // @cpt-cf-file-storage-fr-usage-reporting
        // Debit old owner, credit new owner. Bytes are unchanged.
        let total_bytes: i64 = self
            .store
            .list_versions(file_id)
            .await?
            .iter()
            .filter(|v| v.status == file_storage_sdk::VersionStatus::Available)
            .map(|v| v.size)
            .sum();
        self.report_usage(UsageDelta {
            tenant_id,
            owner_id: old_owner_id,
            bytes_delta: -total_bytes,
            file_count_delta: -1,
        });
        self.report_usage(UsageDelta {
            tenant_id,
            owner_id: new_owner_id,
            bytes_delta: total_bytes,
            file_count_delta: 1,
        });

        self.store.require_file(&scope, file_id).await
    }

    /// Delete a backend blob, logging (not failing) on error. A failed delete
    /// degrades to an orphan reconciled by the P2 cleanup engine.
    pub(super) async fn best_effort_blob_delete(&self, backend_id: &str, path: &str) {
        let Ok(backend) = self.backends.get(backend_id) else {
            return;
        };
        if let Err(err) = backend.delete(path).await {
            tracing::warn!(?err, path, "best-effort backend delete failed");
        }
    }
}
