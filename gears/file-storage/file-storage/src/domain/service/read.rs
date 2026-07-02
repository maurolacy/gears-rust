//! Read-only file and metadata queries.

use toolkit_security::SecurityContext;
use uuid::Uuid;

use file_storage_sdk::{CustomMetadataEntry, File, OwnerFilter};

use crate::domain::authz::actions;
use crate::domain::error::DomainError;
use crate::domain::service::FileService;

impl FileService {
    // ── reads ─────────────────────────────────────────────────────────────────

    /// Get a file's metadata.
    pub async fn get_file(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
    ) -> Result<File, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let scope = self
            .authorizer
            .authorize(ctx, actions::READ, &file.gts_file_type, Some(file_id))
            .await?;
        self.store.require_file(&scope, file_id).await
    }

    /// Get a file plus its custom metadata.
    pub async fn get_file_with_metadata(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
    ) -> Result<(File, Vec<CustomMetadataEntry>), DomainError> {
        let file = self.get_file(ctx, file_id).await?;
        let meta = self.store.list_metadata(file_id).await?;
        Ok((file, meta))
    }

    /// List files for a mandatory owner filter, offset-paginated.
    pub async fn list_files(
        &self,
        ctx: &SecurityContext,
        owner: OwnerFilter,
        limit: Option<u64>,
        offset: u64,
    ) -> Result<Vec<File>, DomainError> {
        // Authorize (access gate), then always tenant-scope the query so the
        // tenant boundary holds regardless of the PDP's returned constraints.
        self.authorizer
            .authorize(ctx, actions::READ, "", None)
            .await?;
        let limit = limit
            .unwrap_or(self.cfg.default_page_size)
            .min(self.cfg.max_page_size);
        self.store
            .list_files(&Self::tenant_scope(ctx), owner, limit, offset)
            .await
    }

    // ── pub(crate) accessors for DataPlaneService ─────────────────────────────

    /// Fetch a single version by `(file_id, version_id)` — delegated to the
    /// data plane so it does not need to hold a direct `Store` reference.
    pub(crate) async fn get_version(
        &self,
        file_id: uuid::Uuid,
        version_id: uuid::Uuid,
    ) -> Result<Option<file_storage_sdk::FileVersion>, crate::domain::error::DomainError> {
        self.store.get_version(file_id, version_id).await
    }
}
