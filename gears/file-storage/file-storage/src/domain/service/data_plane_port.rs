//! [`DataPlanePort`] implementation for [`FileService`].
//!
//! Implement the narrow data-plane port so `DataPlaneService` can hold
//! `Arc<dyn DataPlanePort>` instead of a direct `Arc<FileService>` reference.
//! This decouples `data_plane.rs` from the full `FileService` type (ISP).

use toolkit_security::SecurityContext;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::ports::DataPlanePort;
use crate::domain::service::FileService;
use crate::infra::backend::BackendRegistry;

#[async_trait::async_trait]
impl DataPlanePort for FileService {
    fn backends(&self) -> &BackendRegistry {
        &self.backends
    }

    async fn authorize_write(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
    ) -> Result<(), DomainError> {
        FileService::authorize_write(self, ctx, file_id).await
    }

    async fn get_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<Option<file_storage_sdk::FileVersion>, DomainError> {
        FileService::get_version(self, file_id, version_id).await
    }

    async fn finalize_upload(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        version_id: Uuid,
        size: i64,
        hash_value: Vec<u8>,
    ) -> Result<(), DomainError> {
        FileService::finalize_upload(self, ctx, file_id, version_id, size, hash_value).await
    }
}
