//! Unit tests for the data-plane sidecar binary ([`super`]).
//!
//! Kept in a sibling `_tests.rs` file per the `de1101_tests_in_separate_files`
//! repo lint. Linked into `sidecar.rs` via
//! `#[path = "sidecar_tests.rs"] mod tests;`, so the module sees `sidecar.rs`
//! as `super`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;
use uuid::Uuid;

use file_storage::infra::backend::{
    BackendRegistry, InMemoryBackend, LocalFsBackend, StorageBackend,
};
use file_storage::infra::metrics::NoopMetrics;
use file_storage::infra::signed_url::{Claims, Issuer, MultipartClaims, Op, UploadConstraints};

use super::{
    DEFAULT_MAX_BODY_BYTES, SidecarState, build_router, finalize_with_control_plane,
    write_multipart_part_native, write_multipart_part_offset_object,
};

fn test_state() -> SidecarState {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backends = BackendRegistry::new(
        vec![Arc::new(InMemoryBackend::new("test")) as Arc<dyn StorageBackend>],
        "test",
    )
    .expect("build test backend registry");
    SidecarState {
        verifier: std::sync::Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
    }
}

#[tokio::test]
async fn sidecar_healthz_returns_200() {
    let router = build_router(test_state(), DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get("/healthz")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(response.status(), StatusCode::OK);
}

/// Regression guard for step 1.2(a): a body over axum's blanket 2 MiB
/// `DefaultBodyLimit` must reach the handler (and be rejected there for an
/// unrelated reason — missing token) rather than being rejected by the
/// transport layer with a bare `413` before any handler code runs.
#[tokio::test]
async fn sidecar_body_limit_allows_bodies_over_2mib() {
    let router = build_router(test_state(), DEFAULT_MAX_BODY_BYTES);
    let body = vec![0u8; 3 * 1024 * 1024]; // 3 MiB, over axum's 2 MiB default.
    let response = router
        .oneshot(
            Request::put(
                "/api/file-storage-data/v1/upload/\
                 00000000-0000-0000-0000-000000000000/\
                 00000000-0000-0000-0000-000000000000",
            )
            .body(Body::from(body))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    // No `fs-token` supplied: the handler itself rejects with 401. If the
    // `DefaultBodyLimit` layer were still capped at 2 MiB, this would be a
    // `413` from axum's extractor instead, before `extract_token` ever runs.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// P2 1.5: a control plane that accepts the TCP connection but never
/// responds must not hang the finalize callback indefinitely — each
/// attempt's client-configured `reqwest` timeout must trip and, since a
/// timeout is itself retried up to `CALLBACK_MAX_ATTEMPTS` times, the
/// call must still return `Err` well within the test's own budget (a
/// small per-attempt timeout keeps `attempts * timeout + retry delays`
/// comfortably under that budget). The `tokio::time::timeout` wrapping
/// the call belongs to the *test*, not production: it exists so this
/// test fails fast (instead of hanging the suite) if the production
/// timeout regresses.
#[tokio::test]
async fn finalize_callback_times_out_within_configured_bound() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock listener");
    let addr = listener.local_addr().expect("local addr");

    // Accept connections but never write a response, so the client's
    // read times out rather than erroring immediately.
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(150))
        .connect_timeout(Duration::from_millis(150))
        .build()
        .expect("client build");
    let mut state = test_state();
    state.http = http;
    state.control_base_url = format!("http://{addr}");

    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        finalize_with_control_plane(
            &state,
            "dummy-token",
            "test-request-id",
            Uuid::nil(),
            Uuid::nil(),
            0,
            "deadbeef",
        ),
    )
    .await
    .expect(
        "finalize_with_control_plane must return within the test's own timeout budget \
         (production timeout regressed if this fires)",
    );

    assert!(
        outcome.is_err(),
        "finalize must fail when the control plane never responds"
    );
}

/// P2 1.5: a transient connection-refused failure on the first attempt
/// must be retried, and the callback must succeed once the control plane
/// becomes reachable — without the caller ever seeing the transient
/// failure.
#[tokio::test]
async fn finalize_callback_retries_on_connection_refused_then_succeeds() {
    // Reserve a free port, then release it immediately: connecting to it
    // while nothing is listening reliably yields ECONNREFUSED on loopback.
    let probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe listener");
    let addr = probe.local_addr().expect("local addr");
    drop(probe);

    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_clone = Arc::clone(&accepted);

    // Give the first (connection-refused) attempt time to fail before a
    // real listener claims the same address and answers 200 OK.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let listener = TcpListener::bind(addr)
            .await
            .expect("bind mock control plane");
        if let Ok((mut stream, _)) = listener.accept().await {
            accepted_clone.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            if stream.read(&mut buf).await.is_ok() {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .ok();
            }
        }
    });

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .expect("client build");
    let mut state = test_state();
    state.http = http;
    state.control_base_url = format!("http://{addr}");

    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        finalize_with_control_plane(
            &state,
            "dummy-token",
            "test-request-id",
            Uuid::nil(),
            Uuid::nil(),
            0,
            "deadbeef",
        ),
    )
    .await
    .expect("finalize_with_control_plane must return within the test's own timeout budget");

    assert!(
        outcome.is_ok(),
        "finalize must succeed once it retries past the connection-refused attempt"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "exactly one connection should reach the mock control plane (the retry)"
    );
}

/// Build a `SidecarState` wired to a fresh `InMemoryBackend`, plus the
/// `Issuer` that must be used to mint tokens the state's verifier accepts
/// (P2 1.11's download tests need to mint real `op = get` tokens, unlike
/// the pre-existing tests above which only exercise the missing-token
/// path).
fn test_download_state() -> (SidecarState, Issuer, Arc<InMemoryBackend>) {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backend = Arc::new(InMemoryBackend::new("test"));
    let backends = BackendRegistry::new(
        vec![Arc::clone(&backend) as Arc<dyn StorageBackend>],
        "test",
    )
    .expect("build test backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
    };
    (state, issuer, backend)
}

/// Mint a signed `op = get` download token for `(file_id, version_id, backend_path)`.
fn download_token(issuer: &Issuer, file_id: Uuid, version_id: Uuid, backend_path: &str) -> String {
    let claims = Claims {
        op: Op::Get,
        file_id,
        version_id,
        backend_id: "test".to_owned(),
        backend_path: backend_path.to_owned(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
    };
    issuer
        .issue(claims, OffsetDateTime::now_utc())
        .expect("issue download token")
}

/// P2 1.11: a sub-range `GET` must come back as `206` with a correct
/// `Content-Range: bytes {start}-{end}/{total}` and the exact byte slice
/// requested — previously the sidecar returned `206` with no
/// `Content-Range` at all, which corrupts resumable-download reassembly.
#[tokio::test]
async fn download_range_response_includes_content_range() {
    let (state, issuer, backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    backend
        .put(&path, bytes::Bytes::from_static(b"hello world"))
        .await
        .expect("seed blob");
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .header(header::RANGE, "bytes=0-4")
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let content_range = response
        .headers()
        .get(header::CONTENT_RANGE)
        .expect("Content-Range header present on 206")
        .to_str()
        .expect("valid header value");
    assert_eq!(content_range, "bytes 0-4/11");

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(&body[..], b"hello");
}

/// P2 1.11: a range request against a blob that was never written must be
/// `404`, not the pre-fix behavior of folding every backend error
/// (including a missing blob) into `416`.
#[tokio::test]
async fn download_missing_blob_returns_404_not_416() {
    let (state, issuer, _backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}"); // never written
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .header(header::RANGE, "bytes=0-4")
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a missing blob must be 404, not 416"
    );
}

/// P2 1.11: a range past the end of a blob that *does* exist is a genuine
/// RFC 9110 §14.4 unsatisfiable-range condition — `416` with a
/// `Content-Range: bytes */{total}` header, distinct from the
/// missing-blob `404` case above.
#[tokio::test]
async fn download_unsatisfiable_range_returns_416_with_content_range() {
    let (state, issuer, backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    backend
        .put(&path, bytes::Bytes::from_static(b"hello world")) // 11 bytes
        .await
        .expect("seed blob");
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .header(header::RANGE, "bytes=100-200")
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    let content_range = response
        .headers()
        .get(header::CONTENT_RANGE)
        .expect("Content-Range header present on 416")
        .to_str()
        .expect("valid header value");
    assert_eq!(content_range, "bytes */11");
}

/// P2 1.11: when the control plane's finalize endpoint returns an error
/// response, the sidecar must not forward the raw upstream status/body or
/// the internal control-plane address to the uploading client — only the
/// server-side `tracing::error!` (asserted indirectly here by checking
/// what does *not* appear in the client-facing body) may carry that
/// detail.
#[tokio::test]
async fn finalize_failure_does_not_leak_control_plane_url() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock control plane");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            if stream.read(&mut buf).await.is_ok() {
                let body = "internal-upstream-secret-detail";
                let response = format!(
                    "HTTP/1.1 500 Internal Server Error\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.ok();
            }
        }
    });

    let mut state = test_state();
    state.control_base_url = format!("http://{addr}");

    let outcome = finalize_with_control_plane(
        &state,
        "dummy-token",
        "test-request-id",
        Uuid::nil(),
        Uuid::nil(),
        0,
        "deadbeef",
    )
    .await;

    let Err(response) = outcome else {
        panic!("finalize must fail when the control plane returns an error status");
    };
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    let body_text = String::from_utf8_lossy(&body_bytes).to_lowercase();

    assert!(
        !body_text.contains("internal-upstream-secret-detail"),
        "client-facing body must not leak the upstream error body: {body_text}"
    );
    assert!(
        !body_text.contains(&addr.to_string()),
        "client-facing body must not leak the control-plane address: {body_text}"
    );
    assert!(
        !body_text.contains("500"),
        "client-facing body must not leak the raw upstream HTTP status: {body_text}"
    );
}

/// Mint a signed `op = put` upload token for `(file_id, version_id, backend_id, backend_path)`.
fn upload_token(
    issuer: &Issuer,
    file_id: Uuid,
    version_id: Uuid,
    backend_id: &str,
    backend_path: &str,
) -> String {
    let claims = Claims {
        op: Op::Put,
        file_id,
        version_id,
        backend_id: backend_id.to_owned(),
        backend_path: backend_path.to_owned(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
    };
    issuer
        .issue(claims, OffsetDateTime::now_utc())
        .expect("issue upload token")
}

/// Mint a signed `op = multipart_part` token.
#[allow(clippy::too_many_arguments)]
fn multipart_part_token(
    issuer: &Issuer,
    file_id: Uuid,
    version_id: Uuid,
    backend_id: &str,
    backend_path: &str,
    upload_id: Uuid,
    part_number: u32,
    offset: u64,
    size: u64,
    backend_handle: &str,
) -> String {
    let claims = Claims {
        op: Op::MultipartPart,
        file_id,
        version_id,
        backend_id: backend_id.to_owned(),
        backend_path: backend_path.to_owned(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims {
            upload_id,
            part_number,
            offset,
            size,
            backend_handle: backend_handle.to_owned(),
        },
        request_id: "test-request-id".to_owned(),
    };
    issuer
        .issue(claims, OffsetDateTime::now_utc())
        .expect("issue multipart part token")
}

/// P2 1.7 Stage 6 regression: `upload_multipart_part` must dispatch to the
/// backend's own `upload_part` (native multipart) for a
/// `multipart_native` backend, instead of unconditionally falling back to
/// the local-fs-style offset-object model. That bug was silent until the
/// S3 e2e suite (`testing/e2e/gears/file_storage/lifecycle_s3/`) surfaced
/// it: `CompleteMultipartUpload` 500s against a real S3-compatible
/// endpoint because no part was ever uploaded via a real `UploadPart`
/// call. `InMemoryBackend` is `multipart_native: true` too, so this
/// regression is caught here without needing a live S3 test double: if
/// `upload_multipart_part` used the offset-object fallback instead, the
/// final `complete_multipart` call below would fail (zero real parts
/// would exist in the backend's native multipart session).
#[tokio::test]
async fn sidecar_multipart_native_backend_dispatches_to_upload_part() {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backend = Arc::new(InMemoryBackend::new("mem"));
    let backends =
        BackendRegistry::new(vec![Arc::clone(&backend) as Arc<dyn StorageBackend>], "mem")
            .expect("build test backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
    };

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let backend_path = format!("/{file_id}/{version_id}");
    let upload_id = Uuid::now_v7();

    // Mirrors `initiate_multipart_upload` (domain service): call the
    // backend's own `initiate_multipart` up front and mint each per-part
    // token with the resulting handle (`MultipartClaims::backend_handle`).
    let backend_handle = backend
        .initiate_multipart(&backend_path)
        .await
        .expect("initiate native multipart session");

    let part1 = b"first-part-bytes".to_vec();
    let part2 = b"second-part-payload".to_vec();

    let token1 = multipart_part_token(
        &issuer,
        file_id,
        version_id,
        "mem",
        &backend_path,
        upload_id,
        1,
        0,
        part1.len() as u64,
        &backend_handle,
    );
    let token2 = multipart_part_token(
        &issuer,
        file_id,
        version_id,
        "mem",
        &backend_path,
        upload_id,
        2,
        part1.len() as u64,
        part2.len() as u64,
        &backend_handle,
    );

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);

    let resp1 = router
        .clone()
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/multipart/{file_id}/{version_id}/parts/1?fs-token={token1}"
            ))
            .body(Body::from(part1.clone()))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(resp1.status(), StatusCode::OK, "part 1 PUT must succeed");
    let resp1_body = axum::body::to_bytes(resp1.into_body(), usize::MAX)
        .await
        .expect("read part 1 response body");
    let resp1_json: serde_json::Value =
        serde_json::from_slice(&resp1_body).expect("part 1 response is JSON");
    let etag1 = resp1_json["etag"]
        .as_str()
        .expect("part 1 response has an etag")
        .to_owned();

    let resp2 = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/multipart/{file_id}/{version_id}/parts/2?fs-token={token2}"
            ))
            .body(Body::from(part2.clone()))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(resp2.status(), StatusCode::OK, "part 2 PUT must succeed");
    let resp2_body = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .expect("read part 2 response body");
    let resp2_json: serde_json::Value =
        serde_json::from_slice(&resp2_body).expect("part 2 response is JSON");
    let etag2 = resp2_json["etag"]
        .as_str()
        .expect("part 2 response has an etag")
        .to_owned();

    // Complete the native multipart session directly against the
    // backend (mirrors what `complete_multipart_upload` does
    // server-side) — this only succeeds if both parts above actually
    // landed via `upload_part`, proving the dispatch fix. ADR-0006:
    // `complete_multipart` takes `(part_number, offset, part_hash, etag)`
    // and returns the offset-manifest + its root.
    let hash1 = file_storage::infra::content::hash::digest_to_array(
        file_storage::infra::content::hash::sha256(&part1),
    );
    let hash2 = file_storage::infra::content::hash::digest_to_array(
        file_storage::infra::content::hash::sha256(&part2),
    );
    let (manifest, root) = backend
        .complete_multipart(
            &backend_path,
            &backend_handle,
            &[(1, 0, hash1, etag1), (2, part1.len() as u64, hash2, etag2)],
        )
        .await
        .expect("complete native multipart session - both parts must be real");

    let assembled = backend
        .get(&backend_path)
        .await
        .expect("read assembled object");
    let mut expected = part1.clone();
    expected.extend_from_slice(&part2);
    assert_eq!(
        &assembled[..],
        &expected[..],
        "assembled object must be the exact concatenation of the two parts"
    );

    // The returned root is the offset-manifest composite (ADR-0006 mode 2),
    // independently reproducible from the per-part digests/offsets.
    let expected_manifest = file_storage::infra::content::hash_mode::Manifest::new(vec![
        file_storage::infra::content::hash_mode::ManifestEntry {
            offset: 0,
            digest: hash1,
        },
        file_storage::infra::content::hash_mode::ManifestEntry {
            offset: part1.len() as u64,
            digest: hash2,
        },
    ])
    .unwrap();
    assert_eq!(
        manifest.to_wire_string(),
        expected_manifest.to_wire_string()
    );
    assert_eq!(
        root,
        expected_manifest.root(),
        "complete_multipart's returned root must be sha256(manifest)"
    );
}

/// Review nitpick fix (PR #4184): an *undersized* multipart part
/// (client streamed fewer bytes than the token's `size` claim) is a
/// client mismatch — `400 Bad Request` — not `413 Payload Too Large`
/// (413 is reserved for a body that *exceeds* a limit, which the
/// mid-stream guard above already catches). Covers the `multipart_native`
/// write path (`write_multipart_part_native`).
#[tokio::test]
async fn write_multipart_part_native_undersized_returns_400() {
    let backend = InMemoryBackend::new("mem");
    let backend_path = "/undersized-native";
    let backend_handle = backend
        .initiate_multipart(backend_path)
        .await
        .expect("initiate native multipart session");
    let claims = Claims {
        op: Op::MultipartPart,
        file_id: Uuid::now_v7(),
        version_id: Uuid::now_v7(),
        backend_id: "mem".to_owned(),
        backend_path: backend_path.to_owned(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims {
            upload_id: Uuid::now_v7(),
            part_number: 1,
            offset: 0,
            size: 10,
            backend_handle,
        },
        request_id: "test-request-id".to_owned(),
    };

    let err = write_multipart_part_native(&backend, &claims, 1, Body::from(b"short".to_vec()))
        .await
        .expect_err("undersized part must be rejected");
    assert_eq!(
        err.status(),
        StatusCode::BAD_REQUEST,
        "undersized part is a client size mismatch, not an over-limit body"
    );
}

/// Same fix as above, for the non-native offset-object write path
/// (`write_multipart_part_offset_object`, e.g. `LocalFsBackend`).
#[tokio::test]
async fn write_multipart_part_offset_object_undersized_returns_400() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let backend = LocalFsBackend::new("local-fs", dir.path());
    let claims = Claims {
        op: Op::MultipartPart,
        file_id: Uuid::now_v7(),
        version_id: Uuid::now_v7(),
        backend_id: "local-fs".to_owned(),
        backend_path: "/undersized-offset".to_owned(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims {
            upload_id: Uuid::now_v7(),
            part_number: 1,
            offset: 0,
            size: 10,
            backend_handle: String::new(),
        },
        request_id: "test-request-id".to_owned(),
    };

    let err =
        write_multipart_part_offset_object(&backend, &claims, 1, Body::from(b"short".to_vec()))
            .await
            .expect_err("undersized part must be rejected");
    assert_eq!(
        err.status(),
        StatusCode::BAD_REQUEST,
        "undersized part is a client size mismatch, not an over-limit body"
    );
}

/// Stage 5 regression test (P2 1.7.2): the sidecar must dispatch each
/// upload to the backend named by the verified token's `claims.backend_id`
/// — not always the same hardcoded backend, which was the bug this stage
/// fixes (`SidecarState` previously held a single `backend` field, ignored
/// by every handler's `claims.backend_id`). Uses two differently-tagged
/// in-memory backends so no S3 test double is needed.
#[tokio::test]
async fn sidecar_resolves_backend_by_claims_backend_id() {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backend_a = Arc::new(InMemoryBackend::new("local-fs"));
    let backend_b = Arc::new(InMemoryBackend::new("other"));
    let backends = BackendRegistry::new(
        vec![
            Arc::clone(&backend_a) as Arc<dyn StorageBackend>,
            Arc::clone(&backend_b) as Arc<dyn StorageBackend>,
        ],
        "local-fs",
    )
    .expect("build two-backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
    };

    let file_id_a = Uuid::now_v7();
    let version_id_a = Uuid::now_v7();
    let path_a = format!("/{file_id_a}/{version_id_a}");
    let token_a = upload_token(&issuer, file_id_a, version_id_a, "local-fs", &path_a);

    let file_id_b = Uuid::now_v7();
    let version_id_b = Uuid::now_v7();
    let path_b = format!("/{file_id_b}/{version_id_b}");
    let token_b = upload_token(&issuer, file_id_b, version_id_b, "other", &path_b);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);

    let response_a = router
        .clone()
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/upload/{file_id_a}/{version_id_a}?fs-token={token_a}"
            ))
            .body(Body::from(b"bytes-for-local-fs".to_vec()))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(response_a.status(), StatusCode::OK);

    let response_b = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/upload/{file_id_b}/{version_id_b}?fs-token={token_b}"
            ))
            .body(Body::from(b"bytes-for-other".to_vec()))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(response_b.status(), StatusCode::OK);

    // Assert the bytes landed in the backend the TOKEN named, not always
    // the same one — via each backend's own `list_paths()`/`get()`.
    let a_paths = backend_a.list_paths().await.expect("list local-fs paths");
    assert!(
        a_paths.contains(&path_a),
        "expected {path_a} in local-fs backend, got {a_paths:?}"
    );
    assert!(
        !a_paths.contains(&path_b),
        "path_b must not land in local-fs backend, got {a_paths:?}"
    );
    let got_a = backend_a
        .get(&path_a)
        .await
        .expect("get from local-fs backend");
    assert_eq!(&got_a[..], b"bytes-for-local-fs");

    let b_paths = backend_b.list_paths().await.expect("list other paths");
    assert!(
        b_paths.contains(&path_b),
        "expected {path_b} in other backend, got {b_paths:?}"
    );
    assert!(
        !b_paths.contains(&path_a),
        "path_a must not land in other backend, got {b_paths:?}"
    );
    let got_b = backend_b
        .get(&path_b)
        .await
        .expect("get from other backend");
    assert_eq!(&got_b[..], b"bytes-for-other");
}
