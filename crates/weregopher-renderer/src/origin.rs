//! Immutable manifest-scoped package assets exposed through one private HTTPS-like origin.

use std::{collections::BTreeMap, sync::Arc};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::{AppInstanceId, OriginIdentity, Sha256Digest};

/// Independent bounds for one private package origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageOriginLimits {
    assets: usize,
    path_bytes: usize,
    asset_bytes: usize,
    total_bytes: usize,
    url_bytes: usize,
}

impl PackageOriginLimits {
    /// Constructs nonzero, internally consistent origin limits.
    ///
    /// # Errors
    ///
    /// Returns [`PackageOriginError::InvalidLimits`] when any ceiling is zero or a per-item
    /// ceiling exceeds its aggregate ceiling.
    pub const fn new(
        max_assets: usize,
        max_path_bytes: usize,
        max_asset_bytes: usize,
        max_total_bytes: usize,
        max_url_bytes: usize,
    ) -> Result<Self, PackageOriginError> {
        if max_assets == 0
            || max_path_bytes == 0
            || max_asset_bytes == 0
            || max_total_bytes == 0
            || max_url_bytes == 0
            || max_asset_bytes > max_total_bytes
            || max_path_bytes > max_url_bytes
        {
            return Err(PackageOriginError::InvalidLimits);
        }
        Ok(Self {
            assets: max_assets,
            path_bytes: max_path_bytes,
            asset_bytes: max_asset_bytes,
            total_bytes: max_total_bytes,
            url_bytes: max_url_bytes,
        })
    }

    /// Conservative limits for the synthetic G1 renderer package.
    #[must_use]
    pub const fn g1_fixture() -> Self {
        Self {
            assets: 128,
            path_bytes: 1_024,
            asset_bytes: 4 * 1024 * 1024,
            total_bytes: 16 * 1024 * 1024,
            url_bytes: 4_096,
        }
    }
}

/// One immutable manifest-listed renderer asset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageAsset {
    path: String,
    media_type: &'static str,
    bytes: Arc<[u8]>,
    digest: Sha256Digest,
}

impl PackageAsset {
    /// Validates and retains one immutable asset.
    ///
    /// # Errors
    ///
    /// Returns [`PackageOriginError`] when the path is noncanonical or the bytes exceed the
    /// configured per-asset ceiling.
    pub fn new(
        path: impl Into<String>,
        bytes: Arc<[u8]>,
        limits: &PackageOriginLimits,
    ) -> Result<Self, PackageOriginError> {
        let path = path.into();
        validate_asset_path(&path, limits.path_bytes)?;
        if bytes.len() > limits.asset_bytes {
            return Err(PackageOriginError::AssetTooLarge {
                maximum: limits.asset_bytes,
                actual: bytes.len(),
            });
        }
        let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
        Ok(Self {
            media_type: media_type_for(&path),
            path,
            bytes,
            digest,
        })
    }

    /// Canonical package-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Closed immutable package asset map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutablePackage {
    assets: BTreeMap<String, PackageAsset>,
    limits: PackageOriginLimits,
}

impl ImmutablePackage {
    /// Constructs a bounded package and rejects duplicate manifest paths.
    ///
    /// # Errors
    ///
    /// Returns [`PackageOriginError`] for an empty, duplicate, over-count, or over-byte package.
    pub fn new(
        assets: Vec<PackageAsset>,
        limits: PackageOriginLimits,
    ) -> Result<Self, PackageOriginError> {
        if assets.is_empty() {
            return Err(PackageOriginError::EmptyPackage);
        }
        if assets.len() > limits.assets {
            return Err(PackageOriginError::TooManyAssets {
                maximum: limits.assets,
                actual: assets.len(),
            });
        }
        let mut total = 0_usize;
        let mut indexed = BTreeMap::new();
        for asset in assets {
            total = total
                .checked_add(asset.bytes.len())
                .ok_or(PackageOriginError::AggregateBytesOverflow)?;
            if total > limits.total_bytes {
                return Err(PackageOriginError::PackageTooLarge {
                    maximum: limits.total_bytes,
                    actual: total,
                });
            }
            let path = asset.path.clone();
            if indexed.insert(path.clone(), asset).is_some() {
                return Err(PackageOriginError::DuplicateAsset { path });
            }
        }
        Ok(Self {
            assets: indexed,
            limits,
        })
    }

    fn asset(&self, path: &str) -> Option<&PackageAsset> {
        self.assets.get(path)
    }
}

/// Application-scoped private HTTPS-like package origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateOrigin {
    host: String,
    base_url: String,
}

impl PrivateOrigin {
    /// Derives a DNS-safe opaque origin from one application launch identity.
    #[must_use]
    pub fn for_app(app: AppInstanceId) -> Self {
        let host = format!("app-{}.weregopher.invalid", app.as_uuid().simple());
        let base_url = format!("https://{host}/");
        Self { host, base_url }
    }

    /// Private DNS host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Canonical origin root including its trailing slash.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Constructs one canonical asset URL.
    ///
    /// # Errors
    ///
    /// Returns [`PackageOriginError`] when `path` is not a canonical package-relative path.
    pub fn entry_url(&self, path: &str) -> Result<String, PackageOriginError> {
        validate_asset_path(path, 4_096)?;
        Ok(format!("{}{path}", self.base_url))
    }

    /// Returns the backend-authoritative browser origin identity.
    #[must_use]
    pub fn identity(&self) -> OriginIdentity {
        OriginIdentity {
            serialized: self.base_url.trim_end_matches('/').to_owned(),
            opaque: false,
        }
    }

    pub(crate) fn request_path(
        &self,
        uri: &str,
        limits: PackageOriginLimits,
    ) -> Result<String, PackageOriginError> {
        if uri.len() > limits.url_bytes {
            return Err(PackageOriginError::UrlTooLong {
                maximum: limits.url_bytes,
                actual: uri.len(),
            });
        }
        if uri.contains('#') {
            return Err(PackageOriginError::FragmentNotAllowed);
        }
        let remainder = uri
            .strip_prefix(&self.base_url)
            .ok_or(PackageOriginError::OriginMismatch)?;
        let encoded_path = remainder
            .split_once('?')
            .map_or(remainder, |(path, _)| path);
        decode_request_path(encoded_path, limits.path_bytes)
    }
}

/// Immutable response selected from one manifest-scoped package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageOriginResponse {
    status_code: u16,
    reason: &'static str,
    media_type: &'static str,
    etag: String,
    content_length: usize,
    body: Arc<[u8]>,
}

impl PackageOriginResponse {
    /// HTTP-like response status.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Stable reason phrase.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// Explicit response media type.
    #[must_use]
    pub const fn media_type(&self) -> &'static str {
        self.media_type
    }

    /// Strong content digest validator.
    #[must_use]
    pub fn etag(&self) -> &str {
        &self.etag
    }

    /// Manifest-declared body length, including for `HEAD`.
    #[must_use]
    pub const fn content_length(&self) -> usize {
        self.content_length
    }

    /// Immutable body bytes; empty for `HEAD` and missing assets.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Resolves private-origin requests exclusively through an immutable package manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageOrigin {
    origin: PrivateOrigin,
    package: ImmutablePackage,
}

impl PackageOrigin {
    /// Binds an immutable package to one private application origin.
    #[must_use]
    pub const fn new(origin: PrivateOrigin, package: ImmutablePackage) -> Self {
        Self { origin, package }
    }

    /// Bound private origin.
    #[must_use]
    pub const fn origin(&self) -> &PrivateOrigin {
        &self.origin
    }

    /// Resolves one `GET` or `HEAD` without touching the host filesystem or network.
    ///
    /// # Errors
    ///
    /// Returns [`PackageOriginError`] for unsupported methods, origin mismatch, malformed
    /// escaping, traversal, or a noncanonical request path. Missing canonical assets yield a
    /// deterministic 404 response.
    pub fn serve(
        &self,
        method: &str,
        uri: &str,
    ) -> Result<PackageOriginResponse, PackageOriginError> {
        let head = match method {
            "GET" => false,
            "HEAD" => true,
            _ => return Err(PackageOriginError::UnsupportedMethod),
        };
        let path = self.origin.request_path(uri, self.package.limits)?;
        let Some(asset) = self.package.asset(&path) else {
            return Ok(PackageOriginResponse {
                status_code: 404,
                reason: "Not Found",
                media_type: "application/octet-stream",
                etag: String::new(),
                content_length: 0,
                body: Arc::from([]),
            });
        };
        let body = if head {
            Arc::from([])
        } else {
            Arc::clone(&asset.bytes)
        };
        Ok(PackageOriginResponse {
            status_code: 200,
            reason: "OK",
            media_type: asset.media_type,
            etag: format!("\"{}\"", asset.digest).replace("sha256:", "sha256-"),
            content_length: asset.bytes.len(),
            body,
        })
    }
}

fn validate_asset_path(path: &str, maximum: usize) -> Result<(), PackageOriginError> {
    if path.is_empty() || path.len() > maximum {
        return Err(PackageOriginError::InvalidAssetPath);
    }
    if path.starts_with('/') || path.ends_with('/') || path.contains(['\\', '%', '?', '#', ':']) {
        return Err(PackageOriginError::InvalidAssetPath);
    }
    for segment in path.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(PackageOriginError::InvalidAssetPath);
        }
    }
    Ok(())
}

fn decode_request_path(encoded: &str, maximum: usize) -> Result<String, PackageOriginError> {
    if encoded.is_empty() {
        return Ok("index.html".to_owned());
    }
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::new();
    decoded
        .try_reserve(bytes.len().min(maximum))
        .map_err(|_| PackageOriginError::AllocationFailed)?;
    let mut index = 0;
    while index < bytes.len() {
        let encoded = bytes[index] == b'%';
        let byte = if encoded {
            let high = *bytes
                .get(index + 1)
                .ok_or(PackageOriginError::InvalidPercentEncoding)?;
            let low = *bytes
                .get(index + 2)
                .ok_or(PackageOriginError::InvalidPercentEncoding)?;
            index += 3;
            decode_hex(high)?
                .checked_mul(16)
                .and_then(|value| value.checked_add(decode_hex(low).ok()?))
                .ok_or(PackageOriginError::InvalidPercentEncoding)?
        } else {
            let value = bytes[index];
            index += 1;
            value
        };
        if (encoded && byte == b'/') || matches!(byte, b'\\' | b'?' | b'#' | b':' | 0..=0x1f | 0x7f)
        {
            return Err(PackageOriginError::InvalidAssetPath);
        }
        if decoded.len() >= maximum {
            return Err(PackageOriginError::InvalidAssetPath);
        }
        decoded.push(byte);
    }
    let path = String::from_utf8(decoded).map_err(|_| PackageOriginError::InvalidUtf8Path)?;
    validate_asset_path(&path, maximum)?;
    Ok(path)
}

fn decode_hex(byte: u8) -> Result<u8, PackageOriginError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(PackageOriginError::InvalidPercentEncoding),
    }
}

fn media_type_for(path: &str) -> &'static str {
    let extension = path.rsplit_once('.').map_or("", |(_, extension)| extension);
    match extension {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// Invalid private-origin limits, package assets, or request.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PackageOriginError {
    /// One or more configured limits were zero or internally inconsistent.
    #[error("package origin limits are invalid")]
    InvalidLimits,
    /// A package-relative path was empty, ambiguous, unsafe, or oversized.
    #[error("package asset path is invalid")]
    InvalidAssetPath,
    /// One asset exceeded the configured byte ceiling.
    #[error("package asset exceeds {maximum} bytes: {actual}")]
    AssetTooLarge {
        /// Allowed bytes.
        maximum: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// A package contained no assets.
    #[error("immutable renderer package must contain at least one asset")]
    EmptyPackage,
    /// Asset cardinality exceeded its ceiling.
    #[error("renderer package exceeds {maximum} assets: {actual}")]
    TooManyAssets {
        /// Allowed assets.
        maximum: usize,
        /// Observed assets.
        actual: usize,
    },
    /// The same canonical asset path appeared more than once.
    #[error("renderer package contains duplicate asset `{path}`")]
    DuplicateAsset {
        /// Duplicate path.
        path: String,
    },
    /// Aggregate byte accounting overflowed.
    #[error("renderer package aggregate byte count overflowed")]
    AggregateBytesOverflow,
    /// Aggregate asset bytes exceeded their ceiling.
    #[error("renderer package exceeds {maximum} bytes: {actual}")]
    PackageTooLarge {
        /// Allowed bytes.
        maximum: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// A request method could produce side effects or has no fixture semantics.
    #[error("private package origin accepts only GET and HEAD")]
    UnsupportedMethod,
    /// Request URL exceeded its byte ceiling.
    #[error("private package URL exceeds {maximum} bytes: {actual}")]
    UrlTooLong {
        /// Allowed bytes.
        maximum: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// URL scheme, authority, user information, or port did not exactly match.
    #[error("request URL does not match the private package origin")]
    OriginMismatch,
    /// URL fragments are never sent as resource requests and are rejected as ambiguous input.
    #[error("private package URL fragments are not accepted")]
    FragmentNotAllowed,
    /// Percent escaping was truncated or nonhexadecimal.
    #[error("private package URL contains invalid percent encoding")]
    InvalidPercentEncoding,
    /// Percent-decoded path bytes were not UTF-8.
    #[error("private package URL path is not UTF-8")]
    InvalidUtf8Path,
    /// Bounded decode storage could not be reserved.
    #[error("private package URL allocation failed")]
    AllocationFailed,
}
