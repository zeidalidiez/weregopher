//! Portable immutable private-package-origin behavior.

use std::sync::Arc;

use uuid::Uuid;
use weregopher_domain::AppInstanceId;
use weregopher_renderer::{
    ImmutablePackage, PackageAsset, PackageOrigin, PackageOriginLimits, PrivateOrigin,
};

fn fixture() -> Result<PackageOrigin, Box<dyn std::error::Error>> {
    let limits = PackageOriginLimits::g1_fixture();
    let package = ImmutablePackage::new(
        vec![
            PackageAsset::new(
                "index.html",
                Arc::<[u8]>::from(
                    b"<!doctype html><script src=\"assets/main.js\"></script>".as_slice(),
                ),
                &limits,
            )?,
            PackageAsset::new(
                "assets/main.js",
                Arc::<[u8]>::from(b"document.body.dataset.loaded = 'true';".as_slice()),
                &limits,
            )?,
        ],
        limits,
    )?;
    let app = AppInstanceId::from_uuid(Uuid::from_u128(1));
    Ok(PackageOrigin::new(PrivateOrigin::for_app(app), package))
}

#[test]
fn private_origin_serves_only_manifest_listed_immutable_assets()
-> Result<(), Box<dyn std::error::Error>> {
    let origin = fixture()?;
    let entry = origin.serve("GET", &origin.origin().entry_url("index.html")?)?;
    assert_eq!(entry.status_code(), 200);
    assert_eq!(entry.media_type(), "text/html; charset=utf-8");
    assert!(entry.etag().starts_with("\"sha256-"));
    assert!(entry.body().starts_with(b"<!doctype html>"));

    let script = origin.serve(
        "GET",
        &format!(
            "{}assets/main.js?build=synthetic",
            origin.origin().base_url()
        ),
    )?;
    assert_eq!(script.status_code(), 200);
    assert_eq!(script.media_type(), "text/javascript; charset=utf-8");

    let head = origin.serve("HEAD", &origin.origin().entry_url("index.html")?)?;
    assert_eq!(head.content_length(), entry.content_length());
    assert!(head.body().is_empty());

    let missing = origin.serve("GET", &origin.origin().entry_url("missing.js")?)?;
    assert_eq!(missing.status_code(), 404);
    assert!(missing.body().is_empty());
    Ok(())
}

#[test]
fn private_origin_rejects_network_and_path_escape_inputs() -> Result<(), Box<dyn std::error::Error>>
{
    let origin = fixture()?;
    let host = origin.origin().host();

    for uri in [
        format!("http://{host}/index.html"),
        "https://other.weregopher.invalid/index.html".to_owned(),
        format!("https://{host}:443/index.html"),
        format!("https://{host}/../secret"),
        format!("https://{host}/%2e%2e/secret"),
        format!("https://{host}/assets%2fsecret"),
        format!("https://{host}/assets\\\\secret"),
        format!("https://user@{host}/index.html"),
        format!("https://{host}/index.html#fragment"),
    ] {
        assert!(origin.serve("GET", &uri).is_err(), "accepted {uri}");
    }
    assert!(
        origin
            .serve("POST", &origin.origin().entry_url("index.html")?)
            .is_err()
    );
    Ok(())
}

#[test]
fn package_construction_rejects_ambiguous_or_over_budget_assets()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = PackageOriginLimits::new(2, 32, 8, 12, 256)?;
    assert!(PackageAsset::new("../index.html", Arc::<[u8]>::from(&b"x"[..]), &limits).is_err());
    assert!(
        PackageAsset::new("index.html", Arc::<[u8]>::from(&b"123456789"[..]), &limits).is_err()
    );

    let first = PackageAsset::new("index.html", Arc::<[u8]>::from(&b"one"[..]), &limits)?;
    let duplicate = PackageAsset::new("index.html", Arc::<[u8]>::from(&b"two"[..]), &limits)?;
    assert!(ImmutablePackage::new(vec![first, duplicate], limits).is_err());
    Ok(())
}
