#![allow(clippy::expect_used)]

#[cfg(all(
    feature = "authn",
    feature = "authz",
    feature = "crypto",
    feature = "cve",
    feature = "cvss",
    feature = "cwe",
    feature = "owasp",
    feature = "risk",
    feature = "threat",
    feature = "finding",
    feature = "secret",
    feature = "security-header",
    feature = "sbom"
))]
#[test]
fn facade_reexports_every_child_crate() {
    use use_security::{
        authn as _, authz as _, crypto as _, cve as _, cvss as _, cwe as _, finding as _,
        owasp as _, risk as _, sbom as _, secret as _, security_header as _, threat as _,
    };

    let cve = use_security::CveId::new("CVE-2024-12345").expect("valid CVE");
    let cwe = use_security::CweId::new("CWE-79").expect("valid CWE");
    let cvss = use_security::CvssScore::new(9.8).expect("valid score");
    let risk_id = use_security::SecurityRiskId::new("R-1").expect("valid risk id");
    let threat_id = use_security::ThreatId::new("T-1").expect("valid threat id");
    let finding_id = use_security::SecurityFindingId::new("F-1").expect("valid finding id");
    let permission = use_security::PermissionName::new("document:read").expect("valid permission");
    let secret = use_security::SecretReference::new("prod/db/password").expect("valid reference");
    let header =
        use_security::SecurityHeaderName::new("Content-Security-Policy").expect("valid header");
    let component = use_security::SbomComponentName::new("example").expect("valid component");

    assert_eq!(cve.as_str(), "CVE-2024-12345");
    assert_eq!(cwe.to_string(), "CWE-79");
    assert_eq!(
        use_security::severity_from_score(cvss),
        use_security::CvssSeverity::Critical
    );
    assert_eq!(
        use_security::OwaspTop10Category::BrokenAccessControl.as_str(),
        "broken-access-control"
    );
    assert_eq!(risk_id.as_str(), "R-1");
    assert_eq!(threat_id.as_str(), "T-1");
    assert_eq!(finding_id.as_str(), "F-1");
    assert_eq!(
        use_security::AuthenticationMethod::Passkey.as_str(),
        "passkey"
    );
    assert_eq!(permission.as_str(), "document:read");
    assert_eq!(format!("{secret:?}"), "SecretReference(\"<redacted>\")");
    assert!(use_security::HashAlgorithm::Md5.is_deprecated_like());
    assert_eq!(header.as_str(), "Content-Security-Policy");
    assert_eq!(component.as_str(), "example");
}

#[test]
fn facade_compiles_without_features() {}
