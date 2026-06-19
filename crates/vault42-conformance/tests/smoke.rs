//! Smoke test proving the workspace and test harness compile and run. The real
//! property/fuzz battery (roundtrip, tamper→auth-failure, zero-knowledge) lands
//! with P2 — this only establishes that the conformance crate links the core.

#[test]
fn core_version_present() {
    assert!(!vault42_core::VERSION.is_empty());
}
