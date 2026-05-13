//! Backend-independent types for TLS exporter (RFC 5705 / RFC 8446) support.
//!
//! These types live outside [`crate::tls`] so they are available even when
//! none of the `__tls` feature flags are enabled. We need that because
//! `pin_project_lite!` cannot cfg-gate individual struct fields, so the
//! [`KeyingMaterialSpec`] field on [`crate::connect::sealed::Conn`] must
//! exist (with a real, available type) in every build configuration.

/// A `(label, context, length)` specification for [RFC 5705][] / [RFC 8446][]
/// exported keying material.
///
/// Registered via
/// [`ClientBuilder::tls_export_keying_material`][crate::ClientBuilder::tls_export_keying_material].
///
/// [RFC 5705]: https://datatracker.ietf.org/doc/html/rfc5705
/// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#section-7.5
#[derive(Clone, Debug)]
pub(crate) struct KeyingMaterialSpec {
    // Only the rustls backend actually reads these fields. Suppress dead-code
    // warnings in builds where rustls is disabled (no-tls and native-tls-only
    // builds): the field is still required to exist because the `Conn`
    // pin_project! struct in `connect.rs` carries an
    // `Arc<[KeyingMaterialSpec]>` field in every configuration.
    #[cfg_attr(not(feature = "__rustls"), allow(dead_code))]
    pub(crate) label: Vec<u8>,
    #[cfg_attr(not(feature = "__rustls"), allow(dead_code))]
    pub(crate) context: Option<Vec<u8>>,
    #[cfg_attr(not(feature = "__rustls"), allow(dead_code))]
    pub(crate) length: usize,
}

/// A keying material entry resulting from a successful EKM derivation.
///
/// The `material` field is intentionally omitted from the `Debug` impl so
/// that secret bytes never reach logs.
// Only constructed inside `connect.rs`'s rustls path; in builds without any
// TLS backend the struct is never instantiated but still has to exist
// because [`crate::tls::TlsInfo`]'s field type is part of every build (the
// type is publicly visible only under `__tls`, but is referenced through
// `crate::tls_keying_material::KeyingMaterialEntry` in always-on code).
#[cfg_attr(not(any(feature = "__rustls", feature = "__tls")), allow(dead_code))]
#[derive(Clone)]
pub(crate) struct KeyingMaterialEntry {
    pub(crate) label: Vec<u8>,
    pub(crate) context: Option<Vec<u8>>,
    pub(crate) material: Vec<u8>,
}

impl std::fmt::Debug for KeyingMaterialEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // SECURITY: never include `material` in any Debug/log output.
        f.debug_struct("KeyingMaterialEntry")
            .field("label", &self.label)
            .field("context", &self.context)
            .field("material_len", &self.material.len())
            .finish()
    }
}
