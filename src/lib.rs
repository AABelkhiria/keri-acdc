//! ACDC credentials: the container, its issuance and revocation events, and the IPEX messages
//! that disclose it.
//!
//! [`credential`] builds the container itself and the two self-addressing identifiers that give
//! it its identity. [`issuance`] and [`revocation`] build the transaction events that record a
//! credential's status in its registry's log, on the [`transaction`] machinery both share: the
//! seal that binds a transaction event to the issuer's key event log, the unsigned interaction
//! event carrying it, and the CESR attachments binding each artifact to the next. [`ipex`] builds
//! the five messages two controllers exchange to disclose a credential.
//!
//! Everything here is built unsigned. Signing is the caller's, with whatever holds its keys, and
//! [`transaction::SignedAnchor`] and [`ipex::SignedIpexMessage`] carry the result. Nothing in this
//! crate performs networking, reads a clock, or knows a KERIA endpoint.

#![forbid(unsafe_code)]

pub mod credential;
pub mod error;
pub mod ipex;
pub mod issuance;
pub mod revocation;
pub mod transaction;
