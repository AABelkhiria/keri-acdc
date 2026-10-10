//! What issuance and revocation have in common: a transaction event's shape, the seal that binds
//! it to a key event log, and the interaction event that carries that seal.
//!
//! A credential's *status* lives in its registry's transaction event log, not in the credential.
//! Issuing writes an `iss` event to that log; revoking writes a `rev`. Neither is trusted on its
//! own: the issuer also appends an interaction event to its own key event log sealing the
//! transaction event's identifier, sequence number, and digest, and signs that. So a verifier
//! follows the seal from a signed key event to the transaction event to the credential.
//!
//! This module ports the parts of `Credentials.issue` and `Credentials.revoke` in the pinned
//! `src/keri/app/credentialing.ts` that both perform. The events themselves are
//! [`issuance`](crate::issuance) and [`revocation`](crate::revocation). Signing the anchoring key
//! event is the issuer's: [`anchor_event`] builds it unsigned, and [`SignedAnchor`] carries it with
//! the signatures the issuer produced over it.

use core::fmt;

use keri_cesr::crypto::signature::IndexedSignature;
use keri_protocol::attachment::SignedMessageBuilder;
use keri_protocol::event::ConfigurationTrait;
use keri_protocol::event::interaction::InteractionBuilder;
use keri_protocol::event::kind::EventKind;
use keri_protocol::event::{KeyEvent, Timestamp};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::{DEFAULT_SAID_LABEL, Said};
use keri_protocol::serialization::{
    IDENTIFIER_LABEL, KIND_LABEL, SAID_LABEL, SEQUENCE_LABEL, Sad, SadValue, SerializedEvent, VERSION_LABEL,
};

use crate::credential::REGISTRY_LABEL;
use crate::error::TransactionError;

/// Field label carrying the prior transaction event's digest; a revocation's `p`.
pub const PRIOR_LABEL: &str = "p";
/// Field label carrying a transaction event's timestamp; its `dt`.
pub const TIMESTAMP_LABEL: &str = "dt";

/// Version string written before a transaction event's size is known.
///
/// A transaction event is a KERI message, not an ACDC document, so its protocol is `KERI` even
/// though it exists only to talk about a credential.
pub const UNSIZED_VERSION_STRING: &str = "KERI10JSON000000_";

/// The `{i, s, d}` seal a key event carries to anchor a transaction event.
///
/// This is what makes a transaction event trustworthy: the issuer's signed key event commits to
/// exactly this identifier, position, and digest, so a verifier that trusts the key event log
/// trusts the transaction event it names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionSeal {
    credential: Said,
    sequence_number: u128,
    said: Said,
}

impl TransactionSeal {
    /// Builds a seal naming a transaction event's credential, position, and digest.
    #[must_use]
    pub const fn new(credential: Said, sequence_number: u128, said: Said) -> Self {
        Self {
            credential,
            sequence_number,
            said,
        }
    }

    /// Returns the credential the sealed event is about, which is also its transaction log's
    /// identifier.
    #[must_use]
    pub const fn credential(&self) -> Said {
        self.credential
    }

    /// Returns the sealed event's position in that log.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the sealed event's own digest.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Renders the seal as the ordered field map a key event anchors.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::Said`] when a digest cannot be encoded and
    /// [`TransactionError::Sad`] when the map cannot be assembled.
    pub fn to_sad(&self) -> Result<Sad, TransactionError> {
        let mut seal = Sad::new();
        seal.insert(IDENTIFIER_LABEL, SadValue::Text(self.credential.qb64()?))?;
        seal.insert(SEQUENCE_LABEL, SadValue::Text(format!("{:x}", self.sequence_number)))?;
        seal.insert(SAID_LABEL, SadValue::Text(self.said.qb64()?))?;
        Ok(seal)
    }
}

/// What anchoring reads from the issuer's key state: whose log it is, where that log stands, and
/// whether an interaction event may be appended to it at all.
///
/// A KERIA agent reports key state as text; a Signify client parses what it needs into this
/// before anchoring, and a server derives it from the log it validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorState {
    identifier: IdentifierPrefix,
    sequence_number: u128,
    digest: Said,
    establishment_only: bool,
}

impl AnchorState {
    /// Describes a key event log whose latest event is `digest`, at `sequence_number`.
    #[must_use]
    pub const fn new(identifier: IdentifierPrefix, sequence_number: u128, digest: Said) -> Self {
        Self {
            identifier,
            sequence_number,
            digest,
            establishment_only: false,
        }
    }

    /// Records whether the identifier carries the `EO` configuration trait, which forbids anchoring
    /// in an interaction event.
    #[must_use]
    pub const fn establishment_only(mut self, establishment_only: bool) -> Self {
        self.establishment_only = establishment_only;
        self
    }

    /// Reads the configuration traits a key state reports and records whether `EO` is among them.
    #[must_use]
    pub fn with_configuration<I>(self, configuration: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let establishment_only = is_establishment_only(configuration);
        self.establishment_only(establishment_only)
    }

    /// Returns the identifier whose log is anchored in.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns the position of the log's latest event.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the digest of the log's latest event.
    #[must_use]
    pub const fn digest(&self) -> Said {
        self.digest
    }

    /// Returns whether this state forbids anchoring in an interaction event.
    #[must_use]
    pub const fn is_establishment_only(&self) -> bool {
        self.establishment_only
    }
}

/// The issuer's interaction event anchoring a transaction event, with the signatures over it.
///
/// Who signs is the caller's concern: a Signify client signs with its keeper, a multisig member
/// collects the group's signatures. Either way the event is the one [`anchor_event`] built.
pub struct SignedAnchor {
    /// The anchoring interaction event.
    pub event: KeyEvent,
    /// The controller signatures over its bytes, indexed by signing-key position.
    pub signatures: Vec<IndexedSignature>,
}

impl SignedAnchor {
    /// Pairs an anchoring event with the signatures over it.
    #[must_use]
    pub const fn new(event: KeyEvent, signatures: Vec<IndexedSignature>) -> Self {
        Self { event, signatures }
    }

    /// Encodes the CESR attachment carrying the signatures: the controller-signature group a
    /// disclosure attaches to the anchor.
    ///
    /// # Errors
    ///
    /// Returns layered [`TransactionError::Attachment`] failures for material that cannot be
    /// encoded.
    pub fn attachment(&self) -> Result<Vec<u8>, TransactionError> {
        Ok(SignedMessageBuilder::new(self.event.serialized())
            .controller_signatures(self.signatures.clone())
            .build()?
            .attachments()
            .to_vec())
    }
}

impl fmt::Debug for SignedAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedAnchor")
            .field("event", &self.event)
            .field("signatures", &self.signatures.len())
            .finish()
    }
}

/// Builds the interaction event anchoring `seal` in the issuer's key event log, unsigned.
///
/// The event lands at the state's next sequence number, over the state's digest, carrying exactly
/// one seal — which is what both `issue` and `revoke` do. Signing it is the caller's; a multisig
/// member's signature comes from somewhere else, and a caller may want to inspect the event before
/// committing a key to it.
///
/// # Errors
///
/// Returns [`TransactionError::EstablishmentOnlyIssuer`] when the state carries `EO`, because such
/// an identifier may only anchor in a rotation event; the reference throws
/// `Establishment only not implemented` in the same place.
/// [`TransactionError::SequenceNumberOverflow`] when the log cannot advance, and layered
/// [`TransactionError::Sad`], [`TransactionError::Said`], and [`TransactionError::Event`] failures
/// for material that cannot be encoded.
pub fn anchor_event(state: &AnchorState, seal: &TransactionSeal) -> Result<KeyEvent, TransactionError> {
    if state.establishment_only {
        return Err(TransactionError::establishment_only());
    }
    let sequence_number = state
        .sequence_number
        .checked_add(1)
        .ok_or(TransactionError::SequenceNumberOverflow {
            current: state.sequence_number,
        })?;
    Ok(
        InteractionBuilder::new(state.identifier.clone(), state.digest, sequence_number)
            .anchors(vec![seal.to_sad()?])
            .build()?,
    )
}

/// Returns whether a configuration-trait list forbids anchoring in an interaction event.
///
/// The traits are the codes a key state reports, `EO` among them.
#[must_use]
pub fn is_establishment_only<I>(configuration: I) -> bool
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    configuration
        .into_iter()
        .any(|entry| entry.as_ref() == ConfigurationTrait::EstablishmentOnly.as_str())
}

/// Assembles, derives, and serializes one transaction event.
///
/// The field order is the reference's: `v`, `t`, `d`, `i`, `s`, `ri`, then a revocation's `p`,
/// then `dt`. Both events are built by the same expression apart from that one field, so they are
/// built by the same code here.
pub(crate) fn assemble(
    kind: EventKind,
    credential: Said,
    registry: &str,
    sequence_number: u128,
    prior: Option<Said>,
    timestamp: &Timestamp,
) -> Result<(SerializedEvent, Said), TransactionError> {
    let mut fields = Sad::new();
    fields.insert(VERSION_LABEL, SadValue::text(UNSIZED_VERSION_STRING))?;
    fields.insert(KIND_LABEL, SadValue::text(kind.as_str()))?;
    fields.insert(SAID_LABEL, SadValue::text(""))?;
    fields.insert(IDENTIFIER_LABEL, SadValue::Text(credential.qb64()?))?;
    fields.insert(SEQUENCE_LABEL, SadValue::Text(format!("{sequence_number:x}")))?;
    fields.insert(REGISTRY_LABEL, SadValue::text(registry))?;
    if let Some(prior) = prior {
        fields.insert(PRIOR_LABEL, SadValue::Text(prior.qb64()?))?;
    }
    fields.insert(TIMESTAMP_LABEL, SadValue::text(timestamp.as_str()))?;

    let (said, completed) =
        Said::compute(&fields, crate::credential::DIGEST_ALGORITHM, DEFAULT_SAID_LABEL)?.into_parts();
    Ok((SerializedEvent::from_sad(completed)?, said))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const CREDENTIAL: &str = "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo";
    const ISSUANCE: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";

    #[test]
    fn a_seal_renders_the_three_fields_a_key_event_anchors() -> Result<(), Box<dyn Error>> {
        let seal = TransactionSeal::new(Said::from_qb64(CREDENTIAL)?, 0, Said::from_qb64(ISSUANCE)?);
        assert_eq!(seal.credential().qb64()?, CREDENTIAL);
        assert_eq!(seal.sequence_number(), 0);
        assert_eq!(seal.said().qb64()?, ISSUANCE);

        let sad = seal.to_sad()?;
        let labels: Vec<&str> = sad.entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["i", "s", "d"]);
        assert_eq!(sad.get_text("i"), Some(CREDENTIAL));
        assert_eq!(sad.get_text("s"), Some("0"));
        assert_eq!(sad.get_text("d"), Some(ISSUANCE));
        Ok(())
    }

    #[test]
    fn a_seal_writes_its_position_in_lowercase_hexadecimal() -> Result<(), Box<dyn Error>> {
        let said = Said::from_qb64(CREDENTIAL)?;
        for (sequence_number, expected) in [
            (0_u128, "0"),
            (1, "1"),
            (10, "a"),
            (255, "ff"),
            (4_294_967_296, "100000000"),
        ] {
            let seal = TransactionSeal::new(said, sequence_number, said);
            assert_eq!(seal.to_sad()?.get_text("s"), Some(expected));
        }
        Ok(())
    }

    #[test]
    fn the_establishment_only_trait_is_recognised_by_its_wire_text() {
        assert_eq!(ConfigurationTrait::EstablishmentOnly.as_str(), "EO");
        assert!(matches!(
            TransactionError::establishment_only(),
            TransactionError::EstablishmentOnlyIssuer { trait_code: "EO" }
        ));
    }

    #[test]
    fn a_state_reads_the_establishment_only_trait_from_its_configuration() -> Result<(), Box<dyn Error>> {
        let identifier = IdentifierPrefix::from_qb64("EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1")?;
        let state = AnchorState::new(identifier, 0, Said::from_qb64(CREDENTIAL)?);
        assert!(!state.is_establishment_only());
        assert!(!state.clone().with_configuration(["DND"]).is_establishment_only());
        assert!(state.with_configuration(["DND", "EO"]).is_establishment_only());
        assert!(is_establishment_only(["EO"]));
        assert!(!is_establishment_only(Vec::<String>::new()));
        Ok(())
    }

    #[test]
    fn the_version_string_is_a_keri_message_not_an_acdc_document() {
        assert!(UNSIZED_VERSION_STRING.starts_with("KERI"));
        assert_eq!(UNSIZED_VERSION_STRING.len(), 17);
    }
}
