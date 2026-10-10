# Security Policy

## Supported versions

Security fixes go to the latest `0.x` release. Older `0.x` versions are not patched.

## Reporting a vulnerability

Please don't open a public issue for something you think is exploitable.

Use GitHub's [private vulnerability reporting][gh-pvr] on this repository instead: *Security* →
*Report a vulnerability*.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

Useful things to include: the version and platform you were using, something we can run to
reproduce it, and what you think the impact is. If secret material was involved, say so, but please
generate throwaway keys for the report. Never send real seeds, salts, private keys or passcodes.

## Threat model

Everything parsed from outside is assumed hostile: credential attribute labels and values, edge and
rule blocks, nonces, registry identifiers and schema SAIDs as qualified Base64, timestamps, the
issuer's key state (its position, digest and configuration traits), IPEX message text, payload
blocks and prior identifiers, the signatures a caller attaches, and the sizes and counts any of
them declare.

This crate holds no secret material. Builders take identifiers, digests and finished signatures;
signing stays with the caller.

Given that, the implementation is built to hold up against a few specific things.

Malformed input shouldn't be able to panic or abort the process, so crate-owned code contains no
`unsafe`, `unwrap`, `expect`, panicking macro, or indexing that can fail, and every rejection is a
typed error. Sequence-number arithmetic is checked, and every builder enforces an explicit ceiling
(for example `MAX_NONCE_BYTES`, `MAX_LABEL_BYTES`, `MAX_BLOCK_FIELDS`, `MAX_BLOCK_DEPTH` and
`MAX_MESSAGE_BYTES`) before it commits caller-supplied text into an identifier.

Serialization is deterministic and strict: field order is the protocol's, a credential's SAIDs are
computed from the final bytes, a transaction event reparses byte for byte, and an attribute block
naming a label the message writes itself is refused rather than silently readdressed. An
establishment-only issuer is refused before anything is built, and a disclosure or a signed message
without signatures is refused rather than assembled.

Where signify-ts emits something unsafe, such as signing another controller's anchor with the
sender's key, the unsafe behavior is refused and the refusal is pinned by a fixture rather than
reproduced.

## Randomness

This crate takes no entropy and reads no clock. Nonces and timestamps are parameters, so every
artifact is reproducible from its inputs.

## Known limitations

This is a builder and verifier of individual artifacts, not a validator of registries or logs. It
does not accept transaction events into a registry, decide whether a credential is currently
revoked, validate a disclosure's chain against the issuer's key event log, or verify the signatures
a caller attaches. A verifier that trusts a credential because its SAIDs check out, without
validating the issuance chain and the log it anchors in, has not validated it.

Interoperability is pinned to signify-ts. Other implementations have not been tested against.

## Dependencies

The production dependencies are `keri-cesr`, with its `crypto` feature, and `keri-protocol`, both
written and maintained by this crate's author. `cargo deny` and the resolved graph get reviewed
before each release.
