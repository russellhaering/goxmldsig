# Security Testing TODO

Creative approaches to finding vulnerabilities in goxmldsig v2, beyond the
unit/fuzz/security tests already in place (134 tests, 6 fuzz targets).

## 1. Differential Canonicalization Testing ✅

**Priority: High** · **Effort: Medium** · **Bug-yield: Very High**

Canonicalization divergence is the #1 source of real XML-DSig vulnerabilities.
If Go's C14N produces different output than the signer's C14N for the same
input, an attacker can craft XML that verifies under one implementation but
not the other — enabling signature forgery.

- [x] Install `xmllint` (libxml2-based reference implementation)
- [x] Build a test harness that generates XML, canonicalizes with both Go and
      `xmllint`, and compares output byte-for-byte (`differential_c14n_test.go`)
- [x] Cover all six C14N variants:
  - Exclusive C14N 1.0 (with and without comments)
  - Inclusive C14N 1.1 (with and without comments)
  - Inclusive C14N 1.0 (with and without comments)
- [x] Seed with adversarial inputs: 21 XML files + 15 inline inputs covering
      deep nesting, namespace patterns, SAML, unicode, mixed content
- [x] Run as a fuzzer: `FuzzDifferentialC14N` generates random XML and diffs
- [x] **BUG FOUND**: Attribute sort order was wrong — sorted by prefix instead
      of namespace URI. Fixed in `etreeutils/sort.go`.
- [x] Bit-flip exhaustive test: flips every bit in a signed document, verifies
      each mutation is detected (or is a benign base64 padding bit)
- [x] Attribute and namespace permutation tests: verify canonical form is
      invariant to declaration ordering
- [ ] Known limitation: etree does not normalize tab/newline in attribute values
      (parser-level issue, not goxmldsig)

## 2. Property-Based / Metamorphic Testing ✅

**Priority: High** · **Effort: Low** · **Bug-yield: High**

Test semantic invariants rather than specific inputs. Any violation is a bug.

- [x] **Idempotency**: `canonicalize(canonicalize(x)) == canonicalize(x)` for
      all C14N methods (`TestC14NIdempotency` in w3c_c14n_test.go)
- [x] **Bit-flip exhaustive**: Sign a document, then flip every single bit in
      the serialized XML one at a time — every mutation must fail verification
      (`TestDifferentialC14NBitFlipDetection` in differential_c14n_test.go)
- [x] **Attribute reordering**: Randomly permute attributes and namespace
      declarations → canonical form must be identical
      (`TestDifferentialC14NAttributePermutations` in differential_c14n_test.go)
- [x] **Namespace re-declaration**: Add redundant namespace declarations at
      various levels → canonical form must be identical
      (`TestPropertyRedundantNamespaceDeclarations` in property_test.go)
- [x] **C14N method mismatch**: Sign with method A, tamper transform → must
      fail because SignedInfo is itself signed
      (`TestPropertyC14NMethodMismatch` in property_test.go)
- [x] **Sign-verify roundtrip**: For any well-formed XML and any key type,
      `sign → verify` must succeed, `sign → mutate → verify` must fail
      (`TestDifferentialC14NSignatureRoundTrip`, `TestAlgoRoundTrip_*`)
- [x] **C14N determinism**: Same input canonicalized 100 times → identical
      output (`TestPropertyC14NDeterminism` in property_test.go)
- [x] **Enveloped signature removal**: Verified element has no Signature child
      (`TestPropertyEnvelopedSignatureRemoval` in property_test.go)

## 3. W3C Conformance Test Vectors ✅

**Priority: High** · **Effort: Low** · **Bug-yield: High**

The W3C published official test vectors. Any failure = spec non-compliance =
potential exploit path.

- [x] Download [W3C C14N 2.0 test files](https://www.w3.org/TR/xml-c14n-testcases/files/)
      — stored in `testdata/w3c/`
- [x] Write `TestW3CC14NConformance` that runs 21 inputs through all 3 C14N
      methods and compares against xmllint-generated reference outputs
- [x] W3C C14N 1.0 Section 3.3 inline test vectors (start/end tags, attribute
      sorting, empty elements)
- [x] Exclusive C14N namespace pushdown tests from spec Section 4
- [x] Exclusive C14N InclusiveNamespaces PrefixList tests
- [x] Comment handling tests (with/without comments for all 6 C14N variants)
- [x] Namespace redeclaration, superfluous declaration stripping tests
- [x] Idempotency property test: `c14n(c14n(x)) == c14n(x)`
- [x] All test cases pass (3 skipped for known etree limitation)
- [ ] Consider the [XML-DSig interop test suite](https://www.w3.org/Signature/2002/02/01-interop.html)
      for end-to-end sign/verify interop

## 4. Cross-Reference Confusion Attacks ✅

**Priority: Medium** · **Effort: Low** · **Bug-yield: Medium**

The `Reference URI="#id"` mechanism is a classic attack vector in XML-DSig.
All tests in `cross_reference_test.go` (39 test functions, ~1380 lines).

- [x] **Duplicate IDs**: Two elements with same ID — signed element verifies,
      evil sibling ignored; verifying evil element fails with ErrMissingSignature
- [x] **URL-encoded URI**: `#%41%42%43` ≠ `#ABC` — no percent-decoding happens
- [x] **XPointer URIs**: `#xpointer(/)` and `#xpointer(id('...'))` both rejected
- [x] **Empty URI**: Valid round-trip; injected content detected (ErrDigestMismatch);
      changing URI post-signing invalidates signature
- [x] **External URIs**: `http://`, `https://`, `file://` all rejected — never fetched
- [x] **URI with query string**: `#id?extra` and `#id#extra` don't match
- [x] **Case sensitivity**: `#_ABC` ≠ `#_abc`; exact case matches correctly
- [x] **URI with spaces/special chars**: Leading space, trailing space, tab, newline
- [x] **Unused `uriRegexp` documented**: Digit-starting IDs (invalid per XML spec)
      still verify, proving the regex is unused
- [x] **Signature integrity**: Multiple signatures rejected, relative URIs rejected,
      URI tampering invalidates crypto, digest swap, signature transplant, forged
      SignatureValue, DigestMethod/Transform tampering covered

## 5. Namespace Confusion / Prefix Rebinding ✅

**Priority: Medium** · **Effort: Medium** · **Bug-yield: High**

Namespace handling is notoriously error-prone and is the root cause of many
XML-DSig bypasses in the wild. All tests in `namespace_confusion_test.go`
(16 test functions/subtests, ~691 lines).

- [x] **Prefix rebinding**: Redeclare `ds:` prefix mid-document to point to a
      different namespace — library correctly uses namespace URIs, not prefixes
- [x] **Default namespace shadowing**: `xmlns="http://www.w3.org/2000/09/xmldsig#"`
      on non-Signature elements does not confuse the verifier
- [x] **Alternative prefix signatures**: Sign with prefix "mysig", "dsig",
      "xmldsig", "" — verifier finds all via namespace URI resolution
- [x] **Empty namespace undeclaration**: `xmlns=""` on child elements handled
      correctly by canonicalization
- [x] **Namespace in attribute values**: URIs in attribute values not treated
      as namespace bindings
- [x] **Multiple prefixes same namespace**: Two prefixes pointing to same URI
      handled correctly
- [x] **Fake Signature wrong namespace**: `<fake:Signature>` where `fake` maps
      to `http://evil.com/ns` not recognized as ds:Signature
- [x] **Prefix reuse with different namespace**: `<ds:Foo xmlns:ds="http://other.com">`
      wrapping a legitimate signature — prefix resolution uses nearest ancestor
- [x] **Prefix rebind on SignedInfo children**: Tampering with inner element
      prefixes post-signing detected
- [x] **Deeply nested prefix shadowing**: Multiple levels of prefix redeclaration
- [x] **xmlns attribute injection**: Injecting namespace declarations post-signing
      detected by digest verification

## 6. Coverage-Guided Structured Fuzzing ✅

**Priority: Medium** · **Effort: Medium** · **Bug-yield: Medium**

Go beyond byte-level fuzzing by generating structurally valid but adversarial
XML-DSig documents. `FuzzStructuredSignature` in `property_test.go`.

- [x] Build a custom fuzzer that constructs valid `ds:Signature` elements with
      mutated fields rather than random bytes
- [x] 12 mutations implemented:
  - Swap DigestValue with random base64
  - Extend DigestValue with extra bytes
  - Truncate SignatureValue by N bytes
  - Empty CanonicalizationMethod Algorithm attribute
  - Empty SignatureMethod Algorithm attribute
  - Duplicate SignedInfo element
  - Inject text content into SignedInfo
  - Inject nested Signature inside SignedInfo
  - Inject extra Reference element
  - Remove all Transform elements
  - Replace DigestMethod with unknown algorithm URI
  - Replace SignatureMethod with unknown algorithm URI
- [x] Uses `testing.F` with 12 seed corpus entries (one per mutation)
- [x] Every mutation correctly causes verification to fail

## 7. Certificate Handling Edge Cases ✅

**Priority: Medium** · **Effort: Low** · **Bug-yield: Medium**

All tests in `cert_edge_test.go` (14 test functions, ~438 lines).

- [x] **NotBefore in future**: Cert valid from tomorrow → `ErrCertificateExpired`
- [x] **NotAfter in past**: Cert expired yesterday → `ErrCertificateExpired`
- [x] **Clock manipulation**: Custom `Clock` returns time inside narrow window
      (2030) → accepted correctly
- [x] **Same public key, different cert**: Same RSA key, different serial →
      different DER bytes → `ErrCertificateNotTrusted` (cert.Equal compares DER)
- [x] **Multiple KeyInfo certs**: Only first X509Certificate used; trusting
      only second cert → `ErrCertificateNotTrusted`
- [x] **KeyInfo cert omitted**: Single trusted cert → fallback works;
      multiple trusted certs → `ErrCertificateNotTrusted`
- [x] **Cert with weak key**: RSA-1024 works (no minimum key size enforcement;
      documented as limitation)
- [x] **ECDSA P-256**: Sign+verify round-trip succeeds
- [x] **Cert chain not built**: Leaf+root in KeyInfo, trust only root →
      `ErrCertificateNotTrusted` (equality matching, not chain building;
      documented as limitation)
- [x] **Empty TrustedCerts**: nil and empty slice → proper error
- [x] **Matching but expired**: Cert matches but both expired → `ErrCertificateExpired`
- [x] **Malformed KeyInfo cert**: Garbage DER → `ErrMalformedSignature`
- [x] **Invalid base64 KeyInfo cert**: Bad base64 → `ErrMalformedSignature`

## Done (previous session)

- [x] XSW (XML Signature Wrapping) attack tests — 10 variants
- [x] Certificate trust boundary tests — 7 tests
- [x] Digest tampering tests — 4 tests
- [x] Algorithm abuse tests — 4 tests
- [x] Concurrency / thread safety tests — 4 tests
- [x] All key/hash combination tests — 28 tests
- [x] Malformed signature structure tests — 14 tests
- [x] Edge case tests (unicode, deep nesting, large docs) — 19 tests
- [x] Fuzz targets — 6 targets
- [x] Fix: ASN.1 parsing panic in `convertECDSAASN1ToRawRS`
- [x] Fix: Constant-time digest comparison (`crypto/subtle.ConstantTimeCompare`)
- [x] Fix: C14N attribute sort order — sorted by prefix instead of namespace URI
- [x] Differential C14N testing against xmllint (libxml2)
- [x] W3C conformance test vectors (21 inputs × 3 C14N methods)
- [x] Bit-flip exhaustive mutation test
- [x] Attribute/namespace permutation invariance tests
- [x] Differential C14N fuzzer (`FuzzDifferentialC14N`)
