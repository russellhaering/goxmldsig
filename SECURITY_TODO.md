# Security Testing TODO

Creative approaches to finding vulnerabilities in goxmldsig v2, beyond the
unit/fuzz/security tests already in place (134 tests, 6 fuzz targets).

## 1. Differential Canonicalization Testing

**Priority: High** · **Effort: Medium** · **Bug-yield: Very High**

Canonicalization divergence is the #1 source of real XML-DSig vulnerabilities.
If Go's C14N produces different output than the signer's C14N for the same
input, an attacker can craft XML that verifies under one implementation but
not the other — enabling signature forgery.

- [ ] Install `xmlsec1` (libxml2-based reference implementation)
- [ ] Build a test harness that generates XML, canonicalizes with both Go and
      `xmlsec1`, and compares output byte-for-byte
- [ ] Cover all six C14N variants:
  - Exclusive C14N 1.0 (with and without comments)
  - Inclusive C14N 1.1 (with and without comments)
  - Inclusive C14N 1.0 (with and without comments)
- [ ] Seed with adversarial inputs: deep nesting, unusual namespace patterns,
      mixed content, CDATA, processing instructions, whitespace-only text nodes
- [ ] Run as a fuzzer: generate random XML → diff the two outputs

## 2. Property-Based / Metamorphic Testing

**Priority: High** · **Effort: Low** · **Bug-yield: High**

Test semantic invariants rather than specific inputs. Any violation is a bug.

- [ ] **Idempotency**: `canonicalize(canonicalize(x)) == canonicalize(x)` for
      all C14N methods
- [ ] **Bit-flip exhaustive**: Sign a document, then flip every single bit in
      the serialized XML one at a time — every mutation must fail verification
- [ ] **Attribute reordering**: Randomly permute attributes and namespace
      declarations → canonical form must be identical
- [ ] **Namespace re-declaration**: Add redundant namespace declarations at
      various levels → canonical form must be identical
- [ ] **C14N method mismatch**: Sign with method A, verify with method B →
      must fail (unless A and B are equivalent for the input)
- [ ] **Sign-verify roundtrip**: For any well-formed XML and any key type,
      `sign → verify` must succeed, `sign → mutate → verify` must fail

## 3. W3C Conformance Test Vectors

**Priority: High** · **Effort: Low** · **Bug-yield: High**

The W3C published official test vectors. Any failure = spec non-compliance =
potential exploit path.

- [ ] Download [Canonical XML 1.0 test cases](https://www.w3.org/TR/xml-c14n-testcases/)
- [ ] Download [Exclusive C14N test cases](https://www.w3.org/TR/xml-exc-c14n/#sec-Specification)
- [ ] Download [Canonical XML 1.1 test cases](https://www.w3.org/TR/xml-c14n11/#Examples)
- [ ] Write `TestW3CC14NConformance` that runs each official input through our
      canonicalizer and compares against the expected output
- [ ] Track which test cases pass/fail; file issues for failures
- [ ] Also consider the [XML-DSig interop test suite](https://www.w3.org/Signature/2002/02/01-interop.html)
      for end-to-end sign/verify interop

## 4. Cross-Reference Confusion Attacks

**Priority: Medium** · **Effort: Low** · **Bug-yield: Medium**

The `Reference URI="#id"` mechanism is a classic attack vector in XML-DSig.

- [ ] **Duplicate IDs**: Two elements with the same ID value — which one gets
      digested? Can an attacker control which one the verifier picks?
- [ ] **URL-encoded URI**: `URI="#%41%42%43"` vs `URI="#ABC"` — does the
      library normalize these?
- [ ] **XPointer URIs**: `URI="#xpointer(/)"` or `URI="#xpointer(id('foo'))"`
      — should be rejected (unsupported) rather than silently mishandled
- [ ] **Empty URI**: `URI=""` means "the whole document" — test that this
      references the correct thing and can't be confused with a fragment
- [ ] **External URIs**: `URI="http://evil.com/doc.xml"` — must be rejected,
      never fetched
- [ ] **URI with query string**: `URI="#id?extra"` — should not match
- [ ] **Case sensitivity**: XML IDs are case-sensitive — verify the library
      doesn't do case-insensitive matching

## 5. Namespace Confusion / Prefix Rebinding

**Priority: Medium** · **Effort: Medium** · **Bug-yield: High**

Namespace handling is notoriously error-prone and is the root cause of many
XML-DSig bypasses in the wild.

- [ ] **Prefix rebinding**: Redeclare `ds:` prefix mid-document to point to a
      different namespace — the library must use namespace URIs, not prefixes,
      for element identity
- [ ] **Default namespace shadowing**: Use `xmlns="http://www.w3.org/2000/09/xmldsig#"`
      to make unprefixed elements look like ds: elements — should not confuse
      the verifier
- [ ] **Undeclared prefix on Signature element**: `<foo:Signature>` where
      `foo:` is not declared — must error, not silently proceed
- [ ] **Empty namespace undeclaration**: `xmlns=""` on a child element — test
      that canonicalization handles this correctly
- [ ] **Reserved prefix abuse**: `xmlns:xml="wrong"` or `xmlns:xmlns="wrong"`
      — must be rejected per XML Namespaces spec
- [ ] **Namespace in attribute values**: Namespace URIs in attribute values
      (not declarations) must not be treated as namespace bindings
- [ ] **Prefix used but never declared in ancestor**: Verify the traversal
      limit and error handling in `NSContext.LookupPrefix`

## 6. Coverage-Guided Structured Fuzzing

**Priority: Medium** · **Effort: Medium** · **Bug-yield: Medium**

Go beyond byte-level fuzzing by generating structurally valid but adversarial
XML-DSig documents.

- [ ] Build a custom fuzzer that constructs valid `ds:Signature` elements with
      mutated fields rather than random bytes
- [ ] Mutations to try:
  - Swap DigestValue between two References
  - Inject extra `<Reference>` elements
  - Use different C14N methods in `<CanonicalizationMethod>` vs `<Transform>`
  - Truncate base64 SignatureValue by 1 byte
  - Extend base64 DigestValue by 1 byte
  - Empty string for Algorithm attributes
  - Duplicate `<SignedInfo>` elements
  - `<SignatureValue>` before `<SignedInfo>` (reordered children)
  - Nested `<Signature>` inside `<SignedInfo>`
- [ ] Use `testing.F` with a seed corpus of real signed documents
- [ ] Run for extended periods (hours) in CI

## 7. Certificate Handling Edge Cases

**Priority: Medium** · **Effort: Low** · **Bug-yield: Medium**

- [ ] **NotBefore in future**: Cert valid from tomorrow — must reject
- [ ] **NotAfter in past**: Cert expired yesterday — must reject
- [ ] **Clock manipulation**: Custom `Clock` func returns time inside cert
      validity window even though wall clock is outside — must accept
- [ ] **Same public key, different cert**: Attacker presents cert with the same
      RSA/ECDSA public key but different serial/issuer — must reject (not in
      trusted set)
- [ ] **Multiple KeyInfo certs**: What if KeyInfo contains 2+ certificates?
      Verify only the first is used, or document the behavior
- [ ] **KeyInfo cert omitted**: No `<X509Certificate>` in KeyInfo — verify
      fallback behavior with single vs multiple trusted certs
- [ ] **Cert with weak key**: RSA-1024 cert — the library doesn't enforce
      minimum key sizes; document or add a check
- [ ] **Cert chain validation**: KeyInfo contains an intermediate + leaf cert;
      only the root is in TrustedCerts — currently the library does direct
      cert equality matching, not chain building (document this limitation)

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
