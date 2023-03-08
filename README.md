# goxmldsig

![Build Status](https://github.com/russellhaering/goxmldsig/actions/workflows/test.yml/badge.svg?branch=main)
[![GoDoc](https://godoc.org/github.com/russellhaering/goxmldsig?status.svg)](https://godoc.org/github.com/russellhaering/goxmldsig)

XML Digital Signatures implemented in pure Go.

## Installation

Install `goxmldsig` using `go get`:

```
$ go get github.com/russellhaering/goxmldsig
```

## Usage

Include the [`types.Signature`](https://pkg.go.dev/github.com/russellhaering/goxmldsig/types#Signature) struct from this package in your application messages.

```go
import (
    sigtypes "github.com/russellhaering/goxmldsig/types"
)

type AppHdr struct {
    ...
    Signature *sigtypes.Signature
}
```

### Signing

```go
package main

import (
    "github.com/beevik/etree"
    "github.com/russellhaering/goxmldsig"
)

func main() {
    // Generate a key and self-signed certificate for signing
    randomKeyStore := dsig.RandomKeyStoreForTest()
    ctx := dsig.NewDefaultSigningContext(randomKeyStore)
    elementToSign := &etree.Element{
        Tag: "ExampleElement",
    }
    elementToSign.CreateAttr("ID", "id1234")

    // Sign the element
    signedElement, err := ctx.SignEnveloped(elementToSign)
    if err != nil {
        panic(err)
    }

    // Serialize the signed element. It is important not to modify the element
    // after it has been signed - even pretty-printing the XML will invalidate
    // the signature.
    doc := etree.NewDocument()
    doc.SetRoot(signedElement)
    str, err := doc.WriteToString()
    if err != nil {
        panic(err)
    }

    println(str)
}
```

### Signature Validation

```go
// Validate an element against a root certificate
func validate(root *x509.Certificate, el *etree.Element) {
    // Construct a signing context with one or more roots of trust.
    ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
        Roots: []*x509.Certificate{root},
    })

    // It is important to only use the returned validated element.
    // See: https://www.w3.org/TR/xmldsig-bestpractices/#check-what-is-signed
    validated, err := ctx.Validate(el)
    if err != nil {
        panic(err)
    }

    doc := etree.NewDocument()
    doc.SetRoot(validated)
    str, err := doc.WriteToString()
    if err != nil {
        panic(err)
    }

    println(str)
}
```

### Working with Manifest

```go
package main

import (
    "crypto"
    "github.com/beevik/etree"
    "github.com/austdev/goxmldsig"
    "github.com/austdev/goxmldsig/types"
)

func main() {
    // Generate a key and self-signed certificate for signing
    randomKeyStore := dsig.RandomKeyStoreForTest()
    ctx := dsig.NewDefaultSigningContext(randomKeyStore)

    digest := []byte{0x45, 0xf1, 0xab, 0xd7, 0x8a, 0x6f, 0x92, 0xe6, 0xa4, 0xb6, 0x8e, 0xba, 0x8f, 0xe7, 0x91, 0x96, 0xe0, 0xb2, 0x16, 0xd6, 0x0b, 0x82, 0x1b, 0x00, 0x45, 0xfa, 0xb8, 0xad, 0xd4, 0xfa, 0xff, 0xf9}

    sig := ctx.CreateSignature("id1234")

    // Get SHA256 hash of "package" data and add it as a reference
    err := ctx.AddManifestRef(sig, "package", crypto.SHA256, digest)
    if err != nil {
        panic(err)
    }

    // Sign the signature
    signed, err := ctx.SignManifest(sig)
    if err != nil {
        panic(err)
    }

    // Serialize the signature.
    doc := etree.NewDocument()
    doc.SetRoot(signed)
    str, err := doc.WriteToString()
    if err != nil {
        panic(err)
    }

    println(str)
}

// Validate a signature against a root certificate
func validate(root *x509.Certificate, sig *etree.Element) {
    // Construct a signing context with one or more roots of trust.
    ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
        Roots: []*x509.Certificate{root},
    })

    manifest, err := ctx.ValidateManifest(signed)
    if err != nil {
        panic(err)
    }

    for idx := range manifest.References {
        ref := &manifest.References[idx]
        // Pass raw data of "package" for validating
        err := ctx.VerifyReference(ref, test_data)
        if err != nil {
            panic(err)
        }
    }
}
```

## Limitations

This library was created in order to [implement SAML 2.0](https://github.com/russellhaering/gosaml2)
without needing to execute a command line tool to create and validate signatures. It currently
only implements the subset of relevant standards needed to support that implementation, but
I hope to make it more complete over time. Contributions are welcome.
