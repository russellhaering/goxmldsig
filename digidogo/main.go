package main

import (
	"archive/zip"
	"crypto/x509"
	"io/ioutil"
	"log"
	"mime"
	"os"
	"path"
	"regexp"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func main() {
	inputName := os.Args[1]
	mimetype := mime.TypeByExtension(inputName)
	if mimetype == "" {
		mimetype = map[string]string{
			".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		}[path.Ext(inputName)]
	}

	// Generate a key and self-signed certificate for signing
	randomKeyStore := dsig.RandomKeyStoreForTest()
	ctx := dsig.NewDefaultSigningContext(randomKeyStore)
	_, cert, err := randomKeyStore.GetKeyPair()
	if err != nil {
		panic(err)
	}
	root, err := x509.ParseCertificate(cert)
	if err != nil {
		panic(err)
	}
	validCtx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{root},
	})

	// Sign the element
	input, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	signedElement, err := ctx.SignXAdES(path.Base(inputName), mimetype, input)
	if err != nil {
		panic(err)
	}
	if _, err := validCtx.Validate(signedElement); err != nil {
		log.Fatal("Failed Validation: ", err)
		panic(err)
	}

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8" standalone="no"`)
	doc.SetRoot(signedElement)

	edoc, err := os.Create(
		string(regexp.MustCompile("\\.[^\\.]+$").ReplaceAll(
			[]byte(inputName), []byte(".edoc"),
		)),
	)
	if err != nil {
		panic(err)
	}
	w := zip.NewWriter(edoc)

	mimetypeFile, err := w.Create("mimetype")
	if err != nil {
		panic(err)
	}
	mimetypeFile.Write([]byte("application/vnd.etsi.asic-e+zip"))

	{
		f, err := w.Create("META-INF/manifest.xml")
		if err != nil {
			panic(err)
		}

		root := etree.NewDocument()
		root.CreateProcInst("xml", `version="1.0" encoding="UTF-8" standalone="no"`)
		manifest := root.CreateElement("manifest")
		manifest.Space = "manifest"
		manifest.Attr = append(manifest.Attr, etree.Attr{
			Space: "xmlns",
			Key:   "manifest",
			Value: "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0",
		})

		manifest.Attr = append(manifest.Attr, etree.Attr{
			Space: "manifest",
			Key:   "version",
			Value: "1.2",
		})

		entry := manifest.CreateElement("file-entry")
		entry.Space = "manifest"
		entry.Attr = append(entry.Attr, etree.Attr{
			Space: "manifest",
			Key:   "full-path",
			Value: "/",
		})
		entry.Attr = append(entry.Attr, etree.Attr{
			Space: "manifest",
			Key:   "media-type",
			Value: "application/vnd.etsi.asic-e+zip",
		})

		fileEntry := manifest.CreateElement("file-entry")
		fileEntry.Space = "manifest"
		fileEntry.Attr = append(fileEntry.Attr, etree.Attr{
			Space: "manifest",
			Key:   "full-path",
			Value: path.Base(inputName),
		})
		fileEntry.Attr = append(fileEntry.Attr, etree.Attr{
			Space: "manifest",
			Key:   "media-type",
			Value: mimetype,
		})

		output, err := root.WriteToString()
		println(output)
		if err != nil {
			panic(err)
		}
		f.Write([]byte(output))
	}

	edocSigns, err := w.Create("META-INF/edoc-signatures-S1.xml")
	if err != nil {
		panic(err)
	}
	str, err := doc.WriteToString()
	if err != nil {
		panic(err)
	}
	println(str)
	edocSigns.Write([]byte(str))

	f, err := w.Create(path.Base(inputName))
	if err != nil {
		panic(err)
	}
	f.Write(input)

	if err := w.Close(); err != nil {
		log.Fatal(err)
	}
	if err := edoc.Close(); err != nil {
		log.Fatal(err)
	}
}
