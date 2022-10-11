package dsig

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"github.com/stretchr/testify/require"
)

const canonicalResponse = `
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:8080/v1/_saml_callback" ID="id9464273530269711243550013" InResponseTo="_8a64888e-0a14-4fb9-905d-65629b84786a" IssueInstant="2016-03-15T00:21:40.409Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></saml2p:StatusCode></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id9464273531132552093682430" IssueInstant="2016-03-15T00:21:40.409Z" Version="2.0"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#id9464273531132552093682430"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>DRYTp4xjc4Ec2+fJkQQ2KxFp/4raYPQYGrLtXTp2IhQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>UquJAMHALMZGSab+9XCc6L010djnsDx1wOP7b3LEQpEmGsKUEbblAuI1mdCaKi28VSP7h04S8M4x4xmgG6+RgYERKrMrc6DsW5Mto3nl6TaYQYUMVchp7vX1kDmuGqiEuYusrqIwQnFJNgt+SDAXODolfaJqKH02EMrzEeSFyfEiwaP8+R2jTQ9vqrMTX+t9b9nNo7F1N2sPWFGfk2TC3F5r4H+MF7n33cSny/qzPEEisldLF3LoTdnrPJdKpio/9kPr7ODhks+hwij82gYlvLCXkagmn76lSsAbUgsYoq1C3zvhYUHjTH2c0jmqHNwKT/8FA/oJtxx3N9agDpXEHw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">russell.haering@scaleft.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_8a64888e-0a14-4fb9-905d-65629b84786a" NotOnOrAfter="2016-03-15T00:26:40.409Z" Recipient="http://localhost:8080/v1/_saml_callback"></saml2:SubjectConfirmationData></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2016-03-15T00:16:40.409Z" NotOnOrAfter="2016-03-15T00:26:40.409Z"><saml2:AudienceRestriction><saml2:Audience>123</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2016-03-15T00:21:40.409Z" SessionIndex="_8a64888e-0a14-4fb9-905d-65629b84786a"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>`

const canonicalResponse2 = `
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:8080/v1/_saml_callback" ID="id103532804647787975381325" InResponseTo="_8699c655-c482-451a-9b7f-61668f140b47" IssueInstant="2016-03-16T01:02:57.682Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></saml2p:StatusCode></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id1035328046526588900089424" IssueInstant="2016-03-16T01:02:57.682Z" Version="2.0"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#id1035328046526588900089424"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>No1VyQlk8Xif4FiJ+haViwEQySIzBa14lGy0coCn0c8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>VSV8Vw47q7n/XZwaQOPWQeKI5ZA69fnGZyEFhex4xuaIfC+LOYnfd8q8qcZsm1M6kv47H/dR6YXRIMjPKXZeyX/MKcmGPCadqWFT7EWFvzuO/uy/AB/CL5ZCQiY9H/aOhDysO8glse1S+Y2K0CwvsoRwMfFiO2XOYhVOsngUSkCBdLIB6Oq4f+ZsK0rw/E79n9QUd8owDq3dVC18SFYYdcIVDhQppglyuBEZfu2tG06gD9jls7ZE8vjcMfHmhuHtxlH3ovNLB35NFO/VrCNdFqmD76GnEA98foiJxCX8vzNHF4rPUFXAEdiS4OdQAxb7jNNVoKVYuadunLygysZGSg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">russell.haering@scaleft.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_8699c655-c482-451a-9b7f-61668f140b47" NotOnOrAfter="2016-03-16T01:07:57.682Z" Recipient="http://localhost:8080/v1/_saml_callback"></saml2:SubjectConfirmationData></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2016-03-16T00:57:57.682Z" NotOnOrAfter="2016-03-16T01:07:57.682Z"><saml2:AudienceRestriction><saml2:Audience>123</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2016-03-16T01:02:57.682Z" SessionIndex="_8699c655-c482-451a-9b7f-61668f140b47"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>`

const rawResponse = `
<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:8080/v1/_saml_callback" ID="id1619705532971228558789260" InResponseTo="_213843b4-0693-47b8-b2f6-c41e316015cc" IssueInstant="2016-03-22T19:22:57.054Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id1619705532971228558789260"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>ijTqmVmDy7ssK+rvmJaCQ6AQaFaXz+HIN/r6O37B0eQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>G09fAYXGDLK+/jAekHsNL0RLo40Xm6+VwXmUj0IDIrvIIv/mJU5VD6ylOLnPezLDBVY9BJst1YCz+8krdvmQ8Stkd6qiN2bN/5KpCdika111YGpeNdMmg/E57ZG3S895hTNJQYOfCwhPFUtQuXLkspOaw81pcqOTr+bVSofJ8uQP7cVQa/ANxbjKAj0fhAuxAvZfiqPms5Stv4sNGpzULUDJl87CoEleHExGmpTsI7Qt3EvGToPMZXPHF4MGvuC0Z2ZD4iI6Pr7xk98t54PJtAX2qJu1tZqBJmL0Qcq5spl9W3yC1tAZuDeFLm1C4/T9crO2Q5WILP/tkw/yJ+ZttQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id16197055330485751495860275" IssueInstant="2016-03-22T19:22:57.054Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id16197055330485751495860275"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>zln6sheEO2JBdanrT5mZtJZ192tGHavuBpCFHQsJFVg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dHh6TWbnjtImyrfjPTX5QzE/6Vm/HsRWVvWWlvFAddf/CvhO4Kc5j8C7hvQoYMLhYuZMFFSReGysuDy5IscOJwTGhhcvb238qHSGGs6q8OUBCsmLSDAbIaGA++LV/tkUZ2ridGIi0yT81UOl1oT1batlHsK3eMyxkpnFmvBzIm4tGTzRkOPpYRLeiM9bxbKI+DM/623DCXyBCLYBzJo1O6QE02aLajwRMi/vmiV4LSiGlFcY9TtDCafdVJRv0tIQ25BQoT4feuHdr6S8xOSpGgRYH5ECamVOt4e079XdEkVUiSzQokiUkgDlTXEyerPLOVsOk4PW5nRs86sXIiGL5w==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">phoebe.simon@scaleft.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_213843b4-0693-47b8-b2f6-c41e316015cc" NotOnOrAfter="2016-03-22T19:27:57.054Z" Recipient="http://localhost:8080/v1/_saml_callback"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2016-03-22T19:17:57.054Z" NotOnOrAfter="2016-03-22T19:27:57.054Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AudienceRestriction><saml2:Audience>123</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2016-03-22T19:22:57.054Z" SessionIndex="_213843b4-0693-47b8-b2f6-c41e316015cc" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Attribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Phoebe</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Simon</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">phoebe.simon@scaleft.com</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>`

const expectedTransformation = `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:8080/v1/_saml_callback" ID="id1619705532971228558789260" InResponseTo="_213843b4-0693-47b8-b2f6-c41e316015cc" IssueInstant="2016-03-22T19:22:57.054Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id16197055330485751495860275" IssueInstant="2016-03-22T19:22:57.054Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id16197055330485751495860275"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>zln6sheEO2JBdanrT5mZtJZ192tGHavuBpCFHQsJFVg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dHh6TWbnjtImyrfjPTX5QzE/6Vm/HsRWVvWWlvFAddf/CvhO4Kc5j8C7hvQoYMLhYuZMFFSReGysuDy5IscOJwTGhhcvb238qHSGGs6q8OUBCsmLSDAbIaGA++LV/tkUZ2ridGIi0yT81UOl1oT1batlHsK3eMyxkpnFmvBzIm4tGTzRkOPpYRLeiM9bxbKI+DM/623DCXyBCLYBzJo1O6QE02aLajwRMi/vmiV4LSiGlFcY9TtDCafdVJRv0tIQ25BQoT4feuHdr6S8xOSpGgRYH5ECamVOt4e079XdEkVUiSzQokiUkgDlTXEyerPLOVsOk4PW5nRs86sXIiGL5w==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">phoebe.simon@scaleft.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_213843b4-0693-47b8-b2f6-c41e316015cc" NotOnOrAfter="2016-03-22T19:27:57.054Z" Recipient="http://localhost:8080/v1/_saml_callback"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2016-03-22T19:17:57.054Z" NotOnOrAfter="2016-03-22T19:27:57.054Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AudienceRestriction><saml2:Audience>123</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2016-03-22T19:22:57.054Z" SessionIndex="_213843b4-0693-47b8-b2f6-c41e316015cc" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Attribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Phoebe</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Simon</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">phoebe.simon@scaleft.com</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>`

const emptyReference = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_fd4fa4a5ab4b0c5e8bbc" Version="2.0" IssueInstant="2017-03-18T02:25:46Z" Destination="https://f1f51ddc.ngrok.io/api/sso/saml2/acs/58cafd0573d4f375b8e70e8e"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">a</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>1sl6AXnoU1CaZSx2MuDPLSKWAhGd6K40pcXe502u+Zw=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>jvr8AB4NzTi6FpZV27m6tsWtUXu4kPcCgx3vzE/T0om+DzOs0pkXhTD0H3oNqoWFOnpUo2dqO26nR58hzNpcIHPJPrHnNfboZJf68btzMNDa/OlnFtuwbFWo8Ac+rXS/Up3X5B3CNRlTz/W+ALZEuUHBGNZjE0Hw9Aav8YKAxiWx6uA9z0CCXUFVCbjmtrISMPSUQio+KjIc50j7BbVcezWTz/QB/ySsLEp/Zl4vCTCStFIkdZR/h3Ha5jovxsxuzERZ09x0l748dp8Cm449RnqOz4TIinxKz0xkqtFnbFmF1rFiGF8Vha2f7mdUqgmuy4ifevSI7G2ZQae3vQoNbw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDPDCCAiQCCQDydJgOlszqbzANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEQMA4GA1UEChMHSmFua3lDbzESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTE0MDMxMjE5NDYzM1oXDTI3MTExOTE5NDYzM1owYDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEDAOBgNVBAoTB0phbmt5Q28xEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMGvJpRTTasRUSPqcbqCG+ZnTAurnu0vVpIG9lzExnh11o/BGmzu7lB+yLHcEdwrKBBmpepDBPCYxpVajvuEhZdKFx/Fdy6j5mH3rrW0Bh/zd36CoUNjbbhHyTjeM7FN2yF3u9lcyubuvOzr3B3gX66IwJlU46+wzcQVhSOlMk2tXR+fIKQExFrOuK9tbX3JIBUqItpI+HnAow509CnM134svw8PTFLkR6/CcMqnDfDK1m993PyoC1Y+N4X9XkhSmEQoAlAHPI5LHrvuujM13nvtoVYvKYoj7ScgumkpWNEvX652LfXOnKYlkB8ZybuxmFfIkzedQrbJsyOhfL03cMECAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAeHwzqwnzGEkxjzSD47imXaTqtYyETZow7XwBc0ZaFS50qRFJUgKTAmKS1xQBP/qHpStsROT35DUxJAE6NY1Kbq3ZbCuhGoSlY0L7VzVT5tpu4EY8+Dq/u2EjRmmhoL7UkskvIZ2n1DdERtd+YUMTeqYl9co43csZwDno/IKomeN5qaPc39IZjikJ+nUC6kPFKeu/3j9rgHNlRtocI6S1FdtFz9OZMQlpr0JbUt2T3xS/YoQJn6coDmJL5GTiiKM6cOe+Ur1VwzS1JEDbSS2TWWhzq8ojLdrotYLGd9JOsoQhElmz+tMfCFQUFLExinPAyy7YHlSiVX13QH2XTu/iQQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_f6vEQCp4nBCsBY3MeMleLgS6GfmIPAwy" IssueInstant="2017-03-18T02:25:46.951Z"><saml:Issuer>a</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">arun+okta@launchdarkly.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2017-03-18T03:25:46.951Z" Recipient="https://f1f51ddc.ngrok.io/api/sso/saml2/acs/58cafd0573d4f375b8e70e8e"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2017-03-18T02:25:46.951Z" NotOnOrAfter="2017-03-18T03:25:46.951Z"><saml:AudienceRestriction><saml:Audience>b</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"><saml:AttributeValue xsi:type="xs:anyType">arun+okta@launchdarkly.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="Email"><saml:AttributeValue xsi:type="xs:anyType">arun+okta@launchdarkly.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="FirstName"><saml:AttributeValue xsi:type="xs:anyType">Arun</saml:AttributeValue></saml:Attribute><saml:Attribute Name="LastName"><saml:AttributeValue xsi:type="xs:anyType">Bhalla</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2017-03-18T02:25:46.951Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>`

const oktaCert = `
-----BEGIN CERTIFICATE-----
MIIDPDCCAiQCCQDydJgOlszqbzANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEQ
MA4GA1UEChMHSmFua3lDbzESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTE0MDMxMjE5
NDYzM1oXDTI3MTExOTE5NDYzM1owYDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNh
bGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEDAOBgNVBAoTB0phbmt5
Q28xEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMGvJpRTTasRUSPqcbqCG+ZnTAurnu0vVpIG9lzExnh11o/BGmzu7lB+
yLHcEdwrKBBmpepDBPCYxpVajvuEhZdKFx/Fdy6j5mH3rrW0Bh/zd36CoUNjbbhH
yTjeM7FN2yF3u9lcyubuvOzr3B3gX66IwJlU46+wzcQVhSOlMk2tXR+fIKQExFrO
uK9tbX3JIBUqItpI+HnAow509CnM134svw8PTFLkR6/CcMqnDfDK1m993PyoC1Y+
N4X9XkhSmEQoAlAHPI5LHrvuujM13nvtoVYvKYoj7ScgumkpWNEvX652LfXOnKYl
kB8ZybuxmFfIkzedQrbJsyOhfL03cMECAwEAATANBgkqhkiG9w0BAQUFAAOCAQEA
eHwzqwnzGEkxjzSD47imXaTqtYyETZow7XwBc0ZaFS50qRFJUgKTAmKS1xQBP/qH
pStsROT35DUxJAE6NY1Kbq3ZbCuhGoSlY0L7VzVT5tpu4EY8+Dq/u2EjRmmhoL7U
kskvIZ2n1DdERtd+YUMTeqYl9co43csZwDno/IKomeN5qaPc39IZjikJ+nUC6kPF
Keu/3j9rgHNlRtocI6S1FdtFz9OZMQlpr0JbUt2T3xS/YoQJn6coDmJL5GTiiKM6
cOe+Ur1VwzS1JEDbSS2TWWhzq8ojLdrotYLGd9JOsoQhElmz+tMfCFQUFLExinPA
yy7YHlSiVX13QH2XTu/iQQ==
-----END CERTIFICATE-----
`

func TestDigest(t *testing.T) {
	canonicalizer := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(canonicalResponse))
	require.NoError(t, err)

	vc := NewDefaultValidationContext(nil)
	digest, err := vc.digest(doc.Root(), "http://www.w3.org/2001/04/xmlenc#sha256", canonicalizer)
	require.NoError(t, err)
	require.Equal(t, "gvXF2ygtu4WbVYdepEtHFbgCZLfKW893eFF+x6gjX80=", base64.StdEncoding.EncodeToString(digest))

	doc = etree.NewDocument()
	err = doc.ReadFromBytes([]byte(canonicalResponse2))
	require.NoError(t, err)

	vc = NewDefaultValidationContext(nil)
	digest, err = vc.digest(doc.Root(), "http://www.w3.org/2001/04/xmlenc#sha256", canonicalizer)
	require.NoError(t, err)
	require.Equal(t, "npTAl6kraksBlCRlunbyD6nICTcfsDaHjPXVxoDPrw0=", base64.StdEncoding.EncodeToString(digest))

}

func TestTransform(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(rawResponse))
	require.NoError(t, err)

	vc := NewDefaultValidationContext(nil)

	el := doc.Root()

	sig, err := vc.findSignature(el)
	require.NoError(t, err)

	ref := &sig.SignedInfo.References[0]

	transformed, canonicalizer, err := vc.transform(el, sig, ref)
	require.NoError(t, err)
	require.NotEmpty(t, transformed)
	require.IsType(t, &c14N10ExclusiveCanonicalizer{}, canonicalizer)

	doc = etree.NewDocument()
	doc.SetRoot(transformed)

	str, err := doc.WriteToString()
	require.NoError(t, err)
	require.Equal(t, expectedTransformation, str)
}

func TestValidateWithEmptySignatureReference(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(emptyReference))
	require.NoError(t, err)

	sig := doc.FindElement("//" + SignatureTag)
	require.NotEmpty(t, sig)

	// Verify that Reference URI is empty
	signedInfo := sig.FindElement(childPath(sig.Space, SignedInfoTag))
	require.NotEmpty(t, signedInfo)
	reference := signedInfo.FindElement(childPath(sig.Space, ReferenceTag))
	require.NotEmpty(t, reference)
	require.Empty(t, reference.SelectAttr(URIAttr).Value)

	block, _ := pem.Decode([]byte(oktaCert))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse okta cert pem block")

	certStore := MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}
	vc := NewDefaultValidationContext(&certStore)

	el, err := vc.Validate(doc.Root())
	require.NoError(t, err)
	require.NotEmpty(t, el)
}

const (
	validateCert = `
-----BEGIN CERTIFICATE-----
MIIDnjCCAoagAwIBAgIGAXHxS90vMA0GCSqGSIb3DQEBCwUAMIGPMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNj
bzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMM
B2FzYS1kZXYxHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wHhcNMjAwNTA3
MjIzOTEzWhcNMzAwNTA3MjI0MDEzWjCBjzELMAkGA1UEBhMCVVMxEzARBgNVBAgM
CkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBE9r
dGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdhc2EtZGV2MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAqlQF++AiiKrOb5MVwN8YEgFCbOdLSO44hcJq2BYZYRd1oq1XVnz7
fVC49YgPXRafpXJx4v8jWyRQug2Sv4nEMvsbVzrV9N09/RHQ1MVa4QlTUEAhR0nS
zs897k2e6zObf/zx5ugE+GLx03+chYFVv1ICup0e0pRNS6OWHYFzZnLTlCEgAbay
HkbA82EViqgWD53BNQLvsS06WztF4pGISyxZ2NpycV5ejmI3ZSr6+bKXcgNAWr7i
nNBUaOwJG52/NlBAKaMq56Bljsni6YmZ/9V2DbQgTHSn4mu+++4FdDtFxBe1ZPID
JpjguXf9X183H7ZIkNOxkr+YlW02uzOpBQIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQBRX6NORxMS4cDWkG/PqlYcCjgwZA/8rd6dBkI+wJEzqrXmO1SSIQW6F48ahDVq
T0nicDYSnTkplIbKmooKjm2kkuCIjLwDiLldpZZ/Hpdj9rGDLC2jS6m3dr6OQvoT
DYPOXfrgMykc5VM+h9yx+iYbrilmmrhOwIPxxZDVUiRSB6Op716xk+9d0jlyrtFF
77B3YlKgMThQG6rguXViSwmViywWx+UQD6F1OzES8hoL54hfriOnlIpzZeamtJCo
/jcdeqYHi3ru+uHOBe91GFPtoDGCVuk7YvzlXKMdgyDx82+kRSnLWYMxaI2zleFY
nXHhoQk3K5iSdQT/gFgKJk89
-----END CERTIFICATE-----`
)

func TestValidateWithValid(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(validExample))
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(validateCert))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse okta cert pem block")

	certStore := MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}
	vc := NewDefaultValidationContext(&certStore)

	el, err := vc.Validate(doc.Root())
	require.NoError(t, err)
	require.NotEmpty(t, el)
}

func TestValidateWithModified(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(modifiedToBeTodd))
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(validateCert))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse okta cert pem block")

	certStore := MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}
	vc := NewDefaultValidationContext(&certStore)

	_, err = vc.Validate(doc.Root())
	require.Error(t, err)
}

func TestValidateWithModifiedAndSignatureEdited(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(spoofedAsTodd))
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(validateCert))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse okta cert pem block")

	certStore := MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}
	vc := NewDefaultValidationContext(&certStore)

	_, err = vc.Validate(doc.Root())
	require.Error(t, err)
}

const (
	validExample = `<?xml version="1.0" encoding="UTF-8"?><saml2p:Response Destination="https://dev.sudo.wtf:8443/v1/_saml_callback" ID="id149481635007085371203272055" InResponseTo="_ffea96b1-44a2-4a86-9683-45807984ab5b" IssueInstant="2020-09-01T17:51:12.176Z" Version="2.0" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exkrfkzzb7NyB3UeP0h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id149481635007085371203272055"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="xs" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>LwRDkrPmsTcUa++BIS5VJIANUlZN7zzdtjLfxfLAWds=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>UyjNRj9ZFbhApPhWEuVG26yACVqd25uyRKalSpp6XCdjrqKjI8Fmx7Q/IFkk5M755cxyFCQGttxThR6IPBk4Kp5OG2qGKXNHt7OQ8mumSLqWZpBJbmzNIKyG3nWlFoLVCoWPtBTd2gZM0aHOQp1JKa1birFBp2NofkEXbLeghZQ2YfCc4m8qgpZW5k/Itc0P/TVIkvPInjdSMyjm/ql4FUDO8cMkExJNR/i+GElW8cfnniWGcDPSiOqfIjLEDvZouXC7F1v5Wa0SmIxg7NJUTB+g6yrDN15VDq3KbHHTMlZXOZTXON2mBZOj5cwyyd4uX3aGSmYQiy/CGqBdqxrW2A==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDnjCCAoagAwIBAgIGAXHxS90vMA0GCSqGSIb3DQEBCwUAMIGPMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB2FzYS1kZXYxHDAaBgkqhkiG9w0BCQEWDWlu
Zm9Ab2t0YS5jb20wHhcNMjAwNTA3MjIzOTEzWhcNMzAwNTA3MjI0MDEzWjCBjzELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM
BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdhc2EtZGV2MRwwGgYJKoZIhvcN
AQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqlQF++Ai
iKrOb5MVwN8YEgFCbOdLSO44hcJq2BYZYRd1oq1XVnz7fVC49YgPXRafpXJx4v8jWyRQug2Sv4nE
MvsbVzrV9N09/RHQ1MVa4QlTUEAhR0nSzs897k2e6zObf/zx5ugE+GLx03+chYFVv1ICup0e0pRN
S6OWHYFzZnLTlCEgAbayHkbA82EViqgWD53BNQLvsS06WztF4pGISyxZ2NpycV5ejmI3ZSr6+bKX
cgNAWr7inNBUaOwJG52/NlBAKaMq56Bljsni6YmZ/9V2DbQgTHSn4mu+++4FdDtFxBe1ZPIDJpjg
uXf9X183H7ZIkNOxkr+YlW02uzOpBQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBRX6NORxMS4cDW
kG/PqlYcCjgwZA/8rd6dBkI+wJEzqrXmO1SSIQW6F48ahDVqT0nicDYSnTkplIbKmooKjm2kkuCI
jLwDiLldpZZ/Hpdj9rGDLC2jS6m3dr6OQvoTDYPOXfrgMykc5VM+h9yx+iYbrilmmrhOwIPxxZDV
UiRSB6Op716xk+9d0jlyrtFF77B3YlKgMThQG6rguXViSwmViywWx+UQD6F1OzES8hoL54hfriOn
lIpzZeamtJCo/jcdeqYHi3ru+uHOBe91GFPtoDGCVuk7YvzlXKMdgyDx82+kRSnLWYMxaI2zleFY
nXHhoQk3K5iSdQT/gFgKJk89</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion ID="id149481635007855341483658231" IssueInstant="2020-09-01T17:51:12.176Z" Version="2.0" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exkrfkzzb7NyB3UeP0h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id149481635007855341483658231"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="xs" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>nrIzAXSDsFwgvCm+ulbqfqZylzPxCBof6FYDcCEPdCQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>en3gX+6oIzNnkUWPbIAZp3rX8kHelobV3qqNSQ/JXQAZX7Up42D1pU6dWNc68xLe7RCDr3xV6zFG2bpi+NyZlsmqyKIXot5W6cM0BKkmRxQDcR1ThwP/VrFQ2HRxKTDUNeNCkTGBDfbwyD+w9RuCZO5JP2DX7DBHFBaTQQ+/9EhPSEx6yvJ05CwJ8eoNd/0ib+FCF1VDn9haP0viA8cOg3ApMkpwJsPXvMpb6U/q1tGgtzcyvqYDfAkWYGG0YPk3BsTUhSa7dN/ZI6O+7ZDGtWQohhYCAXBShrM7OWwJBDA5J+AXo7wFWKMt36u+MqGu2hBC58t7NpkZXehBRhvmmg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDnjCCAoagAwIBAgIGAXHxS90vMA0GCSqGSIb3DQEBCwUAMIGPMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB2FzYS1kZXYxHDAaBgkqhkiG9w0BCQEWDWlu
Zm9Ab2t0YS5jb20wHhcNMjAwNTA3MjIzOTEzWhcNMzAwNTA3MjI0MDEzWjCBjzELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM
BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdhc2EtZGV2MRwwGgYJKoZIhvcN
AQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqlQF++Ai
iKrOb5MVwN8YEgFCbOdLSO44hcJq2BYZYRd1oq1XVnz7fVC49YgPXRafpXJx4v8jWyRQug2Sv4nE
MvsbVzrV9N09/RHQ1MVa4QlTUEAhR0nSzs897k2e6zObf/zx5ugE+GLx03+chYFVv1ICup0e0pRN
S6OWHYFzZnLTlCEgAbayHkbA82EViqgWD53BNQLvsS06WztF4pGISyxZ2NpycV5ejmI3ZSr6+bKX
cgNAWr7inNBUaOwJG52/NlBAKaMq56Bljsni6YmZ/9V2DbQgTHSn4mu+++4FdDtFxBe1ZPIDJpjg
uXf9X183H7ZIkNOxkr+YlW02uzOpBQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBRX6NORxMS4cDW
kG/PqlYcCjgwZA/8rd6dBkI+wJEzqrXmO1SSIQW6F48ahDVqT0nicDYSnTkplIbKmooKjm2kkuCI
jLwDiLldpZZ/Hpdj9rGDLC2jS6m3dr6OQvoTDYPOXfrgMykc5VM+h9yx+iYbrilmmrhOwIPxxZDV
UiRSB6Op716xk+9d0jlyrtFF77B3YlKgMThQG6rguXViSwmViywWx+UQD6F1OzES8hoL54hfriOn
lIpzZeamtJCo/jcdeqYHi3ru+uHOBe91GFPtoDGCVuk7YvzlXKMdgyDx82+kRSnLWYMxaI2zleFY
nXHhoQk3K5iSdQT/gFgKJk89</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">phoebe.yu@okta.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_ffea96b1-44a2-4a86-9683-45807984ab5b" NotOnOrAfter="2020-09-01T17:56:12.176Z" Recipient="https://dev.sudo.wtf:8443/v1/_saml_callback"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2020-09-01T17:46:12.176Z" NotOnOrAfter="2020-09-01T17:56:12.176Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AudienceRestriction><saml2:Audience>https://dev.sudo.wtf:8443/v1/teams/asa</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2020-09-01T17:25:30.851Z" SessionIndex="_ffea96b1-44a2-4a86-9683-45807984ab5b" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Attribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Phoebe</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Yu</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">phoebe.yu@okta.com</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Login" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">phoebe.yu@okta.com</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="SSHUserName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string"/></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>`
	modifiedToBeTodd = `<?xml version="1.0" encoding="UTF-8"?><saml2p:Response Destination="https://dev.sudo.wtf:8443/v1/_saml_callback" ID="id149481635007085371203272055" InResponseTo="_ffea96b1-44a2-4a86-9683-45807984ab5b" IssueInstant="2020-09-01T17:51:12.176Z" Version="2.0" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exkrfkzzb7NyB3UeP0h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id149481635007085371203272055"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="xs" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>LwRDkrPmsTcUa++BIS5VJIANUlZN7zzdtjLfxfLAWds=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>UyjNRj9ZFbhApPhWEuVG26yACVqd25uyRKalSpp6XCdjrqKjI8Fmx7Q/IFkk5M755cxyFCQGttxThR6IPBk4Kp5OG2qGKXNHt7OQ8mumSLqWZpBJbmzNIKyG3nWlFoLVCoWPtBTd2gZM0aHOQp1JKa1birFBp2NofkEXbLeghZQ2YfCc4m8qgpZW5k/Itc0P/TVIkvPInjdSMyjm/ql4FUDO8cMkExJNR/i+GElW8cfnniWGcDPSiOqfIjLEDvZouXC7F1v5Wa0SmIxg7NJUTB+g6yrDN15VDq3KbHHTMlZXOZTXON2mBZOj5cwyyd4uX3aGSmYQiy/CGqBdqxrW2A==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDnjCCAoagAwIBAgIGAXHxS90vMA0GCSqGSIb3DQEBCwUAMIGPMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB2FzYS1kZXYxHDAaBgkqhkiG9w0BCQEWDWlu
Zm9Ab2t0YS5jb20wHhcNMjAwNTA3MjIzOTEzWhcNMzAwNTA3MjI0MDEzWjCBjzELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM
BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdhc2EtZGV2MRwwGgYJKoZIhvcN
AQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqlQF++Ai
iKrOb5MVwN8YEgFCbOdLSO44hcJq2BYZYRd1oq1XVnz7fVC49YgPXRafpXJx4v8jWyRQug2Sv4nE
MvsbVzrV9N09/RHQ1MVa4QlTUEAhR0nSzs897k2e6zObf/zx5ugE+GLx03+chYFVv1ICup0e0pRN
S6OWHYFzZnLTlCEgAbayHkbA82EViqgWD53BNQLvsS06WztF4pGISyxZ2NpycV5ejmI3ZSr6+bKX
cgNAWr7inNBUaOwJG52/NlBAKaMq56Bljsni6YmZ/9V2DbQgTHSn4mu+++4FdDtFxBe1ZPIDJpjg
uXf9X183H7ZIkNOxkr+YlW02uzOpBQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBRX6NORxMS4cDW
kG/PqlYcCjgwZA/8rd6dBkI+wJEzqrXmO1SSIQW6F48ahDVqT0nicDYSnTkplIbKmooKjm2kkuCI
jLwDiLldpZZ/Hpdj9rGDLC2jS6m3dr6OQvoTDYPOXfrgMykc5VM+h9yx+iYbrilmmrhOwIPxxZDV
UiRSB6Op716xk+9d0jlyrtFF77B3YlKgMThQG6rguXViSwmViywWx+UQD6F1OzES8hoL54hfriOn
lIpzZeamtJCo/jcdeqYHi3ru+uHOBe91GFPtoDGCVuk7YvzlXKMdgyDx82+kRSnLWYMxaI2zleFY
nXHhoQk3K5iSdQT/gFgKJk89</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion ID="id149481635007855341483658231" IssueInstant="2020-09-01T17:51:12.176Z" Version="2.0" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exkrfkzzb7NyB3UeP0h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id149481635007855341483658231"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="xs" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>nrIzAXSDsFwgvCm+ulbqfqZylzPxCBof6FYDcCEPdCQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>en3gX+6oIzNnkUWPbIAZp3rX8kHelobV3qqNSQ/JXQAZX7Up42D1pU6dWNc68xLe7RCDr3xV6zFG2bpi+NyZlsmqyKIXot5W6cM0BKkmRxQDcR1ThwP/VrFQ2HRxKTDUNeNCkTGBDfbwyD+w9RuCZO5JP2DX7DBHFBaTQQ+/9EhPSEx6yvJ05CwJ8eoNd/0ib+FCF1VDn9haP0viA8cOg3ApMkpwJsPXvMpb6U/q1tGgtzcyvqYDfAkWYGG0YPk3BsTUhSa7dN/ZI6O+7ZDGtWQohhYCAXBShrM7OWwJBDA5J+AXo7wFWKMt36u+MqGu2hBC58t7NpkZXehBRhvmmg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDnjCCAoagAwIBAgIGAXHxS90vMA0GCSqGSIb3DQEBCwUAMIGPMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB2FzYS1kZXYxHDAaBgkqhkiG9w0BCQEWDWlu
Zm9Ab2t0YS5jb20wHhcNMjAwNTA3MjIzOTEzWhcNMzAwNTA3MjI0MDEzWjCBjzELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM
BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdhc2EtZGV2MRwwGgYJKoZIhvcN
AQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqlQF++Ai
iKrOb5MVwN8YEgFCbOdLSO44hcJq2BYZYRd1oq1XVnz7fVC49YgPXRafpXJx4v8jWyRQug2Sv4nE
MvsbVzrV9N09/RHQ1MVa4QlTUEAhR0nSzs897k2e6zObf/zx5ugE+GLx03+chYFVv1ICup0e0pRN
S6OWHYFzZnLTlCEgAbayHkbA82EViqgWD53BNQLvsS06WztF4pGISyxZ2NpycV5ejmI3ZSr6+bKX
cgNAWr7inNBUaOwJG52/NlBAKaMq56Bljsni6YmZ/9V2DbQgTHSn4mu+++4FdDtFxBe1ZPIDJpjg
uXf9X183H7ZIkNOxkr+YlW02uzOpBQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBRX6NORxMS4cDW
kG/PqlYcCjgwZA/8rd6dBkI+wJEzqrXmO1SSIQW6F48ahDVqT0nicDYSnTkplIbKmooKjm2kkuCI
jLwDiLldpZZ/Hpdj9rGDLC2jS6m3dr6OQvoTDYPOXfrgMykc5VM+h9yx+iYbrilmmrhOwIPxxZDV
UiRSB6Op716xk+9d0jlyrtFF77B3YlKgMThQG6rguXViSwmViywWx+UQD6F1OzES8hoL54hfriOn
lIpzZeamtJCo/jcdeqYHi3ru+uHOBe91GFPtoDGCVuk7YvzlXKMdgyDx82+kRSnLWYMxaI2zleFY
nXHhoQk3K5iSdQT/gFgKJk89</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">todd@okta.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_ffea96b1-44a2-4a86-9683-45807984ab5b" NotOnOrAfter="2020-09-01T17:56:12.176Z" Recipient="https://dev.sudo.wtf:8443/v1/_saml_callback"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2020-09-01T17:46:12.176Z" NotOnOrAfter="2020-09-01T17:56:12.176Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AudienceRestriction><saml2:Audience>https://dev.sudo.wtf:8443/v1/teams/asa</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2020-09-01T17:25:30.851Z" SessionIndex="_ffea96b1-44a2-4a86-9683-45807984ab5b" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Attribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Phoebe</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Yu</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">phoebe.yu@okta.com</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Login" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">phoebe.yu@okta.com</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="SSHUserName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string"/></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>`
	spoofedAsTodd = `<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" Destination="https://dev.sudo.wtf:8443/v1/_saml_callback" ID="id149481635007085371203272055" InResponseTo="_ffea96b1-44a2-4a86-9683-45807984ab5b" IssueInstant="2020-09-01T17:51:12.176Z" Version="2.0"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exkrfkzzb7NyB3UeP0h7</saml2:Issuer><dsx:Signature xmlns:ds="" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:dsx="http://www.w3.org/2000/09/xmldsig#"><dsx:SignatureValue>UyjNRj9ZFbhApPhWEuVG26yACVqd25uyRKalSpp6XCdjrqKjI8Fmx7Q/IFkk5M755cxyFCQGttxThR6IPBk4Kp5OG2qGKXNHt7OQ8mumSLqWZpBJbmzNIKyG3nWlFoLVCoWPtBTd2gZM0aHOQp1JKa1birFBp2NofkEXbLeghZQ2YfCc4m8qgpZW5k/Itc0P/TVIkvPInjdSMyjm/ql4FUDO8cMkExJNR/i+GElW8cfnniWGcDPSiOqfIjLEDvZouXC7F1v5Wa0SmIxg7NJUTB+g6yrDN15VDq3KbHHTMlZXOZTXON2mBZOj5cwyyd4uX3aGSmYQiy/CGqBdqxrW2A==</dsx:SignatureValue><dsx:KeyInfo><dsx:X509Data><dsx:X509Certificate>MIIDnjCCAoagAwIBAgIGAXHxS90vMA0GCSqGSIb3DQEBCwUAMIGPMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB2FzYS1kZXYxHDAaBgkqhkiG9w0BCQEWDWlu
Zm9Ab2t0YS5jb20wHhcNMjAwNTA3MjIzOTEzWhcNMzAwNTA3MjI0MDEzWjCBjzELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM
BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdhc2EtZGV2MRwwGgYJKoZIhvcN
AQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqlQF++Ai
iKrOb5MVwN8YEgFCbOdLSO44hcJq2BYZYRd1oq1XVnz7fVC49YgPXRafpXJx4v8jWyRQug2Sv4nE
MvsbVzrV9N09/RHQ1MVa4QlTUEAhR0nSzs897k2e6zObf/zx5ugE+GLx03+chYFVv1ICup0e0pRN
S6OWHYFzZnLTlCEgAbayHkbA82EViqgWD53BNQLvsS06WztF4pGISyxZ2NpycV5ejmI3ZSr6+bKX
cgNAWr7inNBUaOwJG52/NlBAKaMq56Bljsni6YmZ/9V2DbQgTHSn4mu+++4FdDtFxBe1ZPIDJpjg
uXf9X183H7ZIkNOxkr+YlW02uzOpBQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBRX6NORxMS4cDW
kG/PqlYcCjgwZA/8rd6dBkI+wJEzqrXmO1SSIQW6F48ahDVqT0nicDYSnTkplIbKmooKjm2kkuCI
jLwDiLldpZZ/Hpdj9rGDLC2jS6m3dr6OQvoTDYPOXfrgMykc5VM+h9yx+iYbrilmmrhOwIPxxZDV
UiRSB6Op716xk+9d0jlyrtFF77B3YlKgMThQG6rguXViSwmViywWx+UQD6F1OzES8hoL54hfriOn
lIpzZeamtJCo/jcdeqYHi3ru+uHOBe91GFPtoDGCVuk7YvzlXKMdgyDx82+kRSnLWYMxaI2zleFY
nXHhoQk3K5iSdQT/gFgKJk89</dsx:X509Certificate></dsx:X509Data></dsx:KeyInfo><dsx:SignedInfo xmlns:ds="" xmlns:dsx="http://www.w3.org/2000/09/xmldsig#"><dsx:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><dsx:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><dsx:Reference URI="#id149481635007085371203272055"><dsx:Transforms><dsx:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><dsx:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></dsx:Transform></dsx:Transforms><dsx:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><dsx:DigestValue>cFNZV8Uh+WR8yPmPqAfktrxO0DtlNv7WIVf/iQbuwR0=</dsx:DigestValue></dsx:Reference></dsx:SignedInfo><ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id149481635007085371203272055"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>LwRDkrPmsTcUa++BIS5VJIANUlZN7zzdtjLfxfLAWds=</ds:DigestValue></ds:Reference></ds:SignedInfo></dsx:Signature><saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="id149481635007855341483658231" IssueInstant="2020-09-01T17:51:12.176Z" Version="2.0"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exkrfkzzb7NyB3UeP0h7</saml2:Issuer><dsx:Signature xmlns:ds="" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:dsx="http://www.w3.org/2000/09/xmldsig#"><dsx:SignatureValue>en3gX+6oIzNnkUWPbIAZp3rX8kHelobV3qqNSQ/JXQAZX7Up42D1pU6dWNc68xLe7RCDr3xV6zFG2bpi+NyZlsmqyKIXot5W6cM0BKkmRxQDcR1ThwP/VrFQ2HRxKTDUNeNCkTGBDfbwyD+w9RuCZO5JP2DX7DBHFBaTQQ+/9EhPSEx6yvJ05CwJ8eoNd/0ib+FCF1VDn9haP0viA8cOg3ApMkpwJsPXvMpb6U/q1tGgtzcyvqYDfAkWYGG0YPk3BsTUhSa7dN/ZI6O+7ZDGtWQohhYCAXBShrM7OWwJBDA5J+AXo7wFWKMt36u+MqGu2hBC58t7NpkZXehBRhvmmg==</dsx:SignatureValue><dsx:KeyInfo><dsx:X509Data><dsx:X509Certificate>MIIDnjCCAoagAwIBAgIGAXHxS90vMA0GCSqGSIb3DQEBCwUAMIGPMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB2FzYS1kZXYxHDAaBgkqhkiG9w0BCQEWDWlu
Zm9Ab2t0YS5jb20wHhcNMjAwNTA3MjIzOTEzWhcNMzAwNTA3MjI0MDEzWjCBjzELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM
BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdhc2EtZGV2MRwwGgYJKoZIhvcN
AQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqlQF++Ai
iKrOb5MVwN8YEgFCbOdLSO44hcJq2BYZYRd1oq1XVnz7fVC49YgPXRafpXJx4v8jWyRQug2Sv4nE
MvsbVzrV9N09/RHQ1MVa4QlTUEAhR0nSzs897k2e6zObf/zx5ugE+GLx03+chYFVv1ICup0e0pRN
S6OWHYFzZnLTlCEgAbayHkbA82EViqgWD53BNQLvsS06WztF4pGISyxZ2NpycV5ejmI3ZSr6+bKX
cgNAWr7inNBUaOwJG52/NlBAKaMq56Bljsni6YmZ/9V2DbQgTHSn4mu+++4FdDtFxBe1ZPIDJpjg
uXf9X183H7ZIkNOxkr+YlW02uzOpBQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBRX6NORxMS4cDW
kG/PqlYcCjgwZA/8rd6dBkI+wJEzqrXmO1SSIQW6F48ahDVqT0nicDYSnTkplIbKmooKjm2kkuCI
jLwDiLldpZZ/Hpdj9rGDLC2jS6m3dr6OQvoTDYPOXfrgMykc5VM+h9yx+iYbrilmmrhOwIPxxZDV
UiRSB6Op716xk+9d0jlyrtFF77B3YlKgMThQG6rguXViSwmViywWx+UQD6F1OzES8hoL54hfriOn
lIpzZeamtJCo/jcdeqYHi3ru+uHOBe91GFPtoDGCVuk7YvzlXKMdgyDx82+kRSnLWYMxaI2zleFY
nXHhoQk3K5iSdQT/gFgKJk89</dsx:X509Certificate></dsx:X509Data></dsx:KeyInfo><dsx:SignedInfo xmlns:ds="" xmlns:dsx="http://www.w3.org/2000/09/xmldsig#"><dsx:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><dsx:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><dsx:Reference URI="#id149481635007855341483658231"><dsx:Transforms><dsx:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><dsx:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></dsx:Transform></dsx:Transforms><dsx:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><dsx:DigestValue>JaSnCMsKnmGg4Ew3yXuUdRPCmlzJngSWW1RZYH15Exk=</dsx:DigestValue></dsx:Reference></dsx:SignedInfo><ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id149481635007855341483658231"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>nrIzAXSDsFwgvCm+ulbqfqZylzPxCBof6FYDcCEPdCQ=</ds:DigestValue></ds:Reference></ds:SignedInfo></dsx:Signature><saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">todd@okta.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_ffea96b1-44a2-4a86-9683-45807984ab5b" NotOnOrAfter="2020-09-01T17:56:12.176Z" Recipient="https://dev.sudo.wtf:8443/v1/_saml_callback"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2020-09-01T17:46:12.176Z" NotOnOrAfter="2020-09-01T17:56:12.176Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AudienceRestriction><saml2:Audience>https://dev.sudo.wtf:8443/v1/teams/asa</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2020-09-01T17:25:30.851Z" SessionIndex="_ffea96b1-44a2-4a86-9683-45807984ab5b" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Attribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Phoebe</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Yu</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">phoebe.yu@okta.com</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Login" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">phoebe.yu@okta.com</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="SSHUserName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string"/></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>`
)
