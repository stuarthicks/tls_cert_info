# tls_cert_info

Print some of the most commonly checked attributes of a TLS certificate without having to remember a very long set of openssl flags. Essentially a replacement for this:

```
❯ openssl s_client \
  -connect github.com:443 \
  -servername github.com \
  -showcerts < /dev/null 2>/dev/null \
  | openssl x509 \
    -noout \
    -issuer \
    -subject \
    -ext subjectAltName \
    -startdate \
    -enddate

issuer=C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo ECC Domain Validation Secure Server CA
subject=CN=github.com
X509v3 Subject Alternative Name:
    DNS:github.com, DNS:www.github.com
notBefore=Mar  7 00:00:00 2024 GMT
notAfter=Mar  7 23:59:59 2025 GMT
```

## Install

Using Homebrew:

    brew install stuarthicks/brews/tls_cert_info

Using Go:

    go install github.com/stuarthicks/tls_cert_info@latest

## Usage

```
❯ tls_cert_info -h

Usage of tls_cert_info:
  -domain string
        Domain to connect to
  -port string
        Override port to connect to (default "443")
  -sni string
        Override SNI domain (default matches -domain)
```

Example:

```
❯ tls_cert_info -domain github.com

Issuer:		Sectigo Limited
Common Name:	github.com
Subject Alternative Names:
	github.com
	www.github.com
Start Date:	2024-03-07
End Date:	2025-03-07
Remaining Days:	292
```

