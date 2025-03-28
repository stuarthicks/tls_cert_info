package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	var address, port, sni, ip string
	var akamaiStaging bool
	flag.StringVar(&address, "domain", "", "Domain to connect to [Deprecated: use -address]")
	flag.StringVar(&address, "address", "", "Address to connect to. Can be a hostname or IP address.")
	flag.StringVar(&ip, "ip", "", "Override IP address to connect to (default is to resolve -domain)")
	flag.StringVar(&port, "port", "443", "Override port to connect to")
	flag.StringVar(&sni, "sni", "", "Override SNI domain (default matches -domain)")
	flag.BoolVar(&akamaiStaging, "akamai-staging", false, "Resolve the -domain using Akamai's Staging Envionment")

	var printJSON bool
	flag.BoolVar(&printJSON, "json", false, "Print all cert information as JSON")

	flag.Parse()

	if sni == "" {
		sni = address
	}

	if akamaiStaging {
		address += ".edgekey-staging.net"
	}

	var conf = tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	}

	if address == "" {
		log.Fatal("please provide an -address to connect to")
	}

	conn, err := tls.Dial("tcp", address+":"+port, &conf)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer conn.Close()

	var certs = conn.ConnectionState().PeerCertificates
	for i, cert := range certs {
		if printJSON {
			if err := json.NewEncoder(os.Stdout).Encode(cert); err != nil {
				log.Fatalf("failed to encode response as json: %s", err.Error())
			}
			os.Exit(0)
		}
		var certType = "Leaf"
		if cert.IsCA {
			certType = "Intermediate"
		}
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			certType = "Root"
		}
		fmt.Printf("\n--- Certificate %d (%s) ---\n", i+1, certType)
		var sans = cert.DNSNames
		sort.Strings(sans)
		fmt.Printf("Fingerprint:\t%s\n", strings.ReplaceAll(fmt.Sprintf("SHA1=% X", sha1.Sum(cert.Raw)), " ", ":"))
		fmt.Printf("Subject:\t%s\n", cert.Subject.String())
		fmt.Printf("Issuer:\t\t%s\n", cert.Issuer.String())
		if len(sans) > 0 {
			fmt.Printf("Subject Alternative Names:\n")
			for _, san := range sans {
				fmt.Printf("\t%s\n", san)
			}
		}
		fmt.Printf("Start Date:\t%s\n", cert.NotBefore.Format("2006-01-02"))
		fmt.Printf("End Date:\t%s\n", cert.NotAfter.Format("2006-01-02"))
		fmt.Printf("Remaining Days:\t%d\n", int(time.Until(cert.NotAfter).Hours()/24))

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		if len(cert.OCSPServer) > 1 || len(cert.IssuingCertificateURL) > 0 {
			fmt.Printf("\n")
			fmt.Printf("X509v3 Extension - Authority Information Access\n")
			fmt.Printf("OCSP Server: %s\n", strings.Join(cert.OCSPServer, ", "))
			fmt.Printf("Issuing Certificate URL: %s\n", strings.Join(cert.IssuingCertificateURL, ", "))
		}
	}
}
