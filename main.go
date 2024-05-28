package main

import (
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
	var domain, port, sni string
	flag.StringVar(&domain, "domain", "", "Domain to connect to")
	flag.StringVar(&port, "port", "443", "Override port to connect to")
	flag.StringVar(&sni, "sni", "", "Override SNI domain (default matches -domain)")

	var printJSON bool
	flag.BoolVar(&printJSON, "json", false, "Print all cert information as JSON")

	flag.Parse()

	if sni == "" {
		sni = domain
	}

	var conf = tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	}

	conn, err := tls.Dial("tcp", domain+":"+port, &conf)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer conn.Close()

	var certs = conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		if printJSON {
			json.NewEncoder(os.Stdout).Encode(cert)
			os.Exit(0)
		}
		var sans = cert.DNSNames
		sort.Strings(sans)
		fmt.Printf("Fingerprint:\t%s\n", strings.ReplaceAll(fmt.Sprintf("SHA1=% X", sha1.Sum(cert.Raw)), " ", ":"))
		fmt.Printf("Issuer:\t\t%s\n", cert.Issuer.String())
		fmt.Printf("Subject:\t%s\n", cert.Subject.String())
		fmt.Printf("Subject Alternative Names:\n")
		for _, san := range sans {
			fmt.Printf("\t%s\n", san)
		}
		fmt.Printf("Start Date:\t%s\n", cert.NotBefore.Format("2006-01-02"))
		fmt.Printf("End Date:\t%s\n", cert.NotAfter.Format("2006-01-02"))
		fmt.Printf("Remaining Days:\t%d\n", int(time.Until(cert.NotAfter).Hours()/24))

		// Stop after first cert. Subsequent certs are intermediate or root CAs.
		os.Exit(0)
	}
}
