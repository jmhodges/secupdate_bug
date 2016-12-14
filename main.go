package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"time"

	"k8s.io/client-go/1.4/kubernetes"
	"k8s.io/client-go/1.4/rest"
)

var (
	secretName = flag.String("secName", "foobar-tls", "secret name to be updating")
)

func main() {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("unable to make config for kubernetes client: %s", err)
	}
	client := kubernetes.NewForConfigOrDie(restConfig).Core()
	secClient := client.Secrets("default")
	sec, err := secClient.Get(*secretName)
	if err != nil {
		log.Fatalf("error grabbing secret %#v: %s", *secretName, err)
	}
	domBytes := make([]byte, 8)
	_, err = rand.Read(domBytes)
	if err != nil {
		log.Fatalf("unable to get random bytes for new domain name: %s", err)
	}
	newDomain := hex.EncodeToString(domBytes)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("GenerateKey failed: %s", err)
	}
	pub := priv.Public()
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	t := time.Now()
	notBefore := t.Add(-1 * time.Hour)
	notAfter := t.Add(100 * 24 * time.Hour)
	crtTmpl := &x509.Certificate{
		SerialNumber:       serialNumber,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			CommonName: newDomain,
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	crtDERBytes, err := x509.CreateCertificate(rand.Reader, crtTmpl, crtTmpl, pub, priv)
	if err != nil {
		log.Fatalf("CreateCertificate failed: %s", err)
	}

	keyDERBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("MarshalECPrivateKey failed: %s", err)
	}
	keyBuf := &bytes.Buffer{}
	err = pem.Encode(keyBuf, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDERBytes,
	})
	if err != nil {
		log.Fatalf("private key pem.Encode: %s", err)
	}
	keyBytes := keyBuf.Bytes()

	crtBuf := &bytes.Buffer{}
	err = pem.Encode(crtBuf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtDERBytes,
	})
	if err != nil {
		log.Fatalf("cert pem.Encode: %s", err)
	}
	crtBytes := crtBuf.Bytes()
	if sec.Data == nil {
		sec.Data = make(map[string][]byte)
	}
	sec.Data["tls.crt"] = crtBytes
	sec.Data["tls.key"] = keyBytes
	_, err = secClient.Update(sec)
	if err != nil {
		log.Fatalf("kubernetes secret Update failed: %s", err)
	}
	fmt.Println("updated cert secret with domain", newDomain)
}
