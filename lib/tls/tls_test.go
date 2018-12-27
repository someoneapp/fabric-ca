/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls

import (
	"crypto"
	"crypto/rand"
	//"crypto/rsa"
	//"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"
	"path/filepath"

	"github.com/stretchr/testify/assert"
	cspx509 "github.com/hyperledger/fabric/bccsp/x509"
	"github.com/warm3snow/gmsm/sm2"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/signer"
)

const (
	configDir   = "../../testdata"
	caCert      = "root.pem"
	certFile    = "tls_client-cert.pem"
	keyFile     = "tls_client-key.pem"
	expiredCert = "../../testdata/expiredcert.pem"
)

type testTLSConfig struct {
	TLS *ClientTLSConfig
}

func TestGetClientTLSConfig(t *testing.T) {

	cfg := &ClientTLSConfig{
		CertFiles: []string{"root.pem"},
		Client: KeyCertFiles{
			KeyFile:  "tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}

	err := AbsTLSClient(cfg, configDir)
	if err != nil {
		t.Errorf("Failed to get absolute path for client TLS config: %s", err)
	}

	_, err = GetClientTLSConfig(cfg, nil)
	if err != nil {
		t.Errorf("Failed to get TLS Config: %s", err)
	}

}

func TestGetClientTLSConfigInvalidArgs(t *testing.T) {
	// 1.
	cfg := &ClientTLSConfig{
		CertFiles: []string{"root.pem"},
		Client: KeyCertFiles{
			KeyFile:  "no_tls_client-key.pem",
			CertFile: "no_tls_client-cert.pem",
		},
	}
	_, err := GetClientTLSConfig(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "open no_tls_client-cert.pem: no such file or directory")

	// 2.
	cfg = &ClientTLSConfig{
		CertFiles: nil,
		Client: KeyCertFiles{
			KeyFile:  "tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}
	AbsTLSClient(cfg, configDir)
	_, err = GetClientTLSConfig(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No TLS certificate files were provided")

	// 3.
	cfg = &ClientTLSConfig{
		CertFiles: nil,
		Client: KeyCertFiles{
			KeyFile:  "no-tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}
	AbsTLSClient(cfg, configDir)
	_, err = GetClientTLSConfig(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no-tls_client-key.pem: no such file or directory")

	// 4.
	cfg = &ClientTLSConfig{
		CertFiles: nil,
		Client: KeyCertFiles{
			KeyFile:  "",
			CertFile: "",
		},
	}
	_, err = GetClientTLSConfig(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No TLS certificate files were provided")

	// 5.
	cfg = &ClientTLSConfig{
		CertFiles: []string{"no-root.pem"},
		Client: KeyCertFiles{
			KeyFile:  "tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}
	AbsTLSClient(cfg, configDir)
	_, err = GetClientTLSConfig(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no-root.pem: no such file or directory")
}

func TestAbsServerTLSConfig(t *testing.T) {
	cfg := &ServerTLSConfig{
		KeyFile:  "tls_client-key.pem",
		CertFile: "tls_client-cert.pem",
		ClientAuth: ClientAuth{
			CertFiles: []string{"root.pem"},
		},
	}

	err := AbsTLSServer(cfg, configDir)
	if err != nil {
		t.Errorf("Failed to get absolute path for server TLS config: %s", err)
	}
}

func TestCheckCertDates(t *testing.T) {
	err := checkCertDates(expiredCert)
	if err == nil {
		assert.Error(t, errors.New("Expired certificate should have resulted in an error"))
	}

	TestCreateCertificate(t)

	err = checkCertDates("tls-cert.pem")
	if err == nil {
		assert.Error(t, errors.New("Future valid certificate should have resulted in an error"))
	}
	if err != nil {
		assert.Contains(t, err.Error(), "Certificate provided not valid until later date")
	}

	os.Remove("tls-cert.pem")
}
type sm2PrivateKey struct {
	Version       *big.Int
	PrivateKey    *big.Int
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
var oidNamedCurveSm2  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
func TestCreateCertificate(t *testing.T){
	// Dynamically create a certificate with future valid date for testing purposes
	subject := subjectTemplate()
	subject.Organization = []string{"Hyperledger Fabric"}
	subject.OrganizationalUnit = []string{"WWW"}
	subject.CommonName = "localhost"

	var capriv bccsp.Key
	var s crypto.Signer
	keystore := "/home/yuandandan/gopath/src/github.com/hyperledger/fabric-ca"
	opts := &factory.FactoryOpts{
		ProviderName: "SW",
		SwOpts: &factory.SwOpts{
			HashFamily: "SM3",
			SecLevel:   256,
			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: keystore,
			},
		},
	}
	csp, err := factory.GetBCCSPFromOpts(opts)
	if err == nil {
		// generate a key
		capriv, err = csp.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
		if err == nil {
			// create a crypto.Signer
			s, err = signer.New(csp, capriv)
		}
	}

	certTemplate := &x509.Certificate{
		IsCA: true,
		BasicConstraintsValid: true,
		Subject: subject,
		SubjectKeyId:          capriv.SKI(),
		SerialNumber:          big.NewInt(1234),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign,
	}
	

	// create a self-signed certificate. template = parent
	var parent = certTemplate
	caPub, err := GetPublicKey(capriv)
	if err != nil {
		assert.Error(t, fmt.Errorf("Error occurred during get ca pubkey: %s", err))
	}

	cacert, err := cspx509.CreateCertificate(rand.Reader, certTemplate, parent, caPub, s)
	if err != nil {
		assert.Error(t, fmt.Errorf("Error occurred during ca certificate creation: %s", err))
	}

	pemfile, _ := os.Create("root.pem")
	var pemkey = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cacert,
	}
	pem.Encode(pemfile, pemkey)
	pemfile.Close()

	x509Cert, err := cspx509.ParseCertificate(cacert)

	priv, err := csp.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		assert.Error(t, fmt.Errorf("Error occurred during key creation: %s", err))
	}
	pub, err := GetPublicKey(priv)
	if err != nil {
		assert.Error(t, fmt.Errorf("Error occurred during get pubkey: %s", err))
	}
	fmt.Println(x509Cert)
	certTemplate.SubjectKeyId = priv.SKI()
	certTemplate.SerialNumber = big.NewInt(5678)
	certTemplate.NotBefore = time.Now()
	certTemplate.NotAfter = time.Now().Add(3650 * 24 * time.Hour)
	cert, err := cspx509.CreateCertificate(rand.Reader, certTemplate, x509Cert, pub, s)
	if err != nil {
		assert.Error(t, fmt.Errorf("Error occurred during certificate creation: %s", err))
	}
	fmt.Println("2222222222222222222222222222222222222222222222")

	pemfile2, _ := os.Create("tls-cert.pem")
	var pemkey2 = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	pem.Encode(pemfile2, pemkey2)
	pemfile2.Close()

	id := hex.EncodeToString(capriv.SKI())

	os.Rename(filepath.Join(keystore, id+"_sk"), "root-key.pem")

	id2 := hex.EncodeToString(priv.SKI())

	os.Rename(filepath.Join(keystore, id2+"_sk"), "tls-key.pem")



}
//return a *sm2.PublicKey
func GetPublicKey(priv bccsp.Key) (*sm2.PublicKey, error) {
	pubKey, err := priv.PublicKey()
	if err != nil {
		return nil, err
	}
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return nil, err
	}

	sm2PubKey, err := cspx509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return sm2PubKey.(*sm2.PublicKey), nil
}

func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"CN"},
		Locality: []string{"JiNan"},
		Province: []string{"ShanDong Province"},
	}
}