package lib

import (
	"testing"
	//"github.com/hyperledger/fabric/bccsp/pkcs11"
)

func TestDandan(t *testing.T) {

	/*lib, pin, label := sansec.FindPKCS11Lib()
	opts := &factory.FactoryOpts{
		ProviderName: "SansecPKCS11",

		SansecP11Opts: &sansec.SansecP11Opts{
			SecLevel:   256,
			HashFamily: "SHA2",

			Library: lib,
			Pin:     pin,
			Label:   label,
		},
	}
	/*opts := &factory.FactoryOpts{
		ProviderName: "SW",
		SwOpts: &factory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,

			//Ephemeral: true,
		},
	}*/
	/*
		lib, pin, label := pkcs11.FindPKCS11Lib()
		opts := &factory.FactoryOpts{
			ProviderName: "PKCS11",

			Pkcs11Opts: &pkcs11.PKCS11Opts{
				SecLevel:   256,
				HashFamily: "SHA2",
				PubAlgo:    "ecdsa",
				KeySize:    256,

				Library: lib,
				Pin:     pin,
				Label:   label,
			},
		}
	*/

	/*csp, err := util.InitBCCSP(&opts, "/home/someonelucky/beifen", "/home/someonelucky/beifen")
	if err != nil {
		fmt.Println("util InitBCCSP error", err)
		t.Fatal(err)
	}
	//fmt.Printf("csp: %+v\n", csp)

	/*
		pubAlgo, keySize, err := util.GetAlgoAndSize(opts)
		if err != nil {
			fmt.Println("GetAlgoAndSize ERROR", err)
			t.Fatal(err)
		}
		fmt.Printf("pubAlgo: %+v\nkeySize: %+v\n", pubAlgo, keySize)
	*/

	/*req := cfcsr.CertificateRequest{
		CN:    "YDD",
		Names: nil,
		Hosts: nil,
		// FIXME: NewBasicKeyRequest only does ecdsa 256; use config
		KeyRequest:   cfcsr.NewBCCSPKeyRequest("SM2", 256),
		CA:           nil,
		SerialNumber: "1234",
	}
	fmt.Printf("req: %+v\n", req)

	_, cspSigner, err := util.BCCSPKeyRequestGenerate(&req, csp)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := initca.NewFromSigner(&req, cspSigner)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(cert))
	/*c, err := util.GetX509CertificateFromPEM(cert)
	if err != nil {
		fmt.Println("GetX509CertificateFromPEM ERROR", err)
		t.Fatal(err)
	}
	key, _, err := util.GetSignerFromCert(c, csp)
	if err != nil {
		fmt.Println("GetSignerFromCert Error", err)
		t.Fatal(err)
	}*/
	//fmt.Println("CERTIFICATE C", c.Subject.CommonName)*/
	//fmt.Println(string(cert))
	/*hashFunc := crypto.SHA256
	test := []byte("hello world")
	h := hashFunc.New()
	h.Write(test)
	digest := h.Sum(nil)

	var signature []byte
	signature, err = cspSigner.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		t.Fatal(err)
	}
	_ = signature*/
}
