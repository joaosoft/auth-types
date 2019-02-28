package jwt

import (
	"crypto"
	"crypto/rsa"
)

type signatureMethod interface {
	Verify(signatureString, signature string, key interface{}) error
	Signature(signatureString string, key interface{}) (string, error)
	Algorithm() string
}

var signatureMethods = map[string]signatureMethod{
	"ES256": &SignatureECDSA{Name: "ES256", Hash: crypto.SHA256, KeySize: 32, CurveBits: 256},
	"ES384": &SignatureECDSA{Name: "ES384", Hash: crypto.SHA384, KeySize: 48, CurveBits: 384},
	"ES512": &SignatureECDSA{Name: "ES512", Hash: crypto.SHA512, KeySize: 66, CurveBits: 521},
	"RS256": &SignatureRSA{Name: "RS256", Hash: crypto.SHA256},
	"RS384": &SignatureRSA{Name: "RS384", Hash: crypto.SHA384},
	"RS512": &SignatureRSA{Name: "RS512", Hash: crypto.SHA512},
	"PS256": &SignatureRSAPSS{SignatureRSA: &SignatureRSA{Name: "PS256", Hash: crypto.SHA256}, Options: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}},
	"PS384": &SignatureRSAPSS{SignatureRSA: &SignatureRSA{Name: "PS384", Hash: crypto.SHA384}, Options: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA384}},
	"PS512": &SignatureRSAPSS{SignatureRSA: &SignatureRSA{Name: "PS512", Hash: crypto.SHA512}, Options: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA512}},
	"HS256": &SignatureHMAC{"HS256", crypto.SHA256},
	"HS384": &SignatureHMAC{"HS384", crypto.SHA384},
	"HS512": &SignatureHMAC{"HS512", crypto.SHA512},
	"none":  &SignatureNone{},
}
