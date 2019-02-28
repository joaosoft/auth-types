package jwt

import (
	"crypto/rand"
	"crypto/rsa"
)

type SignatureRSAPSS struct {
	*SignatureRSA
	Options *rsa.PSSOptions
}

func (sg *SignatureRSAPSS) Verify(signatureString, signature string, key interface{}) error {
	var err error

	var sig []byte
	if sig, err = decode(signature); err != nil {
		return err
	}

	var rsaKey *rsa.PublicKey
	switch k := key.(type) {
	case *rsa.PublicKey:
		rsaKey = k
	default:
		return ErrorInvalidAuthorization
	}

	if !sg.Hash.Available() {
		return ErrorInvalidAuthorization
	}
	hasher := sg.Hash.New()
	hasher.Write([]byte(signatureString))

	return rsa.VerifyPSS(rsaKey, sg.Hash, hasher.Sum(nil), sig, sg.Options)
}

func (sg *SignatureRSAPSS) Signature(signatureString string, key interface{}) (string, error) {
	var rsaKey *rsa.PrivateKey

	switch k := key.(type) {
	case *rsa.PrivateKey:
		rsaKey = k
	default:
		return "", ErrorInvalidAuthorization
	}

	if !sg.Hash.Available() {
		return "", ErrorInvalidAuthorization
	}

	hasher := sg.Hash.New()
	hasher.Write([]byte(signatureString))

	if sigBytes, err := rsa.SignPSS(rand.Reader, rsaKey, sg.Hash, hasher.Sum(nil), sg.Options); err == nil {
		return encode(sigBytes), nil
	} else {
		return "", err
	}
}
