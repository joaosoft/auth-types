package jwt

import (
	"crypto/rand"
	"crypto/rsa"
)

type SignatureRSAPSS struct {
	*SignatureRSA
	Options *rsa.PSSOptions
}

func (m *SignatureRSAPSS) Verify(signatureString, signature string, key interface{}) error {
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

	if !m.Hash.Available() {
		return ErrorInvalidAuthorization
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signatureString))

	return rsa.VerifyPSS(rsaKey, m.Hash, hasher.Sum(nil), sig, m.Options)
}

func (m *SignatureRSAPSS) Signature(signatureString string, key interface{}) (string, error) {
	var rsaKey *rsa.PrivateKey

	switch k := key.(type) {
	case *rsa.PrivateKey:
		rsaKey = k
	default:
		return "", ErrorInvalidAuthorization
	}

	if !m.Hash.Available() {
		return "", ErrorInvalidAuthorization
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signatureString))

	if sigBytes, err := rsa.SignPSS(rand.Reader, rsaKey, m.Hash, hasher.Sum(nil), m.Options); err == nil {
		return encode(sigBytes), nil
	} else {
		return "", err
	}
}
