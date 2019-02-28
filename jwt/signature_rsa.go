package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

type SignatureRSA struct {
	Name string
	Hash crypto.Hash
}

func (m *SignatureRSA) Algorithm() string {
	return m.Name
}

func (m *SignatureRSA) Verify(signatureString, signature string, key interface{}) error {
	var err error

	var sig []byte
	if sig, err = decode(signature); err != nil {
		return err
	}

	var rsaKey *rsa.PublicKey
	var ok bool

	if rsaKey, ok = key.(*rsa.PublicKey); !ok {
		return ErrorInvalidAuthorization
	}

	if !m.Hash.Available() {
		return ErrorInvalidAuthorization
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signatureString))

	return rsa.VerifyPKCS1v15(rsaKey, m.Hash, hasher.Sum(nil), sig)
}

func (m *SignatureRSA) Signature(signatureString string, key interface{}) (string, error) {
	var rsaKey *rsa.PrivateKey
	var ok bool

	if rsaKey, ok = key.(*rsa.PrivateKey); !ok {
		return "", ErrorInvalidAuthorization
	}

	if !m.Hash.Available() {
		return "", ErrorInvalidAuthorization
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signatureString))

	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, m.Hash, hasher.Sum(nil)); err == nil {
		return encode(sigBytes), nil
	} else {
		return "", err
	}
}
