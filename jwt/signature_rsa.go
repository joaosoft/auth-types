package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

type signatureRSA struct {
	Name string
	Hash crypto.Hash
}

func (sg *signatureRSA) Algorithm() string {
	return sg.Name
}

func (sg *signatureRSA) Verify(signatureString, signature string, key interface{}) error {
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

	if !sg.Hash.Available() {
		return ErrorInvalidAuthorization
	}
	hasher := sg.Hash.New()
	hasher.Write([]byte(signatureString))

	return rsa.VerifyPKCS1v15(rsaKey, sg.Hash, hasher.Sum(nil), sig)
}

func (sg *signatureRSA) Signature(signatureString string, key interface{}) (string, error) {
	var rsaKey *rsa.PrivateKey
	var ok bool

	if rsaKey, ok = key.(*rsa.PrivateKey); !ok {
		return "", ErrorInvalidAuthorization
	}

	if !sg.Hash.Available() {
		return "", ErrorInvalidAuthorization
	}

	hasher := sg.Hash.New()
	hasher.Write([]byte(signatureString))

	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, sg.Hash, hasher.Sum(nil)); err == nil {
		return encode(sigBytes), nil
	} else {
		return "", err
	}
}
