package jwt

import (
	"crypto"
	"crypto/hmac"
)

type SignatureHMAC struct {
	Name string
	Hash crypto.Hash
}

func (m *SignatureHMAC) Algorithm() string {
	return m.Name
}

func (m *SignatureHMAC) Verify(signatureString, signature string, key interface{}) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return ErrorInvalidAuthorization
	}

	sig, err := decode(signature)
	if err != nil {
		return err
	}

	if !m.Hash.Available() {
		return ErrorInvalidAuthorization
	}

	hasher := hmac.New(m.Hash.New, keyBytes)
	hasher.Write([]byte(signatureString))
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return ErrorInvalidAuthorization
	}

	return nil
}

func (m *SignatureHMAC) Signature(signatureString string, key interface{}) (string, error) {
	if keyBytes, ok := key.([]byte); ok {
		if !m.Hash.Available() {
			return "", ErrorInvalidAuthorization
		}

		hasher := hmac.New(m.Hash.New, keyBytes)
		hasher.Write([]byte(signatureString))

		return encode(hasher.Sum(nil)), nil
	}

	return "", ErrorInvalidAuthorization
}
