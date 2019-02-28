package jwt

import (
	"crypto"
	"crypto/hmac"
	"fmt"
)

type SignatureHMAC struct {
	Name string
	Hash crypto.Hash
}

func (sg *SignatureHMAC) Algorithm() string {
	return sg.Name
}

func (sg *SignatureHMAC) Verify(signatureString, signature string, key interface{}) error {
	var keyBytes []byte
	switch b := key.(type) {
	case []byte:
		keyBytes = b
	default:
		keyBytes = []byte(fmt.Sprintf("%+v", key))
	}

	sig, err := decode(signature)
	if err != nil {
		return err
	}

	if !sg.Hash.Available() {
		return ErrorInvalidAuthorization
	}

	hasher := hmac.New(sg.Hash.New, keyBytes)
	hasher.Write([]byte(signatureString))
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return ErrorInvalidAuthorization
	}

	return nil
}

func (sg *SignatureHMAC) Signature(signatureString string, key interface{}) (string, error) {
	var keyBytes []byte
	switch b := key.(type) {
	case []byte:
		keyBytes = b
	default:
		keyBytes = []byte(fmt.Sprintf("%+v", key))
	}

	if !sg.Hash.Available() {
		return "", ErrorInvalidAuthorization
	}

	hasher := hmac.New(sg.Hash.New, keyBytes)
	hasher.Write([]byte(signatureString))

	return encode(hasher.Sum(nil)), nil

	return "", ErrorInvalidAuthorization
}
