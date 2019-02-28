package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
)


type SignatureECDSA struct {
	Name      string
	Hash      crypto.Hash
	KeySize   int
	CurveBits int
}

func (sg *SignatureECDSA) Algorithm() string {
	return sg.Name
}

func (sg *SignatureECDSA) Verify(signatureString, signature string, key interface{}) error {
	var err error

	var sig []byte
	if sig, err = decode(signature); err != nil {
		return err
	}

	var ecdsaKey *ecdsa.PublicKey
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		ecdsaKey = k
	default:
		return ErrorInvalidAuthorization
	}

	if len(sig) != 2*sg.KeySize {
		return ErrorInvalidAuthorization
	}

	r := big.NewInt(0).SetBytes(sig[:sg.KeySize])
	s := big.NewInt(0).SetBytes(sig[sg.KeySize:])

	if !sg.Hash.Available() {
	}
	hasher := sg.Hash.New()
	hasher.Write([]byte(signatureString))

	if verifystatus := ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s); verifystatus == true {
		return nil
	} else {
		return ErrorInvalidAuthorization
	}
}

func (sg *SignatureECDSA) Signature(signatureString string, key interface{}) (string, error) {
	var ecdsaKey *ecdsa.PrivateKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		ecdsaKey = k
	default:
		return "", ErrorInvalidAuthorization
	}

	if !sg.Hash.Available() {
		return "", ErrorInvalidAuthorization
	}

	hasher := sg.Hash.New()
	hasher.Write([]byte(signatureString))

	if r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil)); err == nil {
		curveBits := ecdsaKey.Curve.Params().BitSize

		if sg.CurveBits != curveBits {
			return "", ErrorInvalidAuthorization
		}

		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}

		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

		out := append(rBytesPadded, sBytesPadded...)

		return encode(out), nil
	} else {
		return "", err
	}
}
