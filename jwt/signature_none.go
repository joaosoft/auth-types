package jwt

type SignatureNone struct{}

type unsafeNoneMagicConstant string

const UnsafeAllowNoneSignatureType unsafeNoneMagicConstant = "none signing method allowed"

func (m *SignatureNone) Algorithm() string {
	return "none"
}

func (m *SignatureNone) Verify(signatureString, signature string, key interface{}) (err error) {
	if _, ok := key.(unsafeNoneMagicConstant); !ok {
		return ErrorInvalidAuthorization
	}
	if signature != "" {
		return ErrorInvalidAuthorization
	}

	return nil
}

func (m *SignatureNone) Signature(signatureString string, key interface{}) (string, error) {
	if _, ok := key.(unsafeNoneMagicConstant); ok {
		return "", nil
	}
	return "", ErrorInvalidAuthorization
}
