package jwt

type SignatureNone struct {
	Name string
}

func (sg *SignatureNone) Algorithm() string {
	return sg.Name
}

func (sg *SignatureNone) Verify(signatureString, signature string, key interface{}) (err error) {
	if signature != "" {
		return ErrorInvalidAuthorization
	}

	return nil
}

func (sg *SignatureNone) Signature(signatureString string, key interface{}) (string, error) {
	return "", nil
}
