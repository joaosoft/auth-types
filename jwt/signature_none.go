package jwt

type signatureNone struct {
	Name string
}

func (sg *signatureNone) Algorithm() string {
	return sg.Name
}

func (sg *signatureNone) Verify(signatureString, signature string, key interface{}) (err error) {
	if signature != "" {
		return ErrorInvalidAuthorization
	}

	return nil
}

func (sg *signatureNone) Signature(signatureString string, key interface{}) (string, error) {
	return "", nil
}
