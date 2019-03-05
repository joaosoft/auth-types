package jwt

const (
	EncodeBase64      encodeType = "BASE64"
)

type encodeType string

type iencoder interface {
	Encode(value []byte) ([]byte, error)
	Decode(value []byte) ([]byte, error)
}

var encoderMethods = map[encodeType]iencoder{
	EncodeBase64: &encoderBase64{},
}
