package wst

const (
	EncodeAscii85     encodeType = "ASCII85"
	EncodeBase32      encodeType = "BASE32"
	EncodeBase64      encodeType = "BASE64"
	EncodeHexadecimal encodeType = "HEXADECIMAL"
)

type encodeType string

type iencoder interface {
	Encode(value []byte) ([]byte, error)
	Decode(value []byte) ([]byte, error)
}

var encoderMethods = map[encodeType]iencoder{
	EncodeAscii85:     &encoderAscii85{},
	EncodeBase32:      &encoderBase32{},
	EncodeBase64:      &encoderBase64{},
	EncodeHexadecimal: &encoderHexadecimal{},
}
