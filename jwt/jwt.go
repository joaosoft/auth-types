package jwt

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/joaosoft/errors"
)

var (
	ErrorInvalidAuthorization = errors.New(errors.ErrorLevel, http.StatusUnauthorized, "invalid authorization")
)

type KeyFunc func(*Token) (interface{}, error)

type Token struct {
	raw string

	headers   map[string]interface{}
	payload   string
	signature string

	claims claims
	method signatureMethod
}

func New(signatureMethod string) *Token {
	method := signatureMethods[signatureMethod]

	return &Token{
		headers: map[string]interface{}{
			constJwtTypeKey:      constJwtTypeJwt,
			constJwtAlgorithmKey: method.Algorithm(),
		},
		claims: claims{},
		method: method,
	}
}

func (t *Token) Generate(claims claims, key interface{}) (string, error) {
	t.claims = claims

	headersMarshal, err := json.Marshal(t.headers)
	if err != nil {
		return "", err
	}

	claimsMarshal, err := json.Marshal(t.claims)
	if err != nil {
		return "", err
	}

	headerAndClaims := strings.Join([]string{encode(headersMarshal), encode(claimsMarshal)}, ".")

	signature, err := t.method.Signature(headerAndClaims, key)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{headerAndClaims, signature}, "."), nil
}

func Check(tokenString string, keyFunc KeyFunc, claims claims, skipClaims bool) error {
	token := &Token{raw: tokenString}

	split := strings.Split(tokenString, ".")
	if len(split) != 3 {
		return ErrorInvalidAuthorization
	}

	// headers
	decodedHeader, err := decode(split[0])
	if err != nil {
		return ErrorInvalidAuthorization
	}

	if err = json.Unmarshal(decodedHeader, token.headers); err != nil {
		return ErrorInvalidAuthorization
	}

	// claims
	token.claims = claims

	decodedClaims, err := decode(split[1])
	if err != nil {
		return ErrorInvalidAuthorization

	}

	if err = json.Unmarshal(decodedClaims, token.claims); err != nil {
		return ErrorInvalidAuthorization
	}

	// signature
	if method, ok := token.headers[constJwtAlgorithmKey].(string); ok {
		if token.method, ok = signatureMethods[method]; !ok {
			return ErrorInvalidAuthorization
		}
	} else {
		return ErrorInvalidAuthorization
	}

	// execute keyFunc to get the key
	key, err := keyFunc(token)
	if err != nil {
		return ErrorInvalidAuthorization
	}

	// claims
	if !skipClaims {
		if !claims.Validate() {
			return ErrorInvalidAuthorization
		}
	}

	// signature validation
	token.signature = split[2]
	if err = token.method.Verify(tokenString, token.signature, key); err != nil {
		return ErrorInvalidAuthorization
	}

	return nil
}

func encode(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

func decode(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
