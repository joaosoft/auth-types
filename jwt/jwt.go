package jwt

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/joaosoft/errors"
)

var (
	ErrorInvalidAuthorization   = errors.New(errors.ErrorLevel, http.StatusUnauthorized, "invalid authorization")
	ErrorInvalidSignatureMethod = errors.New(errors.ErrorLevel, http.StatusUnauthorized, "invalid signature method")
	ErrorInvalidJwtAlgorithm    = errors.New(errors.ErrorLevel, http.StatusUnauthorized, "invalid signature method")
	ErrorClaimsValidation       = errors.New(errors.ErrorLevel, http.StatusUnauthorized, "error on claims validation")
)

type KeyFunc func(*Token) (interface{}, error)
type CheckFunc func(Claims) (bool, error)

type Token struct {
	raw string `json:"raw"`

	headers   map[string]interface{} `json:"headers"`
	payload   string                 `json:"payload"`
	signature string                 `json:"signature"`

	claims Claims
	method isignature
}

func New(signature signature) *Token {
	method := signatureMethods[signature]

	return &Token{
		headers: map[string]interface{}{
			HeaderTypeKey:      constHeaderTypeJwt,
			HeaderAlgorithmKey: method.Algorithm(),
		},
		claims: Claims{},
		method: method,
	}
}

func (t *Token) Generate(claims Claims, key interface{}) (string, error) {
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

func Check(tokenString string, keyFunc KeyFunc, checkFunc CheckFunc, claims Claims, skipClaims bool) (bool, error) {
	token := &Token{raw: tokenString, headers: make(map[string]interface{}), claims: claims}

	split := strings.Split(tokenString, ".")
	if len(split) != 3 {
		return false, nil
	}

	// headers
	decodedHeader, err := decode(split[0])
	if err != nil {
		return false, err
	}

	if err = json.Unmarshal(decodedHeader, &token.headers); err != nil {
		return false, err
	}

	// Claims
	token.claims = claims

	decodedClaims, err := decode(split[1])
	if err != nil {
		return false, err

	}

	if err = json.Unmarshal(decodedClaims, &token.claims); err != nil {
		return false, err
	}

	// signature
	if method, ok := token.headers[HeaderAlgorithmKey].(string); ok {
		if token.method, ok = signatureMethods[signature(method)]; !ok {
			return false, ErrorInvalidSignatureMethod
		}
	} else {
		return false, ErrorInvalidJwtAlgorithm
	}

	// execute keyFunc to get the key
	key, err := keyFunc(token)
	if err != nil {
		return false, err
	}

	// Claims
	if !skipClaims {
		if !claims.Validate() {
			return false, ErrorClaimsValidation
		}
	}

	// signature validation
	token.signature = split[2]
	// header.claims
	if err = token.method.Verify(strings.Join(split[0:2], "."), token.signature, key); err != nil {
		return false, err
	}

	// check claims
	return checkFunc(token.claims)
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
