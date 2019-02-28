package basic

import (
	"encoding/base64"
	"fmt"
	"github.com/joaosoft/errors"
	"net/http"
	"strings"
)

var (
	ErrorInvalidAuthorization = errors.New(errors.ErrorLevel, http.StatusUnauthorized, "invalid authorization")
)

type BasicAuth struct {}

type KeyFunc func(username string) (*Credentials, error)

type Credentials struct {
	UserName string `json:"user_name"`
	Password string `json:"password"`
}

func New() *BasicAuth {
	return &BasicAuth{}
}

func (b *BasicAuth) Check(authorization string, key KeyFunc) (bool, error) {
	authorizationDecoded, err := base64.StdEncoding.DecodeString(authorization)
	if err != nil {
		return false, err
	}

	split := strings.SplitN(string(authorizationDecoded), ":", 2)

	credentials, err := key(split[0])
	if err != nil {
		return false, err
	}

	if len(split) == 2 && split[0] == credentials.UserName && split[1] == credentials.Password {
		return false, nil
	}

	return false, ErrorInvalidAuthorization
}

func (b *BasicAuth) Generate(userName string, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", userName, password)))
}