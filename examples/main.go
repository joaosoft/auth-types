package main

import (
	"auth-types/basic"
	"auth-types/jwt"
	"auth-types/wst"
	"fmt"
)

func main() {
	basicAuth()
	jwtAuth()
	wstAuth()
}

func basicAuth() {
	// generate new token
	token := basic.Generate("joao", "ribeiro")

	fmt.Printf("Generated Basic Token: %s\n", token)

	// check token
	ok, err := basic.Check(token, func(username string) (*basic.Credentials, error) {
		return &basic.Credentials{UserName: "joao", Password: "ribeiro"}, nil
	})

	if err != nil {
		panic(err)
	}

	if !ok {
		panic("invalid basic session")
	}
}

func jwtAuth() {
	// generate new token
	j := jwt.New(jwt.SignatureHS384)
	claims := jwt.Claims{"name": "joao", "age": 30}
	token, err := j.Generate(claims, "bananas")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Generated JWT Token: %s\n", token)

	// check token
	keyFunc := func(*jwt.Token) (interface{}, error) {
		return []byte("bananas"), nil
	}

	checkFunc := func(c jwt.Claims) (bool, error) {
		if claims["name"] == c["name"].(string) &&
			claims["age"] == int(c["age"].(float64)) {
			return true, nil
		}
		return false, fmt.Errorf("invalid jwt session token")
	}

	valid, err := jwt.Check(token, keyFunc, checkFunc, jwt.Claims{}, true)

	if !valid {
		panic("the jwt session should be valid")
	}

	if err != nil {
		panic(err)
	}
}

func wstAuth() {
	wst.WithCipherSecret([]byte("my personal super secret key !!!"))

	// generate new token
	w := wst.New(
		wst.SignatureHS384,
		wst.EncodeAscii85,
		wst.EncodeBase32,
		wst.EncodeBase64,
		wst.EncodeHexadecimal,
		wst.EncodeCipher,
	)
	claims := wst.Claims{"name": "joao", "age": 30}
	token, err := w.Generate(claims, "bananas")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Generated WST Token: %s\n", token)

	// check token
	keyFunc := func(*wst.Token) (interface{}, error) {
		return []byte("bananas"), nil
	}

	checkFunc := func(c wst.Claims) (bool, error) {
		if claims["name"] == c["name"].(string) &&
			claims["age"] == int(c["age"].(float64)) {
			return true, nil
		}
		return false, fmt.Errorf("invalid jwt session token")
	}

	valid, err := w.Check(token, keyFunc, checkFunc, wst.Claims{}, true)

	if !valid {
		panic("the wst session should be valid")
	}

	if err != nil {
		panic(err)
	}
}
