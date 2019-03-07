# auth-types
[![Build Status](https://travis-ci.org/joaosoft/auth-types.svg?branch=master)](https://travis-ci.org/joaosoft/auth-types) | [![codecov](https://codecov.io/gh/joaosoft/auth-types/branch/master/graph/badge.svg)](https://codecov.io/gh/joaosoft/auth-types) | [![Go Report Card](https://goreportcard.com/badge/github.com/joaosoft/auth-types)](https://goreportcard.com/report/github.com/joaosoft/auth-types) | [![GoDoc](https://godoc.org/github.com/joaosoft/auth-types?status.svg)](https://godoc.org/github.com/joaosoft/auth-types)

Http authentication implementations.

## With authentication types
* basic
* jwt (Json Web Token)
* wst (Web Security Token) [personal implementation]

## With signatures
* ES256
* ES384
* ES512
* RS256
* RS384
* RS512
* PS256
* PS384
* PS512
* HS256
* HS384
* HS512
* NONE 

## WST (Web Security Token)
This method is similar to JWT but allows you to define multiple encodings to encode the message making your message complex to decode.

## WST Encodings
* Base32
* Base64
* Hexadecimal
* ASCII85
* Cipher (with 32bit secret key, can be changed using ```wst.WithCipherSecret([]byte("my personal super secret key !!!"))```)

###### If i miss something or you have something interesting, please be part of this project. Let me know! My contact is at the end.

## Dependecy Management
>### Dependency

Project dependencies are managed using Dep. Read more about [Dep](https://github.com/golang/dep).
* Get dependency manager: `go get github.com/joaosoft/dependency`
* Install dependencies: `dependency get`

>### Go
```
go get github.com/joaosoft/auth-types
```

## Usage 
This examples are available in the project at [auth-types/examples](https://github.com/joaosoft/auth-types/tree/master/examples)

```go
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
	w := wst.New(wst.SignatureHS384, wst.EncodeAscii85, wst.EncodeBase32, wst.EncodeBase64, wst.EncodeHexadecimal, wst.EncodeCipher)
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
```

> ##### Result:
```
Generated Basic Token: am9hbzpyaWJlaXJv
Generated JWT Token: eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhZ2UiOjMwLCJuYW1lIjoiam9hbyJ9.IBjoIfFYFyqNIdBGIaZFT9aamswR4Hm0exoULbfZAqgampskcI3pldAz2wOKq1q5
Generated WST Token: AAAAAAAAAAAAAAAAAAAAAPD5SB9mKc7r8gj6AhlWsBUresOMBA5Yv0pB9at09CaBKsRTjwXmnvi-_Mm-15DUvSqpe5dRnfw2KImko7Us-QdKPqHqri8P3FnSdx9Tpo6OAWUa38jp_PrbnKX4l_aG_UaDFpW1Lhc7H6kF_C7UhNXJlu5sxjLk58kyVyhLWSClJWKF2FuY6Iirf7hFtwSoArfgbj6AVw.AAAAAAAAAAAAAAAAAAAAAPD5SB9mKc7r8gj6AhlWsBUresOMBlNYv0pA9v93oSaPf_UX4TckvvN57ZzAdh7r0ew13VYgIt-RNINREFrYQdtMGwkb9U5KnwP0AZKM5uOLnP6oq8BRupqoGK9c5KXR5U7_YbvW7RDexQngImWyAz7ZuebXXxHnmIhrZIWgBATE.AAAAAAAAAAAAAAAAAAAAAPD-SB9mfs--8gz6AxwNsxFzUZetOMebRkpcMl9fXCIU_FNjBEYx3LS1DxSCbuOKDyzSWcGicvTVuYBRBc_uwApyhtsB0QbQ5pc2J-t69WSPT1eB7uECwjuKAeM8GPEZvzKlc4MBt7bXkOG7meAfUDaOLbNt2fD6KX7bLhdKvsJbE8L6kJKJZeG9bM1NfsU43uUVDcVjbVdvMiyE3z13O8OzkRlM_93nmozT5RGGRvGdlRI_1atJpNMm_KrS9M-9XxLUKfRROKRHfR7adObLzq4_wMsJs_bPSUVOgmcydD24yOK3tFrLB958BLSVW82bFiJ1vCNtgD7MDf_sScdpf9I
```

## Known issues

## Follow me at
Facebook: https://www.facebook.com/joaosoft

LinkedIn: https://www.linkedin.com/in/jo%C3%A3o-ribeiro-b2775438/

##### If you have something to add, please let me know joaosoft@gmail.com
