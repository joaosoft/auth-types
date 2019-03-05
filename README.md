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
	// generate new token
	w := wst.New(wst.SignatureHS384, wst.EncodeAscii85, wst.EncodeBase32, wst.EncodeBase64, wst.EncodeHexadecimal)
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
Generated WST Token: 536b4a4a56316b7a536c684a535664565631464c4e4568424d6c645255454a4a52305a5256456c545446464a576b4e5951316f795455644f546c4d30545552565346465452564659575430.536b4a4a56316b7a536c4e4a526b5a585655777a54456443526b4e46556b524553554531566b6c56556b4e48546b35544e6c424457456c424e56644a55466f30.5445704e52464e56576b68464e555a554e464d7a5355744754456456535449315445705856304e58516c5a49536b354854314255546b6c4e56566846576c4a4654306c615645565555303146536c68575230314b4d30315754465a42536b4e4654454a4355304e4a53304e4f56566c4751566854556b35435330565a4d307331
```

## Known issues

## Follow me at
Facebook: https://www.facebook.com/joaosoft

LinkedIn: https://www.linkedin.com/in/jo%C3%A3o-ribeiro-b2775438/

##### If you have something to add, please let me know joaosoft@gmail.com
