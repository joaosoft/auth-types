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

>## WST (Web Security Token)
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

	valid, err := j.Check(token, keyFunc, checkFunc, jwt.Claims{}, true)

	if !valid {
		panic("the jwt session should be valid")
	}

	if err != nil {
		panic(err)
	}
}

func wstAuth() {
	// generate new token
	w := wst.New(wst.SignatureHS384, wst.EncodeBase64, wst.EncodeBase32, wst.EncodeBase64, wst.EncodeHexadecimal)
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
Generated WST Token: 545659305656557952454e4a4e564a585531517a536b704b52565a4c4e6c4e4f52314a49525564545446524b526c68475255354d52456c4f5256524e5530784d54304a4e526b31524d6b744952543039505430395051.5456593056565579517a4a48536b74585531517a533070574d31565a55544a4c54315a4e566b394e5445314b526c5a484e6a4a4d516b35564e46645257565261536b6b3055543039505430.54454a48526b733154465a4b516a4a59533152555545343156305a445630744554564a435346453052453150556b5a46527a4e5552453557566c644a576b7861546c705357457456517a4a4e556a52485631524d5445773057556458565552525230354a57457457576c464b556b74575255314552556c4657556456556b705853315a58526b7379575430
```

## Known issues

## Follow me at
Facebook: https://www.facebook.com/joaosoft

LinkedIn: https://www.linkedin.com/in/jo%C3%A3o-ribeiro-b2775438/

##### If you have something to add, please let me know joaosoft@gmail.com
