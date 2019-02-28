# auth-types
[![Build Status](https://travis-ci.org/joaosoft/auth-types.svg?branch=master)](https://travis-ci.org/joaosoft/auth-types) | [![codecov](https://codecov.io/gh/joaosoft/auth-types/branch/master/graph/badge.svg)](https://codecov.io/gh/joaosoft/auth-types) | [![Go Report Card](https://goreportcard.com/badge/github.com/joaosoft/auth-types)](https://goreportcard.com/report/github.com/joaosoft/auth-types) | [![GoDoc](https://godoc.org/github.com/joaosoft/auth-types?status.svg)](https://godoc.org/github.com/joaosoft/auth-types)

Http authentication implementations.

## With authentication types
* basic
* jwt

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
}

func basicAuth() {
	b := basic.New()

	// generate new token
	token := b.Generate("joao", "ribeiro")

	fmt.Printf("Generated Basic Token: %s\n", token)

	// check token
	ok, err := b.Check(token, func(username string) (*basic.Credentials, error) {
		return &basic.Credentials{UserName: "joao", Password: "ribeiro"}, nil
	})

	if err != nil {
		panic(err)
	}

	if !ok {
		panic("invalid basic authentication")
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

	// check token
	valid, err := jwt.Check(token, keyFunc, checkFunc, jwt.Claims{}, true)

	if !valid {
		panic("then jwt session should be valid")
	}

	if err != nil {
		panic(err)
	}
}
```

> ##### Result:
```
Generated Basic Token: am9hbzpyaWJlaXJv
Generated JWT Token: eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJhZ2UiOjMwLCJuYW1lIjoiam9hbyJ9.
```

## Known issues

## Follow me at
Facebook: https://www.facebook.com/joaosoft

LinkedIn: https://www.linkedin.com/in/jo%C3%A3o-ribeiro-b2775438/

##### If you have something to add, please let me know joaosoft@gmail.com
