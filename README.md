# fiber_ldap: LDAP Authentication Middleware

![Release](https://img.shields.io/github/release/eozer/fiber_ldap.svg)
![Test](https://github.com/eozer/fiber_ldap/workflows/Test/badge.svg)
![Security](https://github.com/eozer/fiber_ldap/workflows/Security/badge.svg)
![Linter](https://github.com/eozer/fiber_ldap/workflows/golangci-lint/badge.svg)

LDAP authentication middleware for [Fiber](https://github.com/gofiber/fiber).
It calls the next handler for valid credentials and 401 Unauthorized for other cases.


#### Table of Contents
- [Install](#install)
- [Signatures](#signatures)
- [Examples](#examples)
  * [Basic Example](#basic-example)
- [Config](#config)
- [Default Config](#default-config)
- [License](#license)


## Install
```terminal
go get github.com/eozer/fiber_ldapauth
```

## Signatures
```go
func New(config Config) fiber.Handler
```

## Examples

### Basic example
```go
package main

import (
	ldapauth "github.com/eozer/fiber_ldapauth"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	app.Use(ldapauth.New(ldapauth.Config{
		URL:              "ldap://ldap.forumsys.com:389",
		BindDN:           "cn=read-only-admin,dc=example,dc=com",
		BindCredentials:  "password",
		SearchBase:       "dc=example,dc=com",
		SearchFilter:     "(&(objectClass=organizationalPerson)(uid={{username}}))",
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	app.Listen(":3000")
}

```

## Config
```go
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	//
	// Optional. Default: nil
	Next func(*fiber.Ctx) bool

	// URL defines the LDAP server URL, e.g., ldap://localhost:389 or
	// ldaps://localhost:636 when TLS connection is needed.
	//
	// Required.
	URL string

	// BindDN defines the admin connection DN. Giving empty string may
	// result in anonymous bind when allowed by the LDAP server.
	//
	// Required.
	BindDN string

	// BindCredentials defines the password for BindDN. Giving empty string,
	// performs an unauthenticated bind.
	//
	// Optional. Default: ""
	BindCredentials string

	// SearchBase defines the base DN from which to search for users.
	//
	// Giving empty string skips searching for a user for authentication, i.e.,
	// does only the initial admin bind.
	//
	// Optional. Default: ""
	SearchBase string

	// SearchFilter defines the LDAP search filter with which to find a user
	// by username, e.g. (uid={{username}}). Use the literal {{username}} to
	// have the given username interpolated in for the LDAP search.
	//
	// Giving empty string skips searching for a user for authentication, i.e.
	// does only admin bind.
	//
	// Optional. Default: ""
	SearchFilter string

	// SearchAttributes defines the attributes to fetch from LDAP server.
	//
	// Optional. Default: []string{"dn", "dc"}
	SearchAttributes []string

	// TLSConfig is used to configure a TLS client to connect to the LDAP server.
	// See https://pkg.go.dev/crypto/tls#Config
	//
	// Optional. Default: nil
	TLSConfig *tls.Config

	// UsernameField defines the field name where the username is found.
	//
	// Optional. Default: "username"
	UsernameField string

	// PasswordField defines the field name where the password is found.
	//
	// Optional. Default: "password"
	PasswordField string

	// CredentialsLookup defines the function to provide the login credentials
	// from request. By default it checks request query, body, and header by
	// UsernameField and PasswordField. Lastly, it checks Authorization header,
	// if found, it decodes Basic Authentication credentials.
	//
	// Optional. Default: defaultCredentialsLookup
	CredentialsLookup func(c *fiber.Ctx, usernameField, passwordField string) (username, password string, err error)

	// ErrorCallback defines a function to be called with the received error.
	//
	// Optional. Default: nil
	ErrorCallback ErrorHandlerCallback

	// SuccessCallback defines a function to be called when LDAP authentication
	// is successful. By default it continues executing the next middleware.
	//
	// Optional. Default: defaultSuccessCallback
	SuccessCallback func(*fiber.Ctx) error
}
```


## Default Config
```go
var ConfigDefault = Config{
	SearchAttributes:  []string{"dn", "dc"},
	UsernameField:     "username",
	PasswordField:     "password",
	CredentialsLookup: defaultCredentialsLookup,
	SuccessCallback:   defaultSuccessCallback,
}
```

## License
Copyright (c) 2022-present Ege Can Özer and Contributors. This package is free and 
open-source software licensed under the [MIT License](https://github.com/eozer/fiber_ldap/blob/master/LICENSE).

#### Third-party library licenses
- [gofiber/fiber](https://github.com/gofiber/fiber/blob/master/LICENSE)
- [go-ldap/ldap](https://github.com/go-ldap/ldap/blob/master/LICENSE)
