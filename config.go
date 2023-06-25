package fiber_ldapauth

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/gofiber/fiber/v2"
)

type (
	ErrorHandlerCallback = func(*fiber.Ctx, error) error
	ErrorHandler         = func(*fiber.Ctx, error, ErrorHandlerCallback) error
)

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
	// is successful. By default it calls the next handler.
	//
	// Optional. Default: defaultSuccessCallback
	SuccessCallback func(*fiber.Ctx) error
}

var ConfigDefault = Config{
	SearchAttributes:  []string{"dn", "dc"},
	UsernameField:     "username",
	PasswordField:     "password",
	CredentialsLookup: defaultCredentialsLookup,
	SuccessCallback:   defaultSuccessCallback,
}

func mapLDAPToFiberError(e *ldap.Error) *fiber.Error {
	// Success LDAP operation, i.e., when e.ResultCode == 0, shall not be
	// returned as error.
	ldapErrStr, ok := ldap.LDAPResultCodeMap[e.ResultCode]
	if ok && e.ResultCode != 0 {
		return fiber.NewError(401, ldapErrStr)
	}
	return fiber.ErrInternalServerError
}

func errorHandler(c *fiber.Ctx, err error, cb ErrorHandlerCallback) error {
	err = fiber.NewError(401, err.Error())
	if e, ok := err.(*ldap.Error); ok {
		err = mapLDAPToFiberError(e)
	}
	if cb != nil {
		return cb(c, err)
	}
	return err
}

var defaultSuccessCallback = func(c *fiber.Ctx) error {
	return c.Next()
}

var defaultCredentialsLookup = func(c *fiber.Ctx, usernameField, passwordField string) (username, password string, err error) {
	// Extract credentials from request query
	username = c.Query(usernameField)
	password = c.Query(passwordField)
	if username != "" && password != "" {
		return username, password, nil
	}
	// From request body
	// NOTE: One must use "username" and "password" fields as keys.
	if c.Body() != nil {
		p := &struct {
			Username string `json:"username" xml:"username" form:"username"`
			Password string `json:"password" xml:"password" form:"password"`
		}{}
		err = c.BodyParser(p)
		if err != nil {
			return "", "", err
		}
		username = p.Username
		password = p.Password
		if username != "" && password != "" {
			return username, password, nil
		}
	}
	// From request headers
	reqh := c.GetReqHeaders()
	username, usrOk := reqh[usernameField]
	password, pwdOk := reqh[passwordField]
	if usrOk && pwdOk {
		return username, password, nil
	}
	// From Authorization header. Handles only Basic Auth.
	auth, authOk := reqh["Authorization"]
	if authOk && auth != "" {
		authDec, err := base64.StdEncoding.DecodeString(auth)
		if err == nil {
			if strings.Contains(string(authDec), "Basic") {
				t := strings.Split(string(authDec[6:]), ":")
				if len(t) == 2 {
					return t[0], t[1], nil
				}
			}
		}
	}
	return "", "", errors.New("missing credentials")
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	// Return default config if nothing provided
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	// Set default values on optional values.
	if cfg.SuccessCallback == nil {
		cfg.SuccessCallback = ConfigDefault.SuccessCallback
	}

	if cfg.SearchAttributes == nil {
		cfg.SearchAttributes = ConfigDefault.SearchAttributes
	}

	if cfg.UsernameField == "" {
		cfg.UsernameField = ConfigDefault.UsernameField
	}

	if cfg.PasswordField == "" {
		cfg.PasswordField = ConfigDefault.PasswordField
	}

	if cfg.CredentialsLookup == nil {
		cfg.CredentialsLookup = ConfigDefault.CredentialsLookup
	}

	return cfg
}
