package fiber_ldapauth

import (
	"errors"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/gofiber/fiber/v2"
)

// New creates a new middleware handler.
func New(config Config) fiber.Handler {
	// Set default config
	cfg := configDefault(config)

	return func(c *fiber.Ctx) error {
		// Do not execute middleware if Next returns true.
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		l, err := ldap.DialURL(cfg.URL)
		if err != nil {
			return errorHandler(c, err, cfg.ErrorCallback)
		}
		defer l.Close()

		if cfg.TLSConfig != nil {
			err = l.StartTLS(cfg.TLSConfig)
			if err != nil {
				return errorHandler(c, err, cfg.ErrorCallback)
			}
		}

		// First bind with a read only user
		if cfg.BindCredentials == "" {
			err = l.UnauthenticatedBind(cfg.BindDN)
		} else {
			err = l.Bind(cfg.BindDN, cfg.BindCredentials)
		}
		if err != nil {
			return errorHandler(c, err, cfg.ErrorCallback)
		}

		// Search user
		if cfg.SearchBase != "" || cfg.SearchFilter != "" {
			username, password, err := cfg.CredentialsLookup(c, cfg.UsernameField, cfg.PasswordField)
			if err != nil {
				return errorHandler(c, err, cfg.ErrorCallback)
			}

			sf := strings.Replace(cfg.SearchFilter, "{{username}}", ldap.EscapeFilter(username), -1)
			sreq := ldap.NewSearchRequest(
				cfg.SearchBase,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				sf,
				cfg.SearchAttributes,
				nil,
			)
			sres, err := l.Search(sreq)
			if err != nil {
				return errorHandler(c, err, cfg.ErrorCallback)
			}
			if len(sres.Entries) != 1 {
				return errorHandler(c, errors.New("user does not exist or too many entries returned"), cfg.ErrorCallback)
			}

			userDN := sres.Entries[0].DN
			// Bind as the user to verify their password
			err = l.Bind(userDN, password)
			if err != nil {
				return errorHandler(c, err, cfg.ErrorCallback)
			}
		}

		// Continue stack
		if cfg.SuccessCallback != nil {
			return cfg.SuccessCallback(c)
		} else {
			panic("SuccessCallback must not be nil")
		}
	}
}
