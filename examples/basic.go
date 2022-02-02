package main

import (
	ldapauth "github.com/eozer/fiber_ldapauth"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	app.Use(ldapauth.New(ldapauth.Config{
		URL:             "ldap://ldap.forumsys.com:389",
		BindDN:          "cn=read-only-admin,dc=example,dc=com",
		BindCredentials: "password",
		SearchBase:      "dc=example,dc=com",
		SearchFilter:    "(&(objectClass=organizationalPerson)(uid={{username}}))",
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	app.Listen(":3000")
}
