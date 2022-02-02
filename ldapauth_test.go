package fiber_ldapauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

var helloworldHandler = func(c *fiber.Ctx) error {
	return c.SendString("Hello, World!")
}

var testServers = map[string]map[string]string{
	// https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/
	"forumsys": {
		"_username":       "tesla",
		"_password":       "password",
		"URL":             "ldap://ldap.forumsys.com:389",
		"BindDN":          "cn=read-only-admin,dc=example,dc=com",
		"BindCredentials": "password",
		"SearchBase":      "dc=example,dc=com",
		"SearchFilter":    "(&(objectClass=organizationalPerson)(uid={{username}}))",
	},
	// https://www.freeipa.org/page/Demo
	"freeipa": {
		"_username":       "employee",
		"_password":       "Secret123",
		"URL":             "ldap://ipa.demo1.freeipa.org:389",
		"BindDN":          "uid=admin,cn=users,cn=accounts,dc=demo1,dc=freeipa,dc=org",
		"BindCredentials": "Secret123",
		"SearchBase":      "cn=accounts,dc=demo1,dc=freeipa,dc=org",
		"SearchFilter":    "(uid={{username}})",
	},
	// If one wants to authenticate only using BindDN and BindCredentials
	"freeipaBindOnly": {
		"_username":       "",
		"_password":       "",
		"URL":             "ldap://ipa.demo1.freeipa.org:389",
		"BindDN":          "uid=admin,cn=users,cn=accounts,dc=demo1,dc=freeipa,dc=org",
		"BindCredentials": "Secret123",
		"SearchBase":      "",
		"SearchFilter":    "",
	},
}

func TestQueryAuth(t *testing.T) {
	for k := range testServers {
		app := fiber.New()
		app.Use(New(Config{
			URL:             testServers[k]["URL"],
			BindDN:          testServers[k]["BindDN"],
			BindCredentials: testServers[k]["BindCredentials"],
			SearchBase:      testServers[k]["SearchBase"],
			SearchFilter:    testServers[k]["SearchFilter"],
		}))
		app.Get("/testauth", helloworldHandler)
		target := fmt.Sprintf("/testauth?username=%s&password=%s", testServers[k]["_username"], testServers[k]["_password"])
		req := httptest.NewRequest("GET", target, nil)
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf(`%s: %s`, t.Name(), err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected 200, got %d status code.", resp.StatusCode)
		}
	}
}

func TestBodyFormAuth(t *testing.T) {
	for k := range testServers {
		app := fiber.New()
		app.Use(New(Config{
			URL:             testServers[k]["URL"],
			BindDN:          testServers[k]["BindDN"],
			BindCredentials: testServers[k]["BindCredentials"],
			SearchBase:      testServers[k]["SearchBase"],
			SearchFilter:    testServers[k]["SearchFilter"],
		}))
		app.Post("/testauth", helloworldHandler)
		s := fmt.Sprintf("username=%s&password=%s", testServers[k]["_username"], testServers[k]["_password"])
		body := strings.NewReader(s)
		req := httptest.NewRequest("POST", "/testauth", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf(`%s: %s`, t.Name(), err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected 200, got %d status code.", resp.StatusCode)
		}
	}
}

func TestBodyJSONAuth(t *testing.T) {
	for k := range testServers {
		app := fiber.New()
		app.Use(New(Config{
			URL:             testServers[k]["URL"],
			BindDN:          testServers[k]["BindDN"],
			BindCredentials: testServers[k]["BindCredentials"],
			SearchBase:      testServers[k]["SearchBase"],
			SearchFilter:    testServers[k]["SearchFilter"],
		}))
		app.Post("/testauth", helloworldHandler)
		jsonbytes, _ := json.Marshal(map[string]interface{}{
			"username": testServers[k]["_username"],
			"password": testServers[k]["_password"],
		})
		body := bytes.NewReader(jsonbytes)
		req := httptest.NewRequest("POST", "/testauth", body)
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf(`%s: %s`, t.Name(), err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected 200, got %d status code.", resp.StatusCode)
		}
	}
}

func TestBasicAuth(t *testing.T) {
	for k := range testServers {
		app := fiber.New()
		app.Use(New(Config{
			URL:             testServers[k]["URL"],
			BindDN:          testServers[k]["BindDN"],
			BindCredentials: testServers[k]["BindCredentials"],
			SearchBase:      testServers[k]["SearchBase"],
			SearchFilter:    testServers[k]["SearchFilter"],
		}))
		app.Get("/testauth", helloworldHandler)
		req := httptest.NewRequest("GET", "/testauth", nil)
		basicstr := fmt.Sprintf("Basic %s:%s", testServers[k]["_username"], testServers[k]["_password"])
		enc := base64.StdEncoding.EncodeToString([]byte(basicstr))
		req.Header.Set("Authorization", enc)
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf(`%s: %s`, t.Name(), err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected 200, got %d status code.", resp.StatusCode)
		}
	}
}

func TestWrongBindCredentials(t *testing.T) {
	app := fiber.New()
	app.Use(New(Config{
		URL:             testServers["forumsys"]["URL"],
		BindDN:          testServers["forumsys"]["BindDN"],
		BindCredentials: "wrongpassword",
		SearchBase:      testServers["forumsys"]["SearchBase"],
		SearchFilter:    testServers["forumsys"]["SearchFilter"],
	}))
	app.Get("/testauth", helloworldHandler)
	target := fmt.Sprintf("/testauth?username=%s&password=%s", testServers["forumsys"]["_username"], testServers["forumsys"]["_password"])
	req := httptest.NewRequest("GET", target, nil)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 401 {
		t.Errorf("Expected 401, got %d status code.", resp.StatusCode)
	}
}

func TestErrorCallback(t *testing.T) {
	app := fiber.New()
	app.Use(New(Config{
		URL:             testServers["forumsys"]["URL"],
		BindDN:          testServers["forumsys"]["BindDN"],
		BindCredentials: "wrongpassword",
		SearchBase:      testServers["forumsys"]["SearchBase"],
		SearchFilter:    testServers["forumsys"]["SearchFilter"],
		ErrorCallback: func(c *fiber.Ctx, e error) error {
			if !strings.Contains(e.Error(), "Invalid Credentials") {
				t.Errorf("Expected Invalid Credentials error, got %v", e)
			}
			return e
		},
	}))
	app.Get("/testauth", helloworldHandler)
	target := fmt.Sprintf("/testauth?username=%s&password=%s", testServers["forumsys"]["_username"], testServers["forumsys"]["_password"])
	req := httptest.NewRequest("GET", target, nil)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 401 {
		t.Errorf("Expected 401, got %d status code.", resp.StatusCode)
	}
}

func TestSuccessCallback(t *testing.T) {
	app := fiber.New()
	app.Use(New(Config{
		URL:             testServers["forumsys"]["URL"],
		BindDN:          testServers["forumsys"]["BindDN"],
		BindCredentials: testServers["forumsys"]["BindCredentials"],
		SearchBase:      testServers["forumsys"]["SearchBase"],
		SearchFilter:    testServers["forumsys"]["SearchFilter"],
		SuccessCallback: func(c *fiber.Ctx) error {
			c.Locals("ldapcb", "ok")
			// Continue stack
			return c.Next()
		},
	}))
	app.Get("/testauth", func(c *fiber.Ctx) error {
		if c.Locals("ldapcb") != "ok" {
			t.Errorf("Expected ok, got %s status code.", c.Locals("ldapcb"))
		}
		return c.SendString("Hello, World!")
	})
	target := fmt.Sprintf("/testauth?username=%s&password=%s", testServers["forumsys"]["_username"], testServers["forumsys"]["_password"])
	req := httptest.NewRequest("GET", target, nil)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d status code.", resp.StatusCode)
	}
}

func TestNextOnIgnoredRoutes(t *testing.T) {
	ignoredRoutes := []string{"GET::/about", "POST::/signup"}
	app := fiber.New()
	app.Use(New(Config{
		Next: func(c *fiber.Ctx) bool {
			// Continue to stack if matched to an ignored route.
			if len(ignoredRoutes) > 0 {
				url := c.Method() + "::" + c.Path()
				for i := range ignoredRoutes {
					if ignoredRoutes[i] == url {
						c.Locals("ignoredroutes", "ok")
						return true
					}
				}
			}
			return false
		},
		URL:             testServers["forumsys"]["URL"],
		BindDN:          testServers["forumsys"]["BindDN"],
		BindCredentials: "wrongpassword",
		SearchBase:      testServers["forumsys"]["SearchBase"],
		SearchFilter:    testServers["forumsys"]["SearchFilter"],
	}))
	app.Use(func(c *fiber.Ctx) error {
		if c.Locals("ignoredroutes") != "ok" {
			t.Errorf("Expected ok, got %s status code.", c.Locals("ignoredroutes"))
		}
		return nil
	})
	app.Get("/about", func(c *fiber.Ctx) error {
		return c.SendString("Do not need to authenticate GET::/about")
	})
	req := httptest.NewRequest("GET", "/about", nil)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d status code.", resp.StatusCode)
	}
}
