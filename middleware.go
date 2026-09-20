package echobasicauth

import (
	"net"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// ContextLoginKey is the key used to store the login after successful auth in the context
const ContextLoginKey = "echo-basic-auth.login"

// ClientIP resolves the client address, trusting forwarded headers only when echo.IPExtractor is set
func ClientIP(c echo.Context) string {
	if e := c.Echo(); e != nil && e.IPExtractor != nil {
		return c.RealIP()
	}
	remoteAddr := c.Request().RemoteAddr
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// NewValidator returns a new BasicAuthValidator
func NewValidator(auths ...*Auth) middleware.BasicAuthValidator {
	auths = slices.DeleteFunc(auths, func(a *Auth) bool { return a == nil })
	if len(auths) == 0 {
		return nil
	}
	return func(login, password string, c echo.Context) (bool, error) {
		ip := ClientIP(c)
		wasIPAllowed, wasAuthAllowed := false, false
		for _, auth := range auths {
			allowedIP := auth.AllowedIP(ip)
			if allowedIP {
				wasIPAllowed = true
			}
			// Empty configured creds must never match, or a service that lost its password degrades to IP-only auth.
			match := auth.Login != "" && auth.Password != "" && equals(auth.Login, login) && equals(auth.Password, password)
			if match {
				wasAuthAllowed = true
			}

			if match && allowedIP {
				c.Set(ContextLoginKey, login)
				return true, nil
			}
		}

		logAttempt(c, ip, wasIPAllowed, wasAuthAllowed)
		return false, nil
	}
}

// logAttempt logs a failed authentication attempt at WARN, visible once the app raises the logger level
func logAttempt(c echo.Context, ip string, wasIPAllowed, wasAuthAllowed bool) {
	requestPath := strings.ReplaceAll(strings.ReplaceAll(c.Request().URL.Path, "\n", ""), "\r", "")
	c.Logger().Warnf(
		`%s - FAIL [%s] "%s %s %s" 401 0 "-" "Auth: false (ip: %t; creds: %t)"`,
		anonymizeIP(ip),
		time.Now().Format("2/Jan/2006:15:04:05 -0700"),
		c.Request().Method,
		requestPath,
		c.Request().Proto,
		wasIPAllowed,
		wasAuthAllowed,
	)
}

// NewMiddleware returns a new BasicAuth middleware instance
func NewMiddleware(auths ...*Auth) echo.MiddlewareFunc {
	return middleware.BasicAuth(NewValidator(auths...))
}
