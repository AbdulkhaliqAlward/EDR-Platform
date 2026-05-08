// Package api provides zero-touch provisioning endpoints.
package api

import (
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
)

// ServeCA serves the public CA certificate so agents can auto-bootstrap TLS
// trust without manual file distribution. The CA certificate is public data
// (only the public key) — serving it over plain HTTP is standard practice
// (identical to CRL / AIA distribution).
func (h *Handlers) ServeCA(c echo.Context) error {
	if h.caCertPath == "" {
		h.logger.Error("ServeCA: caCertPath not configured")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "CA certificate path not configured on server",
		})
	}

	pemData, err := os.ReadFile(h.caCertPath)
	if err != nil {
		h.logger.Errorf("ServeCA: failed to read CA certificate at %s: %v", h.caCertPath, err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to read CA certificate",
		})
	}

	return c.Blob(http.StatusOK, "application/x-pem-file", pemData)
}

// realIP extracts the real client IP, honouring X-Forwarded-For and X-Real-IP.
// Falls back to the remote address from the request.
func realIP(c echo.Context) string {
	if xff := c.Request().Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	if xri := c.Request().Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(strings.TrimSpace(xri)) != nil {
			return strings.TrimSpace(xri)
		}
	}
	host, _, err := net.SplitHostPort(c.Request().RemoteAddr)
	if err != nil {
		return c.Request().RemoteAddr
	}
	return host
}
