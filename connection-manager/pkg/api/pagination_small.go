package api

import "github.com/labstack/echo/v4"

// smallListCap bounds endpoints that return a whole configuration table
// (roles, permissions, scripts, connectors, enrollment tokens, context
// policies, detection exceptions, automation rules, per-endpoint quarantine).
// These tables hold tens of rows and their screens need every row, so they keep
// the legacy full-list shape; the cap only guarantees a bounded response. When
// it trips, X-Result-Truncated tells the client the list is incomplete.
const smallListCap = 1000

func capList[T any](c echo.Context, rows []T) []T {
	if len(rows) <= smallListCap {
		return rows
	}
	c.Response().Header().Set("X-Result-Truncated", "true")
	return rows[:smallListCap]
}
