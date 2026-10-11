// Package api provides role and permission management handlers.
package api

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/pkg/models"
)

// ============================================================================
// ROLE HANDLERS
// ============================================================================

// ListRoles returns all roles with their assigned permissions.
func (h *Handlers) ListRoles(c echo.Context) error {
	if h.roleRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	roles, err := h.roleRepo.ListRoles(c.Request().Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to list roles")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list roles")
	}
	roles = capList(c, roles)

	data := make([]RoleResponse, 0, len(roles))
	for _, r := range roles {
		perms := make([]PermissionResponse, 0, len(r.Permissions))
		for _, p := range r.Permissions {
			perms = append(perms, PermissionResponse{
				ID:          p.ID,
				Resource:    p.Resource,
				Action:      p.Action,
				Description: p.Description,
			})
		}
		data = append(data, RoleResponse{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			IsBuiltIn:   r.IsBuiltIn,
			Permissions: perms,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": data,
		"meta": responseMeta(c),
	})
}

// CreateRole creates a new custom role.
func (h *Handlers) CreateRole(c echo.Context) error {
	if h.roleRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	var req RoleCreateRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	if req.Name == "" {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Role name is required")
	}

	role := &models.Role{
		Name:        req.Name,
		Description: req.Description,
	}

	if err := h.roleRepo.CreateRole(c.Request().Context(), role); err != nil {
		h.logger.WithError(err).Warn("Failed to create role")
		return errorResponse(c, http.StatusConflict, "CREATE_FAILED", err.Error())
	}

	// If permission IDs provided, assign them
	if len(req.PermissionIDs) > 0 {
		if err := h.roleRepo.UpdateRolePermissions(c.Request().Context(), role.ID, req.PermissionIDs); err != nil {
			h.logger.WithError(err).Warn("Failed to assign permissions to new role")
		}
	}

	// Audit
	h.fireAudit(c, "role_created", "role", role.ID, "name="+role.Name, false, "")

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"data": RoleResponse{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
			IsBuiltIn:   false,
		},
		"meta": responseMeta(c),
	})
}

// UpdateRolePermissions replaces the permission set for a role.
func (h *Handlers) UpdateRolePermissions(c echo.Context) error {
	if h.roleRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	idStr := c.Param("id")
	roleID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid role ID format")
	}

	var req RoleUpdatePermissionsRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}

	// Protect the admin role: its permissions are immutable.
	// The admin bypass in RequirePermission grants full access regardless of DB entries,
	// so modifying admin permissions would be misleading and potentially dangerous.
	roles, err := h.roleRepo.ListRoles(c.Request().Context())
	if err == nil {
		for _, r := range roles {
			if r.ID == roleID && r.Name == "admin" {
				return errorResponse(c, http.StatusForbidden, "ADMIN_PROTECTED",
					"Cannot modify the permissions of the built-in admin role")
			}
		}
	}

	if err := h.roleRepo.UpdateRolePermissions(c.Request().Context(), roleID, req.PermissionIDs); err != nil {
		h.logger.WithError(err).Error("Failed to update role permissions")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update role permissions")
	}

	// Audit
	h.fireAudit(c, "role_updated", "role", roleID, "", false, "")

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Role permissions updated",
		"meta":    responseMeta(c),
	})
}

// DeleteRole deletes a custom role (built-in roles cannot be deleted).
func (h *Handlers) DeleteRole(c echo.Context) error {
	if h.roleRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	idStr := c.Param("id")
	roleID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid role ID format")
	}

	if err := h.roleRepo.DeleteRole(c.Request().Context(), roleID); err != nil {
		return errorResponse(c, http.StatusBadRequest, "DELETE_FAILED", "Cannot delete built-in role or role not found")
	}

	// Audit
	h.fireAudit(c, "role_deleted", "role", roleID, "", false, "")

	return c.NoContent(http.StatusNoContent)
}

// ============================================================================
// PERMISSION HANDLERS
// ============================================================================

// ListPermissions returns all available permissions.
func (h *Handlers) ListPermissions(c echo.Context) error {
	if h.roleRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	perms, err := h.roleRepo.ListPermissions(c.Request().Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to list permissions")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list permissions")
	}
	perms = capList(c, perms)

	data := make([]PermissionResponse, 0, len(perms))
	for _, p := range perms {
		data = append(data, PermissionResponse{
			ID:          p.ID,
			Resource:    p.Resource,
			Action:      p.Action,
			Description: p.Description,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": data,
		"meta": responseMeta(c),
	})
}
