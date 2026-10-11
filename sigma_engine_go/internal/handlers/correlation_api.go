package handlers

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/edr-platform/sigma-engine/internal/analytics"
	"github.com/gorilla/mux"
)

// RegisterCorrelationRoutes wires in-memory correlation and incident APIs on the
// /api/v1 subrouter (paths are relative: /sigma/...). Pass nil mgr to no-op.
func RegisterCorrelationRoutes(api *mux.Router, mgr *analytics.CorrelationManager) {
	if api == nil || mgr == nil {
		return
	}
	h := &correlationAPIHandler{mgr: mgr}
	api.HandleFunc("/sigma/alerts/correlation", h.getCorrelations).Methods("GET")
	api.HandleFunc("/sigma/incidents", h.listIncidents).Methods("GET")
	api.HandleFunc("/sigma/incidents", h.createIncident).Methods("POST")
	api.HandleFunc("/sigma/incidents/{id}", h.getIncident).Methods("GET")
	api.HandleFunc("/sigma/incidents/{id}", h.updateIncident).Methods("PUT")
	api.HandleFunc("/sigma/incidents/{id}/notes", h.addIncidentNote).Methods("POST")
}

type correlationAPIHandler struct {
	mgr *analytics.CorrelationManager
}

func (h *correlationAPIHandler) getCorrelations(w http.ResponseWriter, r *http.Request) {
	alertID := r.URL.Query().Get("alert_id")
	if alertID == "" {
		writeJSON(w, http.StatusOK, h.mgr.GetAnalytics())
		return
	}
	correlations := h.mgr.GetAlertCorrelations(alertID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alert_id":     alertID,
		"correlations": correlations,
		"total":        len(correlations),
	})
}

// maxIncidentList bounds GET /sigma/incidents (newest incidents are kept).
const maxIncidentList = 1000

func (h *correlationAPIHandler) listIncidents(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	incidents := h.mgr.ListIncidents(status)
	// The manager iterates a map: give the list a stable newest-first order
	// (id breaks ties) and bound the response like other full-list endpoints.
	sort.Slice(incidents, func(i, j int) bool {
		if !incidents[i].CreatedAt.Equal(incidents[j].CreatedAt) {
			return incidents[i].CreatedAt.After(incidents[j].CreatedAt)
		}
		return incidents[i].ID > incidents[j].ID
	})
	total := len(incidents)
	if total > maxIncidentList {
		incidents = incidents[:maxIncidentList]
		w.Header().Set("X-Result-Truncated", "true")
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"incidents": incidents,
		"total":     total,
	})
}

func (h *correlationAPIHandler) createIncident(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AlertIDs []string `json:"alert_ids"`
		Title    string   `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	incident, err := h.mgr.CreateIncident(req.AlertIDs, req.Title)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, incident)
}

func (h *correlationAPIHandler) getIncident(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	incident, err := h.mgr.GetIncident(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, incident)
}

func (h *correlationAPIHandler) updateIncident(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	incident, err := h.mgr.UpdateIncident(id, req.Status)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, incident)
}

func (h *correlationAPIHandler) addIncidentNote(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		AuthorID string `json:"author_id"`
		Content  string `json:"content"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.mgr.AddNote(id, req.AuthorID, req.Content); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Note added"})
}
