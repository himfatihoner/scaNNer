package handlers

import (
	"net/http"

	"scanner/internal/database"
)

// LogsPage renders the admin-only audit log. It is strictly read-only: there is
// no delete/edit path anywhere in the app, so the trail survives scan deletion
// and cannot be purged from the UI (even by an admin).
func (h *Handler) LogsPage(w http.ResponseWriter, r *http.Request) {
	filter := database.AuditFilter{
		Category: r.URL.Query().Get("category"),
		Username: r.URL.Query().Get("user"),
		Action:   r.URL.Query().Get("action"),
		Limit:    1000,
	}
	entries, _ := h.db.ListAudit(filter)

	data := h.baseData(r, "Audit Logs - scaNNer", "logs")
	data["Entries"] = entries
	data["FilterCategory"] = filter.Category
	data["FilterUser"] = filter.Username
	data["FilterAction"] = filter.Action
	h.render(w, "layout", data)
}
