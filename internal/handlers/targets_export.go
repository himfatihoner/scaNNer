package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"scanner/internal/models"
)

// TargetListExport streams a target list's members as a plain-text file (one
// target per line), so a list can be re-used elsewhere or re-imported. Query:
// list=<id> for a named list, or list="" / "__none__" for the uncategorized
// bucket. Mirrors the VulnExport Content-Disposition download pattern.
func (h *Handler) TargetListExport(w http.ResponseWriter, r *http.Request) {
	ws := h.activeWorkspace(r)
	if ws == nil {
		http.Error(w, "no active workspace", http.StatusBadRequest)
		return
	}
	listID := strings.TrimSpace(r.URL.Query().Get("list"))

	var targets []models.Target
	name := "targets"
	switch listID {
	case "", "__none__":
		// Uncategorized bucket: targets with no list membership (same rule as
		// groupTargetsByList).
		all, _ := h.db.ListTargets(ws.ID, "")
		mem := h.db.TargetListMembership(ws.ID)
		for _, t := range all {
			if len(mem[t.ID]) == 0 {
				targets = append(targets, t)
			}
		}
		name = "uncategorized"
	default:
		tl, err := h.db.GetTargetList(listID)
		if err != nil || tl == nil || tl.WorkspaceID != ws.ID {
			http.Error(w, "target list not found", http.StatusNotFound)
			return
		}
		targets, _ = h.db.ListTargetsInList(listID)
		name = tl.Name
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=targets_%s.txt", safeFilename(name)))
	for _, t := range targets {
		fmt.Fprintln(w, t.Value)
	}
}

// safeFilename reduces an arbitrary name to a filesystem/header-safe slug.
func safeFilename(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '_' || r == '-' || r == '.':
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		out = "list"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}
