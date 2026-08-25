package models

import (
	"database/sql"
	"time"
)

// TargetType categorizes a target.
//
// IPv4 / Domain / FQDN are entered together through the "IPs / Domains"
// textarea on the Add Targets modal — each line is classified by
// shared.ClassifyInput so the user doesn't have to pre-sort. URL is a
// separate field because URLs carry scheme + path, which makes them a
// fundamentally different scan unit (most modules treat URL as "single
// target with explicit path" rather than expanding sub-hosts).
type TargetType string

const (
	TargetIPv4   TargetType = "ipv4"
	TargetDomain TargetType = "domain"
	TargetFQDN   TargetType = "fqdn"
	TargetURL    TargetType = "url"
)

// Target represents a scan target within a workspace. A target may optionally
// belong to a TargetList (ListID). NULL ListID = uncategorized / default.
type Target struct {
	ID          string         `db:"id"           json:"id"`
	WorkspaceID string         `db:"workspace_id" json:"workspace_id"`
	Value       string         `db:"value"        json:"value"`
	Type        TargetType     `db:"type"         json:"type"`
	Note        string         `db:"note"         json:"note"`
	// ListID is the LEGACY single-list column, no longer used for grouping.
	// A target's categories now come from the many-to-many join table and
	// are loaded into Categories for display (a target may be in several).
	ListID    sql.NullString `db:"list_id"    json:"list_id"`
	CreatedAt time.Time      `db:"created_at" json:"created_at"`
	// Categories is populated by handlers (not from the targets row) with
	// every list/category this target belongs to. db:"-" so sqlx ignores it.
	Categories []TargetList `db:"-" json:"categories,omitempty"`
}

// TargetList is a per-workspace named list of targets, so users can
// organize hosts ("Company A targets", "Company B targets").
type TargetList struct {
	ID          string    `db:"id"           json:"id"`
	WorkspaceID string    `db:"workspace_id" json:"workspace_id"`
	Name        string    `db:"name"         json:"name"`
	Description string    `db:"description"  json:"description"`
	CreatedAt   time.Time `db:"created_at"   json:"created_at"`
}

// AssetList struct was removed when the user-curated asset-lists
// feature was retired. The DB tables (asset_lists / asset_list_members)
// are DROPped in the migration block; the /assets page is now a flat
// read-only view of every host any scan has touched.

// TargetTypeLabel returns a human-readable label
func TargetTypeLabel(t TargetType) string {
	switch t {
	case TargetIPv4:
		return "IPv4 Address"
	case TargetDomain:
		return "Domain"
	case TargetFQDN:
		return "FQDN"
	case TargetURL:
		return "URL"
	default:
		return string(t)
	}
}
