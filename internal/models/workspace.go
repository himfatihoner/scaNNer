package models

import "time"

// Workspace represents a scanning project workspace
type Workspace struct {
	ID          string    `db:"id"          json:"id"`
	Name        string    `db:"name"        json:"name"`
	Description string    `db:"description" json:"description"`
	IsDefault   bool      `db:"is_default"  json:"is_default"`
	CreatedAt   time.Time `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"  json:"updated_at"`
}

// WorkspaceStats holds aggregated stats for a workspace
type WorkspaceStats struct {
	Workspace
	TargetCount int `db:"target_count"    json:"target_count"`
	IPv4Count   int `db:"ipv4_count"      json:"ipv4_count"`
	DomainCount int `db:"domain_count"    json:"domain_count"`
	FQDNCount   int `db:"fqdn_count"      json:"fqdn_count"`
}
