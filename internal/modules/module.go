package modules

import "sort"

// Status represents the current state of a scan
type Status string

const (
	StatusIdle    Status = "idle"
	StatusRunning Status = "running"
	StatusDone    Status = "done"
	StatusError   Status = "error"
)

// Result holds the output of a scan
type Result struct {
	Module string      `json:"module"`
	Status Status      `json:"status"`
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// Module is the interface that all scanning modules must implement
type Module interface {
	// Name returns the unique identifier of the module
	Name() string
	// DisplayName returns the human-readable name
	DisplayName() string
	// Description returns what this module does
	Description() string
	// Category returns the module category (e.g. "network", "web")
	Category() string
	// Icon returns a CSS class or emoji for the UI
	Icon() string
}

// ModuleInfo holds metadata about a registered module for the UI
type ModuleInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Icon        string `json:"icon"`
}

// Registry holds all registered scanning modules
type Registry struct {
	modules map[string]Module
}

// NewRegistry creates a new module registry
func NewRegistry() *Registry {
	return &Registry{
		modules: make(map[string]Module),
	}
}

// Register adds a module to the registry
func (r *Registry) Register(m Module) {
	r.modules[m.Name()] = m
}

// Get returns a module by name
func (r *Registry) Get(name string) (Module, bool) {
	m, ok := r.modules[name]
	return m, ok
}

// List returns info about all registered modules sorted alphabetically by display name.
func (r *Registry) List() []ModuleInfo {
	list := make([]ModuleInfo, 0, len(r.modules))
	for _, m := range r.modules {
		list = append(list, ModuleInfo{
			Name:        m.Name(),
			DisplayName: m.DisplayName(),
			Description: m.Description(),
			Category:    m.Category(),
			Icon:        m.Icon(),
		})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].DisplayName < list[j].DisplayName
	})
	return list
}

// Categories returns modules grouped by category, sorted alphabetically within each.
func (r *Registry) Categories() map[string][]ModuleInfo {
	cats := make(map[string][]ModuleInfo)
	for _, m := range r.modules {
		info := ModuleInfo{
			Name:        m.Name(),
			DisplayName: m.DisplayName(),
			Description: m.Description(),
			Category:    m.Category(),
			Icon:        m.Icon(),
		}
		cats[m.Category()] = append(cats[m.Category()], info)
	}
	for cat := range cats {
		sort.Slice(cats[cat], func(i, j int) bool {
			return cats[cat][i].DisplayName < cats[cat][j].DisplayName
		})
	}
	return cats
}
