package spider

type Module struct{}

func (m *Module) Name() string        { return "spider" }
func (m *Module) DisplayName() string { return "Web Spider" }
func (m *Module) Description() string {
	return "Crawl websites to discover paths, directories, files, and endpoints by recursively following links, scripts, forms, and resource references."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "🕷️" }
