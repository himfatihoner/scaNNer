package jwt

type Module struct{}

func (m *Module) Name() string        { return "jwt" }
func (m *Module) DisplayName() string { return "JWT Analyzer" }
func (m *Module) Description() string {
	return "Decode and audit JWTs: header/payload introspection, alg=none acceptance test, weak HS256 secret cracking with built-in + custom wordlist, kid injection patterns, and expiry/issuer checks."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "🔑" }
