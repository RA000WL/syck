package jsrecon

type JSRequest struct {
	Endpoint   string
	Method     string
	Headers    map[string]string
	Domains    []string
	APIKeys    []string
	SourceFile string
	SourceLine int
}
