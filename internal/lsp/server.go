package lsp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
	"github.com/RA000WL/syck/internal/scanner"
)

// Server is a minimal LSP server for real-time secret scanning.
type Server struct {
	mu        sync.Mutex
	in        *bufio.Reader
	out       io.Writer
	rootURI   string
	cfg       scanner.Config
	documents map[string]string // URI -> content
}

// NewServer creates a new LSP server reading from stdin and writing to stdout.
func NewServer() *Server {
	return &Server{
		in:        bufio.NewReader(os.Stdin),
		out:       os.Stdout,
		documents: make(map[string]string),
	}
}

// Run starts the LSP message loop.
func (s *Server) Run() error {
	for {
		req, err := s.readMessage()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read message: %w", err)
		}

		if req.ID != nil {
			s.handleRequest(req)
		} else {
			s.handleNotification(req)
		}
	}
}

func (s *Server) readMessage() (*Request, error) {
	var contentLength int
	for {
		line, err := s.in.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Content-Length: ") {
			fmt.Sscanf(line, "Content-Length: %d", &contentLength)
			break
		}
	}

	if contentLength <= 0 {
		return nil, fmt.Errorf("invalid content length: %d", contentLength)
	}

	buf := make([]byte, contentLength)
	_, err := io.ReadFull(s.in, buf)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var req Request
	if err := json.Unmarshal(buf, &req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &req, nil
}

func (s *Server) send(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.out.Write([]byte(header))
	if err != nil {
		return err
	}
	_, err = s.out.Write(data)
	return err
}

func (s *Server) sendResponse(id json.RawMessage, result interface{}) {
	s.send(Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func (s *Server) sendError(id json.RawMessage, code int, message string) {
	s.send(Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &ResponseError{Code: code, Message: message},
	})
}

func (s *Server) sendNotification(method string, params interface{}) {
	data, _ := json.Marshal(params)
	s.send(Notification{
		JSONRPC: "2.0",
		Method:  method,
		Params:  data,
	})
}

func (s *Server) handleRequest(req *Request) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "shutdown":
		s.sendResponse(req.ID, nil)
	default:
		s.sendError(req.ID, ErrMethodNotFound, "method not found: "+req.Method)
	}
}

func (s *Server) handleNotification(req *Request) {
	switch req.Method {
	case "initialized":
		// no-op
	case "textDocument/didOpen":
		s.handleDidOpen(req.Params)
	case "textDocument/didChange":
		s.handleDidChange(req.Params)
	case "textDocument/didSave":
		s.handleDidSave(req.Params)
	case "textDocument/didClose":
		s.handleDidClose(req.Params)
	case "exit":
		os.Exit(0)
	}
}

func (s *Server) handleInitialize(req *Request) {
	var params InitializeParams
	json.Unmarshal(req.Params, &params)
	s.rootURI = params.RootURI

	// Load rules and build scanner config
	rs, err := rules.LoadDefault()
	if err != nil {
		s.sendError(req.ID, ErrInternalError, "load rules: "+err.Error())
		return
	}

	s.cfg = scanner.Config{
		Workers:           1,
		MaxFileSize:       5 * 1024 * 1024,
		Rules:             rs,
		MinSeverity:       finding.SeverityLow,
		DecodeBase64:      true,
		DecodeHex:         true,
		DecodeUnicode:     true,
		DecodeURL:         true,
		JSReconstruct:     true,
		MultiLine:         true,
		DetectAuthHeaders: true,
		NoDedup:           true,
		DowngradeFP:       false,
	}

	result := InitializeResult{
		Capabilities: ServerCapabilities{
			TextDocumentSync: &TextDocumentSyncOptions{
				OpenClose: true,
				Change:    1, // Full sync
				Save:      &SaveOptions{IncludeText: true},
			},
			DiagnosticProvider: &DiagnosticOptions{
				Identifier:            "syck",
				InterFileDependencies: false,
				WorkspaceDiagnostics:  false,
			},
		},
	}
	s.sendResponse(req.ID, result)
}

func (s *Server) handleDidOpen(params json.RawMessage) {
	var p DidOpenTextDocumentParams
	json.Unmarshal(params, &p)
	s.documents[p.TextDocument.URI] = p.TextDocument.Text
	s.scanAndPublish(p.TextDocument.URI, p.TextDocument.Text)
}

func (s *Server) handleDidChange(params json.RawMessage) {
	var p DidChangeTextDocumentParams
	json.Unmarshal(params, &p)
	if len(p.ContentChanges) > 0 {
		content := p.ContentChanges[len(p.ContentChanges)-1].Text
		s.documents[p.TextDocument.URI] = content
		s.scanAndPublish(p.TextDocument.URI, content)
	}
}

func (s *Server) handleDidSave(params json.RawMessage) {
	var p DidSaveTextDocumentParams
	json.Unmarshal(params, &p)
	content := p.Text
	if content == "" {
		content = s.documents[p.TextDocument.URI]
	}
	if content != "" {
		s.scanAndPublish(p.TextDocument.URI, content)
	}
}

func (s *Server) handleDidClose(params json.RawMessage) {
	var p DidCloseTextDocumentParams
	json.Unmarshal(params, &p)
	delete(s.documents, p.TextDocument.URI)
	// Clear diagnostics for closed file
	s.sendNotification("textDocument/publishDiagnostics", PublishDiagnosticsParams{
		URI:         p.TextDocument.URI,
		Diagnostics: []Diagnostic{},
	})
}

func (s *Server) scanAndPublish(uri, content string) {
	path := uriToPath(uri)
	findings := scanner.ScanContent(content, path, s.cfg)

	diagnostics := make([]Diagnostic, 0, len(findings))
	for _, f := range findings {
		line := f.Line - 1
		if line < 0 {
			line = 0
		}
		col := f.Column
		if col < 0 {
			col = 0
		}
		endCol := col + len(f.Secret)
		if endCol > len(f.Context) {
			endCol = len(f.Context)
		}

		severity := findingToSeverity(f.Severity)
		msg := fmt.Sprintf("[%s] %s", f.RuleName, f.Secret)
		if f.Context != "" {
			truncated := f.Context
			if len(truncated) > 120 {
				truncated = truncated[:120] + "..."
			}
			msg += "\n" + truncated
		}

		diagnostics = append(diagnostics, Diagnostic{
			Range: Range{
				Start: Position{Line: line, Character: col},
				End:   Position{Line: line, Character: endCol},
			},
			Severity: severity,
			Source:   "syck",
			Message:  msg,
			Code:     f.RuleName,
		})
	}

	s.sendNotification("textDocument/publishDiagnostics", PublishDiagnosticsParams{
		URI:         uri,
		Diagnostics: diagnostics,
	})
}

func findingToSeverity(sev finding.Severity) int {
	switch sev {
	case finding.SeverityCritical:
		return SeverityError
	case finding.SeverityHigh:
		return SeverityError
	case finding.SeverityMedium:
		return SeverityWarning
	case finding.SeverityLow:
		return SeverityInfo
	default:
		return SeverityHint
	}
}

func uriToPath(uri string) string {
	if strings.HasPrefix(uri, "file://") {
		path := strings.TrimPrefix(uri, "file://")
		// Windows: file:///C:/path -> /C:/path, strip leading /
		if len(path) > 2 && path[0] == '/' && path[2] == ':' {
			path = path[1:]
		}
		return path
	}
	return uri
}
