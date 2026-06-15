package httpclient

import (
	"net/http"
	"testing"
	"time"
)

func TestNewTransport_Default(t *testing.T) {
	tr := NewTransport("", false)
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.Proxy != nil {
		t.Error("expected nil Proxy when proxyURL is empty (should use ProxyFromEnvironment)")
	}
}

func TestNewTransport_WithProxy(t *testing.T) {
	tr := NewTransport("http://127.0.0.1:8080", false)
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.Proxy == nil {
		t.Fatal("expected non-nil Proxy function")
	}
}

func TestNewTransport_InsecureSkipVerify(t *testing.T) {
	tr := NewTransport("", true)
	if tr.TLSClientConfig == nil {
		t.Fatal("expected non-nil TLSClientConfig")
	}
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
}

func TestNewClient_Timeout(t *testing.T) {
	c := NewClient(15*time.Second, "", false)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.Timeout != 15*time.Second {
		t.Errorf("expected timeout 15s, got %v", c.Timeout)
	}
}

func TestNewClient_RedirectPolicy(t *testing.T) {
	c := NewClient(10*time.Second, "", false)
	if c.CheckRedirect == nil {
		t.Fatal("expected non-nil CheckRedirect")
	}
}

func TestNewClient_ProxyPassthrough(t *testing.T) {
	c := NewClient(10*time.Second, "http://127.0.0.1:8080", false)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	transport, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.Proxy == nil {
		t.Error("expected non-nil Proxy on transport")
	}
}
