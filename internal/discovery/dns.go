package discovery

import (
	"context"
	"net"
	"time"
)

// netLookupHost resolves a hostname to IP addresses.
// Uses a short timeout to avoid hanging on unresponsive DNS.
func netLookupHost(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resolver := &net.Resolver{}
	return resolver.LookupHost(ctx, host)
}
