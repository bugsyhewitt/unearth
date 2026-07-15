// Package httpclient provides the shared *http.Client used by techniques and
// the orchestration engine. It centralizes timeout, redirect, TLS, and User-
// Agent policy so individual techniques can focus on protocol-specific work.
package httpclient

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"
)

// Version is the unearth release the User-Agent advertises. GoReleaser
// injects the real tag at build time via ldflags; the default is the dev
// sentinel used for local builds.
var Version = "1.1.0"

// Options configures the shared client. The zero value is usable: it expands
// to sensible defaults via New.
type Options struct {
	// Timeout is the overall per-request deadline. Default 20s.
	Timeout time.Duration
	// UserAgent is the value sent in the User-Agent header. Default
	// "unearth/<Version>".
	UserAgent string
	// MaxRedirects is the maximum number of redirects followed. Default 5.
	MaxRedirects int
	// InsecureTLS, when true, skips TLS certificate verification. Passive
	// techniques keep this false; active techniques (Packet 5) flip it to
	// connect to a server by IP whose certificate names a different host.
	InsecureTLS bool
}

// New returns an *http.Client tuned for recon use.
func New(opts Options) *http.Client {
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "unearth/" + Version
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 5
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: opts.InsecureTLS, // #nosec G402 — Packet 5 toggles this for IP-pinned probes
		},
	}

	return &http.Client{
		Transport: &uaTransport{base: transport, userAgent: opts.UserAgent},
		Timeout:   opts.Timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= opts.MaxRedirects {
				return errors.New("httpclient: too many redirects")
			}
			return nil
		},
	}
}

// uaTransport wraps another RoundTripper and stamps a default User-Agent on
// every outbound request that didn't set one explicitly.
type uaTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", t.userAgent)
	}
	return t.base.RoundTrip(req)
}
