package authproxy

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Authenticator is a method for authenticating a bearer token.
type Authenticator interface {
	// AuthenticateToken maps a bearer token to a username and set of groups.
	AuthenticateToken(string) (username string, groups []string, err error)
}

// Config holds fields for customizing the auth proxy behavior.
type Config struct {
	// Backend address, authentication strategy, and TLS configuration.
	Backend          string
	BackendAuth      func(r *http.Request)
	BackendTLSConfig *tls.Config

	// Authenticator for evaluating bearer tokesn of client requests.
	Authenticator Authenticator

	// Optional logger to use when reporting errors. If not supplied, the
	// proxy uses the log package's default logger.
	Logger *log.Logger
}

// New constructs an Kubernetes auth proxy which authenticates client requests
// and uses impersonation headers to impersonate that user to the backend
// service.
func New(c *Config) (http.Handler, error) {
	backend, err := url.Parse(c.Backend)
	if err != nil {
		return nil, errors.Wrap(err, "parsing backend URL")
	}
	httpProxy := httputil.NewSingleHostReverseProxy(backend)
	httpProxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       c.BackendTLSConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	httpProxy.ErrorLog = c.Logger

	tcpProxy, err := newTCPReverseProxy(&tcpProxyConfig{
		Backend:   c.Backend,
		TLSConfig: c.BackendTLSConfig,
		Logger:    c.Logger,
	})
	if err != nil {
		return nil, errors.Wrap(err, "initializing upgrade support")
	}

	return &proxy{
		authenticator: c.Authenticator,
		backendAuth:   c.BackendAuth,
		tcpProxy:      tcpProxy,
		httpProxy:     httpProxy,
		logger:        c.Logger,
	}, nil
}

type proxy struct {
	authenticator Authenticator

	backendAuth func(r *http.Request)

	httpProxy *httputil.ReverseProxy
	tcpProxy  *tcpReverseProxy

	logger *log.Logger
}

func (p *proxy) logf(format string, v ...interface{}) {
	if p.logger != nil {
		p.logger.Printf(format, v...)
		return
	}
	log.Printf(format, v...)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for k := range r.Header {
		if strings.HasPrefix(k, "Impersonate-") {
			http.Error(w, "Impersonation requests not supported", http.StatusBadRequest)
			return
		}
	}

	const (
		bearerPrefix        = "bearer "
		authorizationHeader = "Authorization"
	)

	p.logf("Proxy Request: %v %v", r.Method, r.URL.Path)
	oidcAuth := func() error {
		a := r.Header.Get(authorizationHeader)
		if !strings.HasPrefix(strings.ToLower(a), bearerPrefix) {
			return fmt.Errorf("no authorization header")
		}

		r.Header.Del(authorizationHeader)

		token := a[len(bearerPrefix):]

		username, groups, err := p.authenticator.AuthenticateToken(token)
		if err != nil {
			p.logf("invalid oidc credentials: %v", err)
			return err
		}

		p.logf("authenticate successful, username: %v, group: %v", username, groups)
		r.Header.Set("Impersonate-User", username)
		for _, group := range groups {
			r.Header.Add("Impersonate-Group", group)
		}
		return nil
	}

	// when oidc token failed, will continue use other authenticate type
	if err := oidcAuth(); err == nil {
		p.backendAuth(r)
	} else if ImpersonateDashboard(r) {
		// TODO: remove impersonate dashboard. dashboard should use kubernetes-dashboard service account to visit kube-oidc-proxy
		p.logf("impersonate dashboard user: system:serviceaccount:kubernetes-dashboard:kubernetes-dashboard")
		p.backendAuth(r)
	}

	if isUpgradeRequest(r) {
		p.tcpProxy.ServeHTTP(w, r)
		return
	}
	p.httpProxy.ServeHTTP(w, r)
}

func ImpersonateDashboard(req *http.Request) bool {
	if strings.HasPrefix(req.Header.Get("User-Agent"), "dashboard") {
		req.Header.Set("Impersonate-User", "system:serviceaccount:kubernetes-dashboard:kubernetes-dashboard")
		return true
	}
	return false
}
