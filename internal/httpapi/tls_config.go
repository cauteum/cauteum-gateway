package httpapi

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

func buildGatewayTLSConfig(opt Options) (*tls.Config, error) {
	if opt.TLSCert == "" || opt.TLSKey == "" {
		return nil, fmt.Errorf("gateway TLS requires both certificate and key")
	}
	serverCert, err := tls.LoadX509KeyPair(opt.TLSCert, opt.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("gateway TLS certificate/key could not be loaded: %w", err)
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}} //nolint:gosec // TLS 1.2 is the pinned minimum.
	if opt.TLSClientCA != "" {
		pem, err := os.ReadFile(opt.TLSClientCA)
		if err != nil {
			return nil, fmt.Errorf("gateway TLS client CA could not be read: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("gateway TLS client CA contains no valid certificates")
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.VerifyClientCertIfGiven
		if opt.TLSRequireClientAuth || opt.OIDC.Issuer == "" {
			config.ClientAuth = tls.RequireAndVerifyClientCert
		}
	} else if opt.TLSRequireClientAuth || opt.EnableMTLSAuth {
		return nil, fmt.Errorf("gateway TLS client certificate verification requires tls.client_ca_path")
	}

	extCertPath, extKeyPath := opt.TLSExternalCert, opt.TLSExternalKey
	if (extCertPath == "") != (extKeyPath == "") {
		return nil, fmt.Errorf("gateway TLS external certificate and key must be configured together")
	}
	if extCertPath != "" {
		if len(opt.TLSExternalServerNames) == 0 {
			return nil, fmt.Errorf("gateway TLS external_server_names is required with an external certificate")
		}
		extCert, err := tls.LoadX509KeyPair(extCertPath, extKeyPath)
		if err != nil {
			return nil, fmt.Errorf("gateway TLS external certificate/key could not be loaded: %w", err)
		}
		names := append([]string(nil), opt.TLSExternalServerNames...)
		leaf := extCert.Leaf
		if leaf == nil && len(extCert.Certificate) > 0 {
			leaf, err = x509.ParseCertificate(extCert.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("gateway TLS external certificate could not be parsed: %w", err)
			}
		}
		for _, name := range names {
			probe := name
			if strings.HasPrefix(name, "*.") {
				probe = "openshell-sni" + strings.TrimPrefix(name, "*")
			}
			if leaf == nil || leaf.VerifyHostname(probe) != nil {
				return nil, fmt.Errorf("gateway TLS external certificate does not cover configured server name %q", name)
			}
		}
		config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			for _, pattern := range names {
				if tlsServerNameMatches(pattern, clientHello.ServerName) {
					return &extCert, nil
				}
			}
			return &serverCert, nil
		}
	}
	return config, nil
}

func tlsServerNameMatches(pattern, serverName string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	serverName = strings.TrimSuffix(strings.ToLower(serverName), ".")
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == serverName
	}
	suffix := strings.TrimPrefix(pattern, "*")
	if !strings.HasSuffix(serverName, suffix) {
		return false
	}
	left := strings.TrimSuffix(serverName, suffix)
	return left != "" && !strings.Contains(left, ".")
}
