package httpapi

import "time"

// Operational defaults for the HTTP control plane and its background operations.
const (
	relayRequestTimeout      = 10 * time.Second
	providerRotationInterval = 15 * time.Second
	oauthRequestTimeout      = 20 * time.Second
	defaultServiceSessionTTL = 24 * time.Hour
	relayRetryInterval       = 500 * time.Millisecond
	headerReadTimeout        = 5 * time.Second
	shutdownTimeout          = 5 * time.Second
)
