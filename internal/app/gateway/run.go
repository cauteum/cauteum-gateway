// Package gateway wires the control-plane application.
package gateway

import (
	"github.com/cauteum/cauteum-gateway/internal/httpapi"
)

// Run is the composition root for cauteum-gateway.
func Run(args []string) error {
	return httpapi.Run(args)
}
