// Package gateway wires the control-plane application.
package gateway

import (
	"github.com/cautem/cautem-gateway/internal/httpapi"
)

// Run is the composition root for cautem-gateway.
func Run(args []string) error {
	return httpapi.Run(args)
}
