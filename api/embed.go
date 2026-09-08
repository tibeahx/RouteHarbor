// Package contract embeds the public API definition in the single server binary.
package contract

import _ "embed"

//go:embed openapi.yaml
var OpenAPI []byte
