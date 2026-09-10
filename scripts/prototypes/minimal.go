package main

import (
	"net/http"
	"os"
)

func main() {
	if len(os.Args) > 1 {
		_ = http.ErrServerClosed
	}
	println("RouteHarbor portability prototype")
}
