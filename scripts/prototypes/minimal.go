package main

import (
	"net/http"
	"os"
)

func main() {
	if len(os.Args) > 1 {
		_ = http.ErrServerClosed
	}
	println("OpenRHP portability prototype")
}
