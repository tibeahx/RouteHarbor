// Package web embeds the offline, dependency-free control panel.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets/*
var assets embed.FS

func Handler() http.Handler {
	f, _ := fs.Sub(assets, "assets")
	files := http.FileServer(http.FS(f))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/index.html", "/app.js", "/style.css", "/strings.js", "/favicon.svg":
			files.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
