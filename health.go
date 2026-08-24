package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
)

func init() {
    go func() {
        port := os.Getenv("PORT")
        if port == "" {
            port = "8080"
        }
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
            fmt.Fprintln(w, "NPVT Bot is running")
        })
        if err := http.ListenAndServe(":"+port, nil); err != nil {
            log.Printf("HTTP server: %v", err)
        }
    }()
}
