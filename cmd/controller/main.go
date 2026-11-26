// Command controller hands out random entry/middle/exit relays from a pool.
//
// This is a local-demo controller: no authentication, one endpoint.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"dvpn-sim/internal/registry"
)

type assignment struct {
	Entry  registry.Relay `json:"entry"`
	Middle registry.Relay `json:"middle"`
	Exit   registry.Relay `json:"exit"`
}

func main() {
	relaysPath := flag.String("relays", "relays.json", "relay registry JSON")
	listen := flag.String("listen", "127.0.0.1:18000", "HTTP listen address")
	flag.Parse()

	pool, err := registry.Load(*relaysPath)
	if err != nil {
		log.Fatalf("relays: %v", err)
	}
	log.Printf("controller: loaded %d relays from %s", len(pool.Relays), *relaysPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/assign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		entry, middle, exit, err := pool.Assign()
		if err != nil {
			log.Printf("assign: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(assignment{Entry: entry, Middle: middle, Exit: exit}); err != nil {
			log.Printf("assign encode: %v", err)
			return
		}
		// One line per assignment so cluster scripts can audit exactly the
		// circuit the client was given.
		fmt.Printf("assign entry=%s middle=%s exit=%s\n", entry.ID, middle.ID, exit.ID)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("controller listening on http://%s", *listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
