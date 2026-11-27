package main

import (
	"fmt"
	"log"

	"dvpn-sim/internal/assign"
	"dvpn-sim/internal/model"
	"dvpn-sim/internal/registry"
)

func main() {
	relays := []registry.Relay{
		{ID: "entry-0", Role: "entry", Addr: "127.0.0.1:17101", AS: "AS1"},
		{ID: "middle-0", Role: "middle", Addr: "127.0.0.1:17102", AS: "AS2"},
		{ID: "exit-0", Role: "exit", Addr: "127.0.0.1:17103", AS: "AS3"},
	}
	dir, err := assign.NewDirectory(relays)
	if err != nil {
		log.Fatal(err)
	}
	es, err := assign.NewServer(model.RoleEntry, dir.ByRole(model.RoleEntry), 1)
	if err != nil {
		log.Fatal(err)
	}
	ms, err := assign.NewServer(model.RoleMiddle, dir.ByRole(model.RoleMiddle), 2)
	if err != nil {
		log.Fatal(err)
	}
	xs, err := assign.NewServer(model.RoleExit, dir.ByRole(model.RoleExit), 3)
	if err != nil {
		log.Fatal(err)
	}
	board, err := assign.NewBoard(es, ms, xs, 16)
	if err != nil {
		log.Fatal(err)
	}
	ticket, err := board.Assign()
	if err != nil {
		log.Fatal(err)
	}
	tel := assign.NewTelescope(ticket)
	n, err := tel.Client.Build(tel.Entry)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("client view: entry=%s token=%s\n", tel.Client.Entry.ID, tel.Client.Token)
	fmt.Printf("telescope: learned %d hop keys (no middle/exit identities)\n", n)

	payload := []byte("hello from telescope")
	cell, err := tel.Client.Seal(payload)
	if err != nil {
		log.Fatal(err)
	}
	got, err := tel.Entry.Peel(cell)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("data: %s\n", got)
}
