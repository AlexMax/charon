package main

import (
	"log"

	"github.com/AlexMax/charon"
)

func main() {
	log.Print("Starting Charon...")

	// Construct application.
	authApp, err := charon.NewAuthApp()
	if err != nil {
		log.Fatal(err)
	}

	// Start the application server.
	log.Fatal(authApp.ListenAndServe(":16666"))
}
