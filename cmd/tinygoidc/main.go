package main

import (
	"fmt"
	"log"
	"os"

	"tinygoidc/internal/config"
	"tinygoidc/internal/oidc"
	"tinygoidc/internal/server"
)

func main() {
	usersPath := os.Getenv("USERS")
	if usersPath == "" {
		usersPath = "users.yaml"
	}
	users, err := config.LoadUsers(usersPath)
	if err != nil {
		log.Fatalf("failed to load users: %v", err)
	}
	keys := oidc.GenerateKeySet()
	s := server.New(users, keys)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}
	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("Mock OIDC server listening at http://localhost:%s", port)
	log.Fatal(s.Engine.Run(addr))
}
