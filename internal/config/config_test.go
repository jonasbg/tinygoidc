package config

import (
	"os"
	"testing"
)

func TestLoadUsers(t *testing.T) {
	data := `users:
  - name: "Alice Example"
    email: "alice@example.com"
`
	f, err := os.CreateTemp("", "users-*.yaml")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(data); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	f.Close()

	users, err := LoadUsers(f.Name())
	if err != nil {
		t.Fatalf("LoadUsers failed: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	u := users[0]
	if u.Sub != u.Email {
		t.Fatalf("expected Sub to default to Email, got Sub=%q Email=%q", u.Sub, u.Email)
	}
	if u.Initials == "" {
		t.Fatalf("expected initials to be computed, got empty")
	}
}
