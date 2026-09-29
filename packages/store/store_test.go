package store

import (
	"testing"
	"time"

	"github.com/desurfofficial-ship-it/proofagent/packages/schemas"
)

func TestConsumeAuthSingleUse(t *testing.T) {
	s := NewMemory()
	a := &schemas.Authorization{
		AuthorizationID: "auth_1",
		AgentID:         "agt_1",
		Decision:        "ALLOW",
		Status:          "approved",
		ExpiresAt:       time.Now().UTC().Add(time.Minute).Format(time.RFC3339),
	}
	s.PutAuth(a)
	got, ok := s.ConsumeAuth("auth_1", time.Now().UTC())
	if !ok || got.Status != "consumed" {
		t.Fatalf("first consume failed")
	}
	_, ok = s.ConsumeAuth("auth_1", time.Now().UTC())
	if ok {
		t.Fatalf("second consume should fail")
	}
}
