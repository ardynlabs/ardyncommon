package messaging

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewEnvelope(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("test", 3600))
	attributes := map[string]string{"tenant": "t-1"}
	event, err := NewEnvelope("identity.user.created", struct {
		UserID string `json:"user_id"`
	}{UserID: "u-1"}, Metadata{Attributes: attributes}, now)
	if err != nil {
		t.Fatal(err)
	}
	if event.ID == "" || event.Version != VersionV1 || event.Metadata.CorrelationID != event.ID || !event.OccurredAt.Equal(now.UTC()) {
		t.Fatalf("unexpected envelope: %#v", event)
	}
	attributes["tenant"] = "changed"
	if event.Metadata.Attributes["tenant"] != "t-1" {
		t.Fatal("event metadata aliases caller attributes")
	}
	var payload map[string]string
	if err := json.Unmarshal(event.Data, &payload); err != nil || payload["user_id"] != "u-1" {
		t.Fatalf("payload = %s, error = %v", event.Data, err)
	}
}

func TestNewEnvelopeRejectsInvalidInput(t *testing.T) {
	now := time.Now()
	if _, err := NewEnvelope("", nil, Metadata{}, now); err == nil {
		t.Fatal("NewEnvelope accepted empty type")
	}
	if _, err := NewEnvelope("test.event", nil, Metadata{}, time.Time{}); err == nil {
		t.Fatal("NewEnvelope accepted zero timestamp")
	}
	if _, err := NewEnvelope("test.event", make(chan int), Metadata{}, now); err == nil {
		t.Fatal("NewEnvelope accepted non-JSON payload")
	}
}
