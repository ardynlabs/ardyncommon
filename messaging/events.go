// Package messaging defines service-agnostic contracts for Kafka-backed events.
// It intentionally contains no Kafka client: services integrate their chosen
// adapter behind these interfaces and never call one another directly.
package messaging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const VersionV1 = "v1"

// Metadata carries tracing data across asynchronous service boundaries.
type Metadata struct {
	CorrelationID string            `json:"correlation_id"`
	CausationID   string            `json:"causation_id,omitempty"`
	TraceParent   string            `json:"traceparent,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// Envelope is the stable, versioned representation sent over the event bus.
// Data is JSON so publishers and consumers can remain independent of domain
// package types.
type Envelope struct {
	ID         string          `json:"id"`
	Version    string          `json:"version"`
	Type       string          `json:"type"`
	OccurredAt time.Time       `json:"occurred_at"`
	Metadata   Metadata        `json:"metadata"`
	Data       json.RawMessage `json:"data"`
}

// NewEnvelope constructs a v1 event and marshals a service-owned payload.
func NewEnvelope(eventType string, payload any, metadata Metadata, now time.Time) (Envelope, error) {
	if eventType == "" {
		return Envelope{}, errors.New("event type is required")
	}
	if now.IsZero() {
		return Envelope{}, errors.New("event time is required")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal event payload: %w", err)
	}
	id, err := randomID()
	if err != nil {
		return Envelope{}, err
	}
	if metadata.CorrelationID == "" {
		metadata.CorrelationID = id
	}
	metadata.Attributes = cloneAttributes(metadata.Attributes)
	return Envelope{
		ID:         id,
		Version:    VersionV1,
		Type:       eventType,
		OccurredAt: now.UTC(),
		Metadata:   metadata,
		Data:       data,
	}, nil
}

func randomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("create event ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func cloneAttributes(attributes map[string]string) map[string]string {
	if attributes == nil {
		return nil
	}
	clone := make(map[string]string, len(attributes))
	for key, value := range attributes {
		clone[key] = value
	}
	return clone
}

// Publisher is implemented by a Kafka adapter owned by a service's transport
// layer. It is the only direction for inter-service communication.
type Publisher interface {
	Publish(context.Context, Envelope) error
}

// Handler processes a consumed event.
type Handler func(context.Context, Envelope) error

// Consumer is implemented by a Kafka adapter. The adapter owns offsets,
// retries, dead-lettering and connection lifecycle policy.
type Consumer interface {
	Consume(context.Context, Handler) error
}
