// Package api provides transport-neutral response models shared by Ardyn APIs.
package api

// Problem follows RFC 9457's problem-details shape. Type can be a stable,
// service-defined URI or identifier; Detail must be safe to expose to clients.
type Problem struct {
	Type     string `json:"type,omitempty"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// NewProblem creates a client-safe problem response.
func NewProblem(status int, title, detail string) Problem {
	return Problem{Status: status, Title: title, Detail: detail}
}

// Response is the standard envelope for successful API responses where an
// envelope is useful. APIs may return a resource directly instead.
type Response[T any] struct {
	Data T `json:"data"`
}
