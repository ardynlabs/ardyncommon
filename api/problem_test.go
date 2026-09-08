package api

import (
	"encoding/json"
	"testing"
)

func TestProblemAndResponseJSONShape(t *testing.T) {
	problem := NewProblem(401, "Unauthorized", "Credentials are required.")
	encodedProblem, err := json.Marshal(problem)
	if err != nil {
		t.Fatal(err)
	}
	if string(encodedProblem) != `{"title":"Unauthorized","status":401,"detail":"Credentials are required."}` {
		t.Fatalf("problem JSON = %s", encodedProblem)
	}

	encodedResponse, err := json.Marshal(Response[string]{Data: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if string(encodedResponse) != `{"data":"ok"}` {
		t.Fatalf("response JSON = %s", encodedResponse)
	}
}
