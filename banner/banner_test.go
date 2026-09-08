package banner

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWrite(t *testing.T) {
	var output bytes.Buffer
	if err := Write(&output, "ardyn-citizen", "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), Logo+"\nardyn-citizen v1.2.3\n\n"; got != want {
		t.Fatalf("Write() output = %q, want %q", got, want)
	}
}

func TestWritePropagatesWriterError(t *testing.T) {
	want := errors.New("write failed")
	err := Write(failingWriter{err: want}, "service", "v1")
	if !errors.Is(err, want) {
		t.Fatalf("Write() error = %v, want %v", err, want)
	}
}

type failingWriter struct{ err error }

func (writer failingWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestLogoIsPrintable(t *testing.T) {
	if strings.TrimSpace(Logo) == "" {
		t.Fatal("Logo must not be empty")
	}
}
