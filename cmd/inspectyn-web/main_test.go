package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestHelpAndInvalidOptions(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, &output); err != nil || !strings.Contains(output.String(), "127.0.0.1") {
		t.Fatalf("help = %s, %v", output.String(), err)
	}
	for _, args := range [][]string{{"--port", "-1"}, {"--port", "65536"}, {"--host", "0.0.0.0"}, {"unexpected"}} {
		if err := run(context.Background(), args, &output); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
