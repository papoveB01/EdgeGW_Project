package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalSink_WritesWhatItReceived(t *testing.T) {
	dir := t.TempDir()
	sink, err := newLocalSink(dir)
	if err != nil {
		t.Fatalf("newLocalSink: %v", err)
	}
	t.Cleanup(func() { sink.Close() })

	payloads := [][]byte{
		[]byte(`{"identity_mosaic":"abc","amount_tier":"TIER_1"}`),
		[]byte(`{"identity_mosaic":"def","amount_tier":"TIER_2"}`),
	}
	for _, p := range payloads {
		if err := sink.Forward(context.Background(), p); err != nil {
			t.Fatalf("Forward: %v", err)
		}
	}

	wantFile := filepath.Join(dir, "signals-"+time.Now().UTC().Format("2006-01-02")+".ndjson")
	f, err := os.Open(wantFile)
	if err != nil {
		t.Fatalf("expected sink file %s to exist: %v", wantFile, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanning sink file: %v", err)
	}

	if len(lines) != len(payloads) {
		t.Fatalf("expected %d lines, got %d: %v", len(payloads), len(lines), lines)
	}
	for i, line := range lines {
		var got, want map[string]interface{}
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i, err)
		}
		if err := json.Unmarshal(payloads[i], &want); err != nil {
			t.Fatalf("fixture %d not valid JSON: %v", i, err)
		}
		if got["identity_mosaic"] != want["identity_mosaic"] {
			t.Errorf("line %d: got mosaic %v, want %v", i, got["identity_mosaic"], want["identity_mosaic"])
		}
	}
}

func TestLocalSink_CreatesDirIfMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "sink")
	sink, err := newLocalSink(dir)
	if err != nil {
		t.Fatalf("newLocalSink: %v", err)
	}
	t.Cleanup(func() { sink.Close() })

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("expected sink dir to be created: %v", err)
	}
}

func TestLocalSink_MultipleForwardsAppendNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	sink, err := newLocalSink(dir)
	if err != nil {
		t.Fatalf("newLocalSink: %v", err)
	}
	t.Cleanup(func() { sink.Close() })

	const n = 50
	for i := 0; i < n; i++ {
		if err := sink.Forward(context.Background(), []byte(`{"n":`+string(rune('0'+i%10))+`}`)); err != nil {
			t.Fatalf("Forward %d: %v", i, err)
		}
	}

	wantFile := filepath.Join(dir, "signals-"+time.Now().UTC().Format("2006-01-02")+".ndjson")
	data, err := os.ReadFile(wantFile)
	if err != nil {
		t.Fatalf("reading sink file: %v", err)
	}
	f, err := os.Open(wantFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	lineCount := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineCount++
	}
	if lineCount != n {
		t.Errorf("expected %d lines, got %d (raw: %d bytes)", n, lineCount, len(data))
	}
}
