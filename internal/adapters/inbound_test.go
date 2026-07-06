package adapters

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProcessInboundRequest_Valid(t *testing.T) {
	body := `{"id":"CUST-1","name":"Jane Doe","account":"ACC-1","amount":250.5,
		"latitude":6.4541,"longitude":3.3947,"timestamp":"2026-01-15T14:07:33Z"}`
	req := httptest.NewRequest("POST", "/process", strings.NewReader(body))

	raw, err := ProcessInboundRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw.ID != "CUST-1" || raw.Amount != 250.5 {
		t.Errorf("unexpected decode: %+v", raw)
	}
}

func TestProcessInboundRequest_Rejects(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"not json", `hello`},
		{"missing id", `{"name":"J","account":"A","amount":1,"timestamp":"2026-01-15T14:07:33Z"}`},
		{"null id", `{"id":null,"name":"J","account":"A","amount":1,"timestamp":"2026-01-15T14:07:33Z"}`},
		{"empty id", `{"id":"","name":"J","account":"A","amount":1,"timestamp":"2026-01-15T14:07:33Z"}`},
		{"null amount", `{"id":"C","name":"J","account":"A","amount":null,"timestamp":"2026-01-15T14:07:33Z"}`},
		{"string amount", `{"id":"C","name":"J","account":"A","amount":"lots","timestamp":"2026-01-15T14:07:33Z"}`},
		{"bad timestamp", `{"id":"C","name":"J","account":"A","amount":1,"timestamp":"01/15/2026"}`},
		{"lat without lon", `{"id":"C","name":"J","account":"A","amount":1,"latitude":6.4,"timestamp":"2026-01-15T14:07:33Z"}`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("POST", "/process", strings.NewReader(tc.body))
		if _, err := ProcessInboundRequest(req); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}
