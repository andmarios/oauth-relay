package httputil

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteJSON(rr, http.StatusCreated, map[string]string{"key": "value"})

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if !strings.Contains(rr.Body.String(), `"key":"value"`) {
		t.Errorf("body = %q, want key:value", rr.Body.String())
	}
}

func TestReadJSON(t *testing.T) {
	body := strings.NewReader(`{"name":"test"}`)
	req := httptest.NewRequest("POST", "/", body)
	rr := httptest.NewRecorder()

	var v struct {
		Name string `json:"name"`
	}
	if err := ReadJSON(rr, req, &v); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if v.Name != "test" {
		t.Errorf("name = %q, want test", v.Name)
	}
}

func TestReadJSONBodyLimit(t *testing.T) {
	// Create a body larger than 1 MB
	big := strings.Repeat("x", 1<<20+100)
	body := strings.NewReader(`{"data":"` + big + `"}`)
	req := httptest.NewRequest("POST", "/", body)
	rr := httptest.NewRecorder()

	var v struct {
		Data string `json:"data"`
	}
	if err := ReadJSON(rr, req, &v); err == nil {
		t.Error("expected error for oversized body")
	}
}
