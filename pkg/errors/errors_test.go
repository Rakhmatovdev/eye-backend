package errors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestOKEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	OK(c, gin.H{"foo": "bar"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if raw["success"] != true {
		t.Fatalf("expected success=true, got %v", raw["success"])
	}
	data, ok := raw["data"].(map[string]interface{})
	if !ok {
		t.Fatal("expected data object")
	}
	if data["foo"] != "bar" {
		t.Fatalf("unexpected data payload: %v", data)
	}
	if _, hasError := raw["error"]; hasError {
		t.Fatal("success envelope must not include an error field")
	}
}

func TestOKWithMetaEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	OKWithMeta(c, []int{1, 2}, gin.H{"page": 1, "total": 2})

	var raw map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	meta, ok := raw["meta"].(map[string]interface{})
	if !ok {
		t.Fatal("expected meta object")
	}
	if meta["total"] != float64(2) {
		t.Fatalf("unexpected meta: %v", meta)
	}
}

func TestFailEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Fail(c, ErrForbidden)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if raw["success"] != false {
		t.Fatalf("expected success=false, got %v", raw["success"])
	}
	errObj, ok := raw["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object")
	}
	if errObj["message"] != "forbidden" {
		t.Fatalf("unexpected error message: %v", errObj["message"])
	}
	if _, hasData := raw["data"]; hasData {
		t.Fatal("failure envelope must not include a data field")
	}
}

func TestAbortEnvelopeAndAborts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Abort(c, ErrUnauthorized)

	if !c.IsAborted() {
		t.Fatal("Abort should abort the gin context")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestFailMsgEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	FailMsg(c, http.StatusBadRequest, "bad input")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	errObj := raw["error"].(map[string]interface{})
	if errObj["message"] != "bad input" {
		t.Fatalf("unexpected message: %v", errObj["message"])
	}
}
