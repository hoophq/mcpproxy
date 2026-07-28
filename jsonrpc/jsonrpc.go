// Package jsonrpc implements a tolerant JSON-RPC 2.0 envelope used by the
// MCP gateway. It parses only what the inspector needs (id, method, params,
// result, error) and preserves unknown fields verbatim so protocol revisions
// pass through untouched.
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ID is a JSON-RPC id: string, integer, or null. The zero value means
// "absent" (notification). Raw preserves the exact wire bytes so the gateway
// can correlate responses and re-emit the id byte for byte.
type ID struct {
	Raw json.RawMessage
}

// IsZero reports whether the id was absent (a notification).
func (id ID) IsZero() bool { return len(id.Raw) == 0 }

// Key returns a map key for correlation. Distinct wire encodings ("1" vs
// "\"1\"") produce distinct keys, matching JSON-RPC semantics where ids are
// compared by value and type.
func (id ID) Key() string { return string(id.Raw) }

func (id ID) String() string { return string(id.Raw) }

// MarshalJSON re-emits the exact bytes received.
func (id ID) MarshalJSON() ([]byte, error) {
	if id.IsZero() {
		return []byte("null"), nil
	}
	return id.Raw, nil
}

// UnmarshalJSON captures the raw id bytes.
func (id *ID) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		id.Raw = nil
		return nil
	}
	id.Raw = append(json.RawMessage(nil), b...)
	return nil
}

// Message is a single JSON-RPC 2.0 message. Exactly one of Method (request /
// notification) or Result/Error (response) is set. Extra carries any fields
// beyond the standard five so re-serialization drops nothing.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      ID              `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`

	// Extra holds unrecognized top-level fields, re-emitted on Marshal.
	Extra map[string]json.RawMessage `json:"-"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message) }

// Standard and gateway-specific error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInternalError  = -32603

	// CodePolicyDenied is returned when the gateway blocks a request by
	// policy. The session stays alive; the client sees a readable refusal.
	CodePolicyDenied = -32010
	// CodeApprovalRejected is returned when a human reviewer rejects a held
	// tool call.
	CodeApprovalRejected = -32011
	// CodeBudgetExceeded is returned when a session/tool budget is exhausted.
	CodeBudgetExceeded = -32012
)

// IsRequest reports whether m is a request expecting a response.
func (m *Message) IsRequest() bool { return m.Method != "" && !m.ID.IsZero() }

// IsNotification reports whether m is a notification (no response expected).
func (m *Message) IsNotification() bool { return m.Method != "" && m.ID.IsZero() }

// IsResponse reports whether m answers an earlier request.
func (m *Message) IsResponse() bool { return m.Method == "" && (m.Result != nil || m.Error != nil) }

var standardFields = map[string]bool{
	"jsonrpc": true, "id": true, "method": true,
	"params": true, "result": true, "error": true,
}

// Parse decodes a single JSON-RPC message, tolerating and preserving unknown
// top-level fields. It returns an error only for malformed JSON or a message
// that is neither request, notification, nor response.
func Parse(data []byte) (*Message, error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("malformed json-rpc message: %w", err)
	}
	var m Message
	if v, ok := all["jsonrpc"]; ok {
		_ = json.Unmarshal(v, &m.JSONRPC)
	}
	if v, ok := all["id"]; ok {
		if err := m.ID.UnmarshalJSON(v); err != nil {
			return nil, err
		}
	}
	if v, ok := all["method"]; ok {
		if err := json.Unmarshal(v, &m.Method); err != nil {
			return nil, fmt.Errorf("invalid method field: %w", err)
		}
	}
	m.Params = all["params"]
	m.Result = all["result"]
	if v, ok := all["error"]; ok && !bytes.Equal(v, []byte("null")) {
		m.Error = &Error{}
		if err := json.Unmarshal(v, m.Error); err != nil {
			return nil, fmt.Errorf("invalid error field: %w", err)
		}
	}
	for k, v := range all {
		if !standardFields[k] {
			if m.Extra == nil {
				m.Extra = map[string]json.RawMessage{}
			}
			m.Extra[k] = v
		}
	}
	if m.Method == "" && m.Result == nil && m.Error == nil {
		return nil, fmt.Errorf("message is neither request nor response")
	}
	return &m, nil
}

// Marshal serializes the message, re-emitting preserved unknown fields.
func (m *Message) Marshal() ([]byte, error) {
	out := map[string]json.RawMessage{}
	ver := m.JSONRPC
	if ver == "" {
		ver = "2.0"
	}
	vb, _ := json.Marshal(ver)
	out["jsonrpc"] = vb
	if !m.ID.IsZero() {
		out["id"] = m.ID.Raw
	}
	if m.Method != "" {
		mb, _ := json.Marshal(m.Method)
		out["method"] = mb
	}
	if m.Params != nil {
		out["params"] = m.Params
	}
	if m.Result != nil {
		out["result"] = m.Result
	}
	if m.Error != nil {
		eb, err := json.Marshal(m.Error)
		if err != nil {
			return nil, err
		}
		out["error"] = eb
	}
	for k, v := range m.Extra {
		out[k] = v
	}
	return json.Marshal(out)
}

// NewError builds an error response answering id.
func NewError(id ID, code int, msg string) *Message {
	return &Message{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: msg}}
}

// NewResult builds a success response answering id.
func NewResult(id ID, result any) (*Message, error) {
	b, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &Message{JSONRPC: "2.0", ID: id, Result: b}, nil
}
