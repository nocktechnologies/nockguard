package jsonrpc

import "encoding/json"

type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (m *Message) IsRequest() bool  { return m.Method != "" && m.ID != nil }
func (m *Message) IsNotify() bool   { return m.Method != "" && m.ID == nil }
func (m *Message) IsResponse() bool { return m.Method == "" && m.ID != nil }

func Decode(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

func ErrorResponse(id json.RawMessage, code int, message string) []byte {
	resp := Message{
		JSONRPC: "2.0",
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}
