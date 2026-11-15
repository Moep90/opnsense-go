package api

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSelectedMapListOrdered_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected SelectedMapListOrdered
	}{
		{
			name: "keeps response order of selected keys",
			input: `{
				"zebra": {"selected": 1, "value": "z"},
				"alpha": {"selected": true, "value": "a"},
				"beta": {"selected": 0, "value": "b"},
				"gamma": {"selected": false, "value": "g"}
			}`,
			expected: SelectedMapListOrdered{"zebra", "alpha"},
		},
		{name: "empty map", input: `{}`, expected: SelectedMapListOrdered{}},
		{name: "empty array fallback", input: `[]`, expected: SelectedMapListOrdered{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got SelectedMapListOrdered
			if err := json.Unmarshal([]byte(tt.input), &got); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}

	var got SelectedMapListOrdered
	if err := json.Unmarshal([]byte(`{invalid}`), &got); err == nil {
		t.Error("expected error for invalid json")
	}
}

func TestSelectedMapListOrdered_MarshalJSON(t *testing.T) {
	s := SelectedMapListOrdered{"zebra", "alpha"}
	b, err := json.Marshal(&s)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"zebra,alpha"` {
		t.Errorf("got %s, want order preserved", b)
	}
}
