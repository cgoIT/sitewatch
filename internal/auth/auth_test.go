package auth

import "testing"

func TestTokens(t *testing.T) {
	tok, hash, err := NewToken()
	if err != nil || len(tok) != 64 || hash != Hash(tok) {
		t.Fatalf("NewToken: %v", err)
	}
	if !Match(hash, tok) || Match(hash, tok+"x") || Match(hash, "") || Match("kein-hex", tok) {
		t.Error("Match")
	}
}
