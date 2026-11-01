// Package auth verwaltet die Tokens der Agenten. Gespeichert werden nur SHA-256-Hashes.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// NewToken erzeugt ein zufälliges Token und den Hash, der gespeichert wird.
func NewToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(raw)
	return token, Hash(token), nil
}

// Hash ist der SHA-256 des Tokens in Hex; nur er wird gespeichert.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Match prüft, ob token zum gespeicherten Hash passt (zeitkonstanter Vergleich).
func Match(hash, token string) bool {
	want, err := hex.DecodeString(hash)
	if err != nil || token == "" {
		return false
	}
	got := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}
