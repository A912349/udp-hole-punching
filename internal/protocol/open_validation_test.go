package protocol

// These tests cover open validation behavior and regression cases.
import (
	"errors"
	"fmt"
	"testing"
)

func TestOpenRejectsMalformedNonceAndTag(t *testing.T) {
	key := make([]byte, 32)
	for _, field := range []string{"nonce", "tag"} {
		for _, size := range []int{0, 1, 11, 12, 15, 16, 17, 32} {
			if field == "nonce" && size == 12 || field == "tag" && size == 16 {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", field, size), func(t *testing.T) {
				sealed, err := Seal(key, []byte("payload"), nil)
				if err != nil {
					t.Fatal(err)
				}
				sealed[field] = B64Encode(make([]byte, size))
				if _, err := Open(key, sealed, nil); !errors.Is(err, ErrProtocol) {
					t.Fatalf("expected protocol error, got %v", err)
				}
			})
		}
	}
	// Missing fields decode to empty slices and must not panic either.
	if _, err := Open(key, map[string]string{}, nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("missing fields: %v", err)
	}
}
