package auth_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/lilWe3zy/ticketeer/pkg/auth"
)

var mockTimeNow = func() time.Time {
	return time.Unix(6942013370, 0)
}

func TestGenerateNonce(t *testing.T) {
	expected := 6942013
	nonce := auth.GenerateNonce(mockTimeNow)

	if nonce != expected {
		t.Errorf("expected %d, got %d", expected, nonce)
	}
}

func TestGenerateSignature(t *testing.T) {
	testCases := []struct {
		key      string
		secret   string
		nonce    int
		expected string
	}{
		// Random hex strings of equivalent length of Splynx tokens, don't get excited
		{"d0e0e21be10d744f0562d38d022d181b", "e459f3edeb4b10f755ee433db544e9f9", 1726070045, "3BCBF92DD327522A2D01C8560257DF34C1FAA831F18A7595C7B9E7F2631DB579"},
		{"1d5b3795cfe037f548318eb64737c8c8", "b5b71a66ae22bd5dcef8677b002049ad", 1726070081, "8F45EF5DFF1DF375D89BF127213994D7A83BC0B99BF3B488E6EFA9A2F167925B"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("key=%s,secret=%s,nonce%d", tc.key, tc.secret, tc.nonce), func(t *testing.T) {
			got := auth.GenerateSignature(tc.key, tc.secret, tc.nonce)

			if got != tc.expected {
				t.Errorf("GenerateSignature(%s, %s, %d) = %s; want %s", tc.key, tc.secret, tc.nonce, got, tc.expected)
			}
		})
	}
}
