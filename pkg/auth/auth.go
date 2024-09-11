package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Token struct {
	Access         string `json:"access_token"`
	Refresh        string `json:"refresh_token"`
	AccessExpires  int    `json:"access_token_expiration"`
	RefreshExpires int    `json:"refresh_token_expiration"`
}

// GenerateNonce generates a nonce (number used once) based on the current Unix time in seconds.
// The function takes a parameter `now` which is a function returning the current time.
// It returns an integer representing the nonce.
//
// Example usage:
//
//	nonce := GenerateNonce(time.Now)
//	fmt.Println(nonce)
func GenerateNonce(now func() time.Time) int {
	return int(now().Unix() / 1000)
}

// GenerateSignature generates a HMAC SHA-256 signature based on the provided key, secret, and nonce.
// The function concatenates the nonce and key, then uses the secret to create a HMAC SHA-256 hash.
// The resulting signature is converted to an uppercase hexadecimal string.
//
// Example usage:
//
//	key := "exampleKey"
//	secret := "exampleSecret"
//	nonce := 12345
//	signature := GenerateSignature(key, secret, nonce)
//	fmt.Println(signature)
func GenerateSignature(key, secret string, nonce int) string {
	msg := strconv.Itoa(nonce) + key
	h := hmac.New(sha256.New, []byte(secret))

	h.Write([]byte(msg))
	sig := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	fmt.Printf("generated signature %s***\n", sig[:5])
	return sig
}

func RequestAPIToken() {
	// need to test if this works
	//endpoint := strings.Replace(baseUrl+"/auth/tokens", "//", "/", -1)
	//body := map[string]string{"auth_type": "api"}
}
