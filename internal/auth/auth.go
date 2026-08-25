// Package auth holds the cryptographic primitives behind scaNNer's login,
// session, and two-factor layer. It is deliberately HTTP-free and side-effect
// free so every routine here is unit-testable in isolation (see auth_test.go).
//
// Design notes:
//   - Passwords are hashed with bcrypt (cost 12). bcrypt is pure-Go via
//     golang.org/x/crypto and needs no CGO, so it composes with the modernc
//     sqlite driver the rest of the app uses.
//   - Session tokens are 32 bytes of crypto/rand rendered base64url. The raw
//     token lives ONLY in the user's cookie; the database stores sha256(token)
//     so a database leak does not hand out live sessions.
//   - TOTP is implemented in-house per RFC 6238 (HMAC-SHA1, 30s step, 6 digits)
//     rather than pulling a dependency — it is small and worth auditing directly
//     for a security tool.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is intentionally above the library default (10). 12 is a good
// balance for an interactive login on modern hardware (~250ms).
const bcryptCost = 12

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

// HashPassword returns a bcrypt hash suitable for storage in users.password_hash.
func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(b), nil
}

// CheckPassword reports whether plain matches the stored bcrypt hash. It runs in
// (roughly) constant time relative to the hash, which is what we want for login.
func CheckPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// DummyHash is a real bcrypt hash used to equalize login timing for unknown
// users: LoginSubmit compares against it when the username does not exist, so an
// attacker cannot distinguish "no such user" from "wrong password" by timing
// (bcrypt does the same work either way). It is computed once at init from a
// fixed string so it is GUARANTEED to be a well-formed hash — a hand-written
// malformed constant would make CompareHashAndPassword error out instantly and
// silently defeat the defense.
var DummyHash = mustDummyHash()

func mustDummyHash() string {
	h, err := bcrypt.GenerateFromPassword([]byte("scaNNer login timing equalizer - not a credential"), bcryptCost)
	if err != nil {
		return ""
	}
	return string(h)
}

// ---------------------------------------------------------------------------
// Session tokens
// ---------------------------------------------------------------------------

// NewSessionToken returns a fresh random opaque token for the session cookie.
func NewSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the sha256 of a session/OTP token, hex-encoded. This is what
// gets persisted; the raw token never touches the database.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum)
}

// ConstantTimeEqual compares two strings without leaking length-independent
// timing. Use for comparing hashed tokens/codes.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------------------------------------------------------------------------
// Random admin / temp passwords
// ---------------------------------------------------------------------------

// pwAlphabet excludes visually ambiguous characters (0/O, 1/l/I) so an operator
// can transcribe a printed bootstrap password without confusion.
const pwAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%*-_"

// GeneratePassword returns a cryptographically-random password of n characters.
func GeneratePassword(n int) (string, error) {
	if n <= 0 {
		n = 20
	}
	var sb strings.Builder
	max := big.NewInt(int64(len(pwAlphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		sb.WriteByte(pwAlphabet[idx.Int64()])
	}
	return sb.String(), nil
}

// ---------------------------------------------------------------------------
// Email OTP (six-digit numeric)
// ---------------------------------------------------------------------------

// GenerateEmailOTP returns a random 6-digit numeric code as a string.
func GenerateEmailOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238)
// ---------------------------------------------------------------------------

const (
	totpPeriod = 30 // seconds per step
	totpDigits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a base32-encoded 20-byte secret for a new enrollment.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp secret: %w", err)
	}
	return b32.EncodeToString(b), nil
}

// totpAt computes the TOTP code for the given secret at a specific counter step.
func totpAt(secretB32 string, counter uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secretB32)))
	if err != nil {
		return "", fmt.Errorf("decode totp secret: %w", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	code = code % 1000000
	return fmt.Sprintf("%0*d", totpDigits, code), nil
}

// currentCounter is the TOTP step counter for the current wall-clock time.
func currentCounter() uint64 {
	return uint64(time.Now().Unix() / totpPeriod)
}

// VerifyTOTPStep checks a code against the secret (allowing ±1 step of skew) and
// returns the matched step counter. The caller enforces one-time use by
// rejecting any step at or below the last step it accepted for that user — so a
// captured code cannot be replayed within its ~90s validity window.
func VerifyTOTPStep(secretB32, code string) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	counter := int64(currentCounter())
	for _, delta := range []int64{0, -1, 1} {
		step := counter + delta
		want, err := totpAt(secretB32, uint64(step))
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// VerifyTOTP checks a user-supplied code against the secret, allowing ±1 step of
// clock skew. Used for enrollment confirmation (where replay is not a concern).
func VerifyTOTP(secretB32, code string) bool {
	_, ok := VerifyTOTPStep(secretB32, code)
	return ok
}

// OTPAuthURL builds the otpauth:// URI an authenticator app consumes (also what
// we render as a QR code during enrollment).
func OTPAuthURL(issuer, account, secretB32 string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
