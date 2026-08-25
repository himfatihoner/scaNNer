package auth

import (
	"testing"
)

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse battery staple") {
		t.Fatal("correct password should verify")
	}
	if CheckPassword(h, "wrong") {
		t.Fatal("wrong password must not verify")
	}
	if CheckPassword(DummyHash, "anything") {
		t.Fatal("dummy hash must never verify (defends the enumeration timing path)")
	}
}

func TestSessionTokenAndHash(t *testing.T) {
	tok, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 40 {
		t.Fatalf("token too short: %q", tok)
	}
	tok2, _ := NewSessionToken()
	if tok == tok2 {
		t.Fatal("two tokens must differ")
	}
	if HashToken(tok) == tok {
		t.Fatal("stored hash must not equal the raw token")
	}
	if HashToken(tok) != HashToken(tok) {
		t.Fatal("hash must be deterministic")
	}
	if !ConstantTimeEqual(HashToken(tok), HashToken(tok)) {
		t.Fatal("equal hashes should compare equal")
	}
}

func TestGeneratePassword(t *testing.T) {
	p, err := GeneratePassword(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 20 {
		t.Fatalf("want 20 chars, got %d", len(p))
	}
	for _, c := range p {
		if !containsRune(pwAlphabet, c) {
			t.Fatalf("password contains out-of-alphabet char %q", c)
		}
	}
	p2, _ := GeneratePassword(20)
	if p == p2 {
		t.Fatal("two generated passwords must differ")
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func TestEmailOTPFormat(t *testing.T) {
	c, err := GenerateEmailOTP()
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 6 {
		t.Fatalf("want 6 digits, got %q", c)
	}
	for _, d := range c {
		if d < '0' || d > '9' {
			t.Fatalf("non-digit in OTP: %q", c)
		}
	}
}

// RFC 6238 Appendix B test vector: secret "12345678901234567890" (ASCII),
// T=59s → counter=1, SHA1 → 8-digit 94287082 → 6-digit 287082.
func TestTOTPKnownAnswer(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	got, err := totpAt(secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("RFC6238 vector mismatch: got %s want 287082", got)
	}
}

func TestTOTPGenerateAndVerify(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	// Current-step code must verify; a clearly wrong one must not.
	counter := currentCounter()
	code, err := totpAt(secret, counter)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTOTP(secret, code) {
		t.Fatal("freshly computed code should verify")
	}
	if VerifyTOTP(secret, "000000") && code == "000000" {
		t.Skip("degenerate code, skip")
	}
	if VerifyTOTP(secret, "999999") && code != "999999" {
		t.Fatal("an arbitrary wrong code should not verify")
	}
}

func TestOTPAuthURL(t *testing.T) {
	u := OTPAuthURL("scaNNer", "alice", "ABCDEFGH")
	if u == "" || u[:15] != "otpauth://totp/" {
		t.Fatalf("bad otpauth url: %s", u)
	}
}
