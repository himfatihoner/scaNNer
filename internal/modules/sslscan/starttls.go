package sslscan

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// StartTLSMode enumerates the supported plaintext-to-TLS upgrade dances.
// "" and "none" mean "no upgrade — dial TLS directly" (default 443 behaviour).
// "auto" resolves to a per-port default via AutoStartTLS.
//
// Audit: prior to this addition, ScanHost dialled tls.Client on the raw TCP
// port for every configured port. STARTTLS-only services (SMTP, IMAP, POP3,
// LDAP, FTP, Postgres) never negotiated TLS and appeared as "No TLS/SSL
// service detected" — the exact hosts a pentester most needs to audit.
const (
	StartTLSNone     = "none"
	StartTLSAuto     = "auto"
	StartTLSSMTP     = "smtp"
	StartTLSIMAP     = "imap"
	StartTLSPOP3     = "pop3"
	StartTLSFTP      = "ftp"
	StartTLSLDAP     = "ldap"
	StartTLSPostgres = "postgres"
)

// AutoStartTLS picks the STARTTLS protocol based on a well-known port. Returns
// "" (meaning "direct TLS") when the port has no STARTTLS convention.
func AutoStartTLS(port int) string {
	switch port {
	case 25, 587:
		return StartTLSSMTP
	case 143:
		return StartTLSIMAP
	case 110:
		return StartTLSPOP3
	case 21:
		return StartTLSFTP
	case 389:
		return StartTLSLDAP
	case 5432:
		return StartTLSPostgres
	}
	return ""
}

// ResolveStartTLS turns a user-facing selection into a concrete protocol
// name that startTLSUpgrade understands. "" / "none" / "auto" all resolve
// via AutoStartTLS for the specific port; a named protocol passes through.
func ResolveStartTLS(mode string, port int) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	switch m {
	case "", StartTLSNone:
		return ""
	case StartTLSAuto:
		return AutoStartTLS(port)
	}
	return m
}

// startTLSUpgrade runs the plaintext STARTTLS dance on conn and returns nil
// once the server has agreed to upgrade. The caller is responsible for
// wrapping the same net.Conn in tls.Client afterwards.
//
// timeout is applied as an overall read/write deadline on conn. mode is the
// resolved protocol name (never "auto"). host is the server name used in
// EHLO / LDAP StartTLS (not currently sent for LDAP but preserved for logs).
func startTLSUpgrade(ctx context.Context, conn net.Conn, mode, host string, timeout time.Duration) error {
	if mode == "" || mode == StartTLSNone {
		return nil
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("starttls: set deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{})

	switch mode {
	case StartTLSSMTP:
		return starttlsSMTP(conn, host)
	case StartTLSIMAP:
		return starttlsIMAP(conn)
	case StartTLSPOP3:
		return starttlsPOP3(conn)
	case StartTLSFTP:
		return starttlsFTP(conn)
	case StartTLSLDAP:
		return starttlsLDAP(conn)
	case StartTLSPostgres:
		return starttlsPostgres(conn)
	}
	return fmt.Errorf("starttls: unknown mode %q", mode)
}

// --- SMTP ------------------------------------------------------------------
//
// RFC 3207: after banner, EHLO, then STARTTLS. Server multi-line replies use
// "220-foo" for continuation, "220 foo" for last line.
func starttlsSMTP(conn net.Conn, host string) error {
	r := bufio.NewReader(conn)
	if err := readSMTPReply(r, "220"); err != nil {
		return fmt.Errorf("smtp banner: %w", err)
	}
	ehloName := host
	if ehloName == "" || net.ParseIP(ehloName) != nil {
		ehloName = "scanner.local"
	}
	if _, err := fmt.Fprintf(conn, "EHLO %s\r\n", ehloName); err != nil {
		return fmt.Errorf("smtp ehlo: %w", err)
	}
	if err := readSMTPReply(r, "250"); err != nil {
		return fmt.Errorf("smtp ehlo reply: %w", err)
	}
	if _, err := io.WriteString(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}
	if err := readSMTPReply(r, "220"); err != nil {
		return fmt.Errorf("smtp starttls reply: %w", err)
	}
	return nil
}

// readSMTPReply consumes a possibly multi-line SMTP reply and validates the
// leading 3-digit status code. Any 4xx / 5xx is returned as an error.
func readSMTPReply(r *bufio.Reader, wantCode string) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return fmt.Errorf("short reply: %q", line)
		}
		code := line[:3]
		if code != wantCode {
			return fmt.Errorf("unexpected code %q: %s", code, line)
		}
		if len(line) < 4 || line[3] == ' ' {
			return nil
		}
		// line[3] == '-' → continuation line, keep reading
	}
}

// --- IMAP ------------------------------------------------------------------
//
// RFC 3501 / 2595: read "* OK ..." greeting, send tagged "A001 STARTTLS",
// wait for "A001 OK ..." reply (ignoring interleaved untagged responses).
func starttlsIMAP(conn net.Conn) error {
	r := bufio.NewReader(conn)
	greet, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("imap banner: %w", err)
	}
	if !strings.HasPrefix(greet, "* OK") {
		return fmt.Errorf("imap banner: %s", strings.TrimSpace(greet))
	}
	if _, err := io.WriteString(conn, "A001 STARTTLS\r\n"); err != nil {
		return fmt.Errorf("imap starttls: %w", err)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("imap starttls reply: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "A001 ") {
			if strings.HasPrefix(line, "A001 OK") {
				return nil
			}
			return fmt.Errorf("imap starttls refused: %s", line)
		}
		// Untagged response, keep reading
	}
}

// --- POP3 ------------------------------------------------------------------
//
// RFC 2595: read "+OK ..." banner, send "STLS", expect "+OK".
func starttlsPOP3(conn net.Conn) error {
	r := bufio.NewReader(conn)
	greet, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("pop3 banner: %w", err)
	}
	if !strings.HasPrefix(greet, "+OK") {
		return fmt.Errorf("pop3 banner: %s", strings.TrimSpace(greet))
	}
	if _, err := io.WriteString(conn, "STLS\r\n"); err != nil {
		return fmt.Errorf("pop3 stls: %w", err)
	}
	resp, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("pop3 stls reply: %w", err)
	}
	if !strings.HasPrefix(resp, "+OK") {
		return fmt.Errorf("pop3 stls refused: %s", strings.TrimSpace(resp))
	}
	return nil
}

// --- FTP -------------------------------------------------------------------
//
// RFC 4217: read "220 ..." banner, send "AUTH TLS", expect "234".
func starttlsFTP(conn net.Conn) error {
	r := bufio.NewReader(conn)
	if err := readFTPReply(r, "220"); err != nil {
		return fmt.Errorf("ftp banner: %w", err)
	}
	if _, err := io.WriteString(conn, "AUTH TLS\r\n"); err != nil {
		return fmt.Errorf("ftp auth: %w", err)
	}
	if err := readFTPReply(r, "234"); err != nil {
		return fmt.Errorf("ftp auth reply: %w", err)
	}
	return nil
}

// readFTPReply mirrors readSMTPReply: 3-digit code, "-" continuation, " " last.
func readFTPReply(r *bufio.Reader, wantCode string) error {
	return readSMTPReply(r, wantCode)
}

// --- LDAP ------------------------------------------------------------------
//
// RFC 4511 / 4513: send an ExtendedRequest with OID 1.3.6.1.4.1.1466.20037
// as messageID 1, expect ExtendedResponse with resultCode success (0).
//
// The wire format is BER; we hand-encode the minimal request rather than
// pull in a full LDAP library. The response is parsed just enough to find
// the resultCode inside the LDAPResult sequence.
func starttlsLDAP(conn net.Conn) error {
	// Pre-computed BER encoding of:
	//   LDAPMessage ::= SEQUENCE {
	//     messageID   INTEGER (1),
	//     protocolOp  ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
	//       requestName [0] LDAPOID (1.3.6.1.4.1.1466.20037)
	//     }
	//   }
	req := []byte{
		0x30, 0x1d, // SEQUENCE, length 29
		0x02, 0x01, 0x01, // messageID INTEGER 1
		0x77, 0x18, // [APPLICATION 23] ExtendedRequest, length 24
		0x80, 0x16, // [0] LDAPOID, length 22
		'1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1',
		'.', '1', '4', '6', '6', '.', '2', '0', '0', '3', '7',
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("ldap starttls: %w", err)
	}
	// Read LDAPMessage SEQUENCE header.
	r := bufio.NewReader(conn)
	tag, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("ldap reply tag: %w", err)
	}
	if tag != 0x30 {
		return fmt.Errorf("ldap reply not a SEQUENCE (tag=0x%02x)", tag)
	}
	length, err := readBERLength(r)
	if err != nil {
		return fmt.Errorf("ldap reply length: %w", err)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return fmt.Errorf("ldap reply body: %w", err)
	}
	// Skip messageID INTEGER: body[0]=0x02, body[1]=len, body[2..2+len]=value
	if len(body) < 4 || body[0] != 0x02 {
		return fmt.Errorf("ldap reply missing messageID")
	}
	idLen := int(body[1])
	off := 2 + idLen
	if off+2 > len(body) {
		return fmt.Errorf("ldap reply truncated")
	}
	// Expect protocolOp [APPLICATION 24] ExtendedResponse = 0x78
	if body[off] != 0x78 {
		return fmt.Errorf("ldap reply not an ExtendedResponse (tag=0x%02x)", body[off])
	}
	off++
	// Length of the ExtendedResponse.
	if body[off]&0x80 != 0 {
		// long-form length; skip its bytes
		n := int(body[off] & 0x7f)
		off += 1 + n
	} else {
		off++
	}
	// Inside ExtendedResponse the first field is LDAPResult.resultCode ENUMERATED.
	if off+3 > len(body) {
		return fmt.Errorf("ldap reply too short for resultCode")
	}
	if body[off] != 0x0a {
		return fmt.Errorf("ldap reply missing resultCode (tag=0x%02x)", body[off])
	}
	if body[off+1] != 0x01 {
		return fmt.Errorf("ldap reply resultCode length=%d", body[off+1])
	}
	if body[off+2] != 0x00 {
		return fmt.Errorf("ldap starttls refused (resultCode=%d)", body[off+2])
	}
	return nil
}

// readBERLength parses a BER length field (short-form or long-form).
func readBERLength(r *bufio.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if b&0x80 == 0 {
		return int(b), nil
	}
	n := int(b & 0x7f)
	if n == 0 || n > 4 {
		return 0, fmt.Errorf("unsupported BER length octets=%d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	length := 0
	for _, c := range buf {
		length = (length << 8) | int(c)
	}
	return length, nil
}

// --- PostgreSQL ------------------------------------------------------------
//
// libpq SSLRequest: send an 8-byte packet [length=8, code=80877103], read a
// single-byte reply: 'S' = TLS agreed, 'N' = refused, anything else = error.
func starttlsPostgres(conn net.Conn) error {
	pkt := make([]byte, 8)
	binary.BigEndian.PutUint32(pkt[0:4], 8)
	binary.BigEndian.PutUint32(pkt[4:8], 80877103)
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("postgres sslrequest: %w", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("postgres reply: %w", err)
	}
	switch buf[0] {
	case 'S':
		return nil
	case 'N':
		return fmt.Errorf("postgres refused TLS (server replied 'N')")
	default:
		return fmt.Errorf("postgres unexpected reply 0x%02x", buf[0])
	}
}
