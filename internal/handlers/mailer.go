package handlers

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"scanner/internal/models"
)

// sendMail delivers a message using the current SMTP settings. It is called for
// 2FA e-mail codes and the "Test SMTP" button.
//
// Deliberately uses a plain net.Dialer (host routing) rather than the shared
// killswitch-bound dialer: management mail must go out even while scan traffic
// is pinned to a VPN interface that can't reach the mail server.
//
// Settings are read fresh by the caller on every send, so saving new SMTP config
// takes effect immediately — there is no cached client to restart.
func sendMail(s models.AppSettings, to, subject, body string) error {
	if !s.SMTPConfigured() {
		return fmt.Errorf("SMTP is not configured")
	}
	host := s.SMTPHost
	port := s.EffectiveSMTPPort()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	from := s.SMTPFrom

	msg := buildMessage(from, to, subject, body)

	var auth smtp.Auth
	if s.SMTPUser != "" {
		auth = smtp.PlainAuth("", s.SMTPUser, s.SMTPPassword, host)
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}

	switch strings.ToLower(s.SMTPTLSMode) {
	case "ssl": // implicit TLS (usually :465)
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("smtp tls dial: %w", err)
		}
		return sendOverClient(conn, host, auth, from, to, msg)
	default: // "starttls" (default) or "none"
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("smtp dial: %w", err)
		}
		c, err := smtp.NewClient(conn, host)
		if err != nil {
			conn.Close()
			return fmt.Errorf("smtp client: %w", err)
		}
		defer c.Close()
		if strings.ToLower(s.SMTPTLSMode) != "none" {
			if ok, _ := c.Extension("STARTTLS"); ok {
				if err := c.StartTLS(tlsCfg); err != nil {
					return fmt.Errorf("starttls: %w", err)
				}
			} else if s.SMTPTLSMode == "starttls" {
				return fmt.Errorf("server does not offer STARTTLS")
			}
		}
		return finishSend(c, auth, from, to, msg)
	}
}

// sendOverClient wraps an already-TLS connection into an smtp.Client and sends.
func sendOverClient(conn net.Conn, host string, auth smtp.Auth, from, to string, msg []byte) error {
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()
	return finishSend(c, auth, from, to, msg)
}

func finishSend(c *smtp.Client, auth smtp.Auth, from, to string, msg []byte) error {
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return c.Quit()
}

func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	b.WriteString("\r\n")
	return []byte(b.String())
}
