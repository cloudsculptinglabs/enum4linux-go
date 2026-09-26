// Package smb performs native SMB2 enumeration against a target host.
//
// It replaces enum4linux's shell-outs to smbclient/nmblookup with direct
// SMB2 using go-smb2: session setup (including null/guest sessions), share
// enumeration, and per-share read probing.
package smb

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// Session bundles a live SMB2 session with its transport so callers can close both.
type Session struct {
	s    *smb2.Session
	conn net.Conn
}

// Connect establishes an SMB2 session. Empty user and pass attempt a null
// session; "guest" with an empty password attempts a guest session.
func Connect(host, user, pass, domain string, timeout time.Duration) (*Session, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "445"), timeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s:445: %w", host, err)
	}
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{User: user, Password: pass, Domain: domain},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	s, err := d.DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("session setup: %w", err)
	}
	return &Session{s: s, conn: conn}, nil
}

// Close tears down the SMB session and its TCP connection.
func (s *Session) Close() {
	if s.s != nil {
		_ = s.s.Logoff()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// Shares lists the share names visible to this session (via SRVSVC).
func (s *Session) Shares() ([]string, error) {
	return s.s.ListSharenames()
}

// Readable reports whether the root of a share can be listed with this session.
func (s *Session) Readable(share string) bool {
	fs, err := s.s.Mount(share)
	if err != nil {
		return false
	}
	defer fs.Umount()
	_, err = fs.ReadDir(".")
	return err == nil
}
