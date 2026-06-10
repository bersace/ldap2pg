package ldap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SASLWrapper protects and unprotects the byte stream of a connection after
// a SASL bind negotiated a security layer (RFC 4422 section 3.7).
// Implementations sign (and possibly encrypt) outgoing buffers with Wrap and
// verify (and possibly decrypt) incoming buffers with Unwrap.
type SASLWrapper interface {
	Wrap(b []byte) ([]byte, error)
	Unwrap(b []byte) ([]byte, error)
	// MaxPlaintext returns the maximum plaintext size per buffer so that
	// wrapped buffers stay below the server-advertised maximum.
	MaxPlaintext() int
}

// Refuse to allocate more than 16MB for one incoming SASL buffer.
const maxSASLBufferSize = 0x00FFFFFF

// saslConn applies a SASL security layer on a net.Conn. Each Write wraps
// the data into one or more protected buffers, each prefixed with its
// four-octet length in network byte order. Reads decode such buffers and
// return the verified plaintext stream.
type saslConn struct {
	net.Conn
	wrapper  SASLWrapper
	readBuf  bytes.Buffer // decoded plaintext not yet consumed
	maxChunk int
}

func newSASLConn(conn net.Conn, wrapper SASLWrapper) *saslConn {
	maxChunk := wrapper.MaxPlaintext()
	if maxChunk <= 0 {
		maxChunk = 0xFFFF
	}
	return &saslConn{Conn: conn, wrapper: wrapper, maxChunk: maxChunk}
}

func (c *saslConn) Read(b []byte) (int, error) {
	for c.readBuf.Len() == 0 {
		var hdr [4]byte
		if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
			return 0, err
		}
		size := binary.BigEndian.Uint32(hdr[:])
		if size == 0 {
			continue
		}
		if size > maxSASLBufferSize {
			return 0, fmt.Errorf("ldap: SASL buffer of %d bytes exceeds maximum", size)
		}
		token := make([]byte, size)
		if _, err := io.ReadFull(c.Conn, token); err != nil {
			return 0, err
		}
		plaintext, err := c.wrapper.Unwrap(token)
		if err != nil {
			return 0, fmt.Errorf("ldap: SASL unwrap: %w", err)
		}
		c.readBuf.Write(plaintext)
	}
	return c.readBuf.Read(b)
}

func (c *saslConn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n := len(b)
		if n > c.maxChunk {
			n = c.maxChunk
		}
		token, err := c.wrapper.Wrap(b[:n])
		if err != nil {
			return total, fmt.Errorf("ldap: SASL wrap: %w", err)
		}
		out := make([]byte, 4+len(token))
		binary.BigEndian.PutUint32(out, uint32(len(token)))
		copy(out[4:], token)
		if _, err := c.Conn.Write(out); err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}
