package gssapi

import (
	"encoding/binary"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// SASL security layer bitmasks, RFC 4752 section 3.3.
const (
	saslSecurityNone            byte = 1
	saslSecurityIntegrity       byte = 2
	saslSecurityConfidentiality byte = 4
)

// Client implements ldap.GSSAPIClient interface.
type Client struct {
	*client.Client

	ekey     types.EncryptionKey
	Subkey   types.EncryptionKey
	secLayer *saslSecurityLayer
}

// saslSecurityLayer implements the SASL "integrity" security layer
// (GSS_Wrap with conf_flag FALSE) on top of the established Kerberos
// context. Servers like Samba AD with "ldap server require strong auth =
// yes" reject GSSAPI binds that select no security layer with LDAP result
// 8: SASL:[GSSAPI]: Sign or Seal are required.
//
// gokrb5 wrap tokens only support signing (no encryption), so only the
// integrity layer is available, equivalent to ldapsearch -O maxssf=1.
//
// Wrap is only called from the connection writer goroutine and Unwrap only
// from the reader goroutine, so no locking is needed.
type saslSecurityLayer struct {
	ekey       types.EncryptionKey // AP exchange session key
	subkey     types.EncryptionKey // acceptor subkey, may be empty
	tokenFlags byte                // flags for our initiator tokens
	sendSeq    uint64              // next initiator wrap token sequence number
	maxSend    int                 // max plaintext bytes per wrap token
}

// MaxPlaintext returns the maximum plaintext chunk size so that wrapped
// tokens stay below the server-advertised maximum buffer size.
func (s *saslSecurityLayer) MaxPlaintext() int { return s.maxSend }

// Wrap signs b into an initiator wrap token (RFC 4121, conf_flag FALSE).
func (s *saslSecurityLayer) Wrap(b []byte) ([]byte, error) {
	key := s.sendKey()
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	token := &gssapi.WrapToken{
		Flags:     s.tokenFlags,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: s.sendSeq,
		Payload:   b,
	}
	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}
	s.sendSeq++
	return token.Marshal()
}

// Unwrap verifies an acceptor wrap token and returns its payload.
func (s *saslSecurityLayer) Unwrap(b []byte) ([]byte, error) {
	token := &gssapi.WrapToken{}
	if err := token.Unmarshal(b, true); err != nil {
		return nil, err
	}
	if (token.Flags & 0b10) != 0 {
		return nil, fmt.Errorf("sealed (confidentiality) tokens are not supported")
	}
	key := s.ekey
	if (token.Flags&0b100) != 0 && len(s.subkey.KeyValue) != 0 {
		key = s.subkey
	}
	if _, err := token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, err
	}
	return token.Payload, nil
}

func (s *saslSecurityLayer) sendKey() types.EncryptionKey {
	if (s.tokenFlags&0b100) != 0 && len(s.subkey.KeyValue) != 0 {
		return s.subkey
	}
	return s.ekey
}

// SecurityLayer returns the negotiated SASL security layer, or nil when the
// bind selected no layer. The ldap package type-asserts the result against
// its SASLWrapper interface to install connection wrapping after the bind.
func (client *Client) SecurityLayer() any {
	if client.secLayer == nil {
		return nil
	}
	return client.secLayer
}

func copyKey(k types.EncryptionKey) types.EncryptionKey {
	kv := make([]byte, len(k.KeyValue))
	copy(kv, k.KeyValue)
	return types.EncryptionKey{KeyType: k.KeyType, KeyValue: kv}
}

// NewClientWithKeytab creates a new client from a keytab credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithKeytab(username, realm, keytabPath, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	keytab, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, err
	}

	client := client.NewWithKeytab(username, realm, keytab, krb5conf, settings...)

	return &Client{
		Client: client,
	}, nil
}

// NewClientWithPassword creates a new client from a password credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithPassword(username, realm, password string, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	client := client.NewWithPassword(username, realm, password, krb5conf, settings...)

	return &Client{
		Client: client,
	}, nil
}

// NewClientFromCCache creates a new client from a populated client cache.
func NewClientFromCCache(ccachePath, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, err
	}

	client, err := client.NewFromCCache(ccache, krb5conf, settings...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: client,
	}, nil
}

// Close deletes any established secure context and closes the client.
func (client *Client) Close() error {
	client.Client.Destroy()
	return nil
}

// DeleteSecContext destroys any established secure context.
func (client *Client) DeleteSecContext() error {
	client.ekey = types.EncryptionKey{}
	client.Subkey = types.EncryptionKey{}
	return nil
}

// InitSecContext initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (client *Client) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	return client.InitSecContextWithOptions(target, input, []int{})
}

// InitSecContextWithOptions initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (client *Client) InitSecContextWithOptions(target string, input []byte, APOptions []int) ([]byte, bool, error) {
	gssapiFlags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}

	// Ensure mutual-required AP-Option is set when mutual GSSAPI flag is requested
	APOptions = append(APOptions, flags.APOptionMutualRequired)

	switch input {
	case nil:
		tkt, ekey, err := client.Client.GetServiceTicket(target)
		if err != nil {
			return nil, false, err
		}
		client.ekey = ekey

		token, err := spnego.NewKRB5TokenAPREQ(client.Client, tkt, ekey, gssapiFlags, APOptions)
		if err != nil {
			return nil, false, err
		}

		output, err := token.Marshal()
		if err != nil {
			return nil, false, err
		}

		return output, true, nil

	default:
		var token spnego.KRB5Token

		err := token.Unmarshal(input)
		if err != nil {
			return nil, false, err
		}

		var completed bool

		if token.IsAPRep() {
			completed = true

			encpart, err := crypto.DecryptEncPart(token.APRep.EncPart, client.ekey, keyusage.AP_REP_ENCPART)
			if err != nil {
				return nil, false, err
			}

			part := &messages.EncAPRepPart{}

			if err = part.Unmarshal(encpart); err != nil {
				return nil, false, err
			}
			client.Subkey = part.Subkey
		}

		if token.IsKRBError() {
			return nil, !false, token.KRBError
		}

		return make([]byte, 0), !completed, nil
	}
}

// NegotiateSaslAuth performs the last step of the SASL handshake.
// See RFC 4752 section 3.1.
func (client *Client) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	token := &gssapi.WrapToken{}
	err := token.Unmarshal(input, true)
	if err != nil {
		return nil, err
	}

	if (token.Flags & 0b1) == 0 {
		return nil, fmt.Errorf("got a Wrapped token that's not from the server")
	}

	key := client.ekey
	if (token.Flags & 0b100) != 0 {
		key = client.Subkey
	}

	_, err = token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, err
	}

	pl := token.Payload
	if len(pl) != 4 {
		return nil, fmt.Errorf("server send bad final token for SASL GSSAPI Handshake")
	}

	// RFC 4752 section 3.1: the server sends a bitmask of supported
	// security layers and the maximum wrapped buffer size it accepts.
	serverOffer := pl[0]
	serverMaxBuf := binary.BigEndian.Uint32(pl) & 0x00FFFFFF

	var chosen byte
	var ourMaxBuf uint32
	switch {
	case (serverOffer & saslSecurityIntegrity) != 0:
		// Prefer integrity (sign) when the server supports it: servers
		// requiring strong auth (Samba/AD) reject the "none" choice.
		chosen = saslSecurityIntegrity
		ourMaxBuf = 0x00FFFFFF // our Unwrap accepts tokens of any size
		if serverMaxBuf < 256 {
			return nil, fmt.Errorf("server SASL buffer size too small: %d", serverMaxBuf)
		}
		client.secLayer = &saslSecurityLayer{
			ekey:    copyKey(client.ekey),
			subkey:  copyKey(client.Subkey),
			sendSeq: 2, // the final handshake token below uses 1
			// Room for the 16 byte token header and the trailing checksum.
			maxSend: int(serverMaxBuf) - 64,
		}
		if len(client.Subkey.KeyValue) != 0 {
			client.secLayer.tokenFlags = 0b100
		}
	case (serverOffer & saslSecurityNone) != 0:
		chosen = saslSecurityNone
		ourMaxBuf = 0
	default:
		return nil, fmt.Errorf("no supported SASL security layer in server offer 0x%02x (confidentiality is not implemented)", serverOffer)
	}

	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ourMaxBuf)
	b[0] = chosen
	payload := append(b[:], []byte(authzid)...)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	token = &gssapi.WrapToken{
		Flags:     0b100,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 1,
		Payload:   payload,
	}

	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	output, err := token.Marshal()
	if err != nil {
		return nil, err
	}

	return output, nil
}

