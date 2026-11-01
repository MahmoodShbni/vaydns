// Package mdtransport provides a reliable, multiplexed stream transport over
// an unreliable net.PacketConn, using the MasterDnsVPN wire protocol and ARQ
// engine (vendored under internal/mdtransport/{vpnproto,arq,security,...}).
//
// It is a drop-in replacement for the KCP + smux + Noise stack that VayDNS
// previously layered on top of its DNS packet connection:
//
//	before:  DNSPacketConn -> kcp.UDPSession -> Noise -> smux.Session -> Stream
//	after:   DNSPacketConn -> mdtransport.Session ----------------------> Stream
//
// Encryption is handled here by security.Codec (XOR / ChaCha20 / AES-GCM); the
// underlying DNSPacketConn is responsible only for DNS framing (base32/labels),
// exactly as it was under KCP.
//
// Derived from MasterDnsVPN (MIT) by MasterkinG32. See ATTRIBUTION.md.
package mdtransport

import (
	"time"

	"github.com/net2share/vaydns/internal/mdtransport/arq"
)

// SessionConfig configures a client Dial or a server Listen.
type SessionConfig struct {
	// EncryptionMethod selects the security.Codec cipher:
	// 0=none, 1=XOR, 2=ChaCha20, 3=AES-128-GCM, 4=AES-192-GCM, 5=AES-256-GCM.
	EncryptionMethod int
	// EncryptionKey is the raw (pre-derivation) key string shared by both ends.
	EncryptionKey string
	// MTU is the maximum raw payload carried in one DNS exchange, matched to
	// the DNS codec capacity (same value previously passed to kcp.SetMtu).
	MTU int
	// ARQ holds the retransmission/window tuning. Zero value => DefaultARQConfig.
	ARQ arq.Config
	// Logger receives ARQ diagnostics; nil => silent.
	Logger arq.Logger
}

// DefaultARQConfig returns ARQ tuning mirroring MasterDnsVPN's client defaults.
// isClient selects client vs. server role flags.
func DefaultARQConfig(isClient bool) arq.Config {
	return arq.Config{
		WindowSize:                  600,
		RTO:                         0.5,
		MaxRTO:                      3.0,
		EnableControlReliability:    true,
		ControlRTO:                  0.5,
		ControlMaxRTO:               2.0,
		ControlMaxRetries:           400,
		InactivityTimeout:           1800.0,
		DataPacketTTL:               2400.0,
		MaxDataRetries:              1200,
		ControlPacketTTL:            1200.0,
		DataNackMaxGap:              16,
		DataNackInitialDelaySeconds: 0.1,
		DataNackRepeatSeconds:       1.0,
		TerminalDrainTimeout:        120.0,
		TerminalAckWaitTimeout:      90.0,
		CompressionType:             0,
		IsClient:                    isClient,
		InboundQueueSize:            1024,
	}
}

func (c SessionConfig) arqConfig(isClient bool) arq.Config {
	cfg := c.ARQ
	if cfg.WindowSize == 0 {
		cfg = DefaultARQConfig(isClient)
	}
	cfg.IsClient = isClient
	return cfg
}

func (c SessionConfig) logger() arq.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return &arq.DummyLogger{}
}

// handshakeTimeout bounds the SESSION_INIT/SESSION_ACCEPT exchange.
const handshakeTimeout = 15 * time.Second
