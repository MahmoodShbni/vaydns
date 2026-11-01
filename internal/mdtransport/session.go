// Session/stream layer: the drop-in replacement for smux + KCP + Noise.
//
// A Session multiplexes many reliable Streams over a single net.PacketConn
// (VayDNS's DNSPacketConn on the client, QueuePacketConn on the server). Each
// Stream is backed by one arq.ARQ (the vendored MasterDnsVPN ARQ engine), which
// provides retransmission, ordering and flow control. Stream exposes a net.Conn
// via an in-process pipe, so existing VayDNS call sites that io.Copy between a
// TCP connection and an smux stream keep working unchanged.
//
// Wire datagram = codec.Encrypt(vpnproto.BuildRaw(packet)). The DNSPacketConn
// underneath performs only DNS framing (base32/labels).
//
// NOTE: The ARQ engine itself is covered by its own (passing) test suite. This
// session/stream orchestration layer is new and has not yet been exercised
// end-to-end; the handshake and stream-lifecycle paths need on-device e2e
// testing (phase 5) before this transport is considered production-ready.
//
// Derived from MasterDnsVPN (MIT) by MasterkinG32. See ATTRIBUTION.md.
package mdtransport

import (
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/net2share/vaydns/internal/mdtransport/arq"
	Enums "github.com/net2share/vaydns/internal/mdtransport/enums"
	"github.com/net2share/vaydns/internal/mdtransport/security"
	"github.com/net2share/vaydns/internal/mdtransport/vpnproto"
)

const readBufferSize = 4096

var (
	ErrSessionClosed  = errors.New("mdtransport: session closed")
	ErrHandshakeFail  = errors.New("mdtransport: session handshake failed")
	ErrListenerClosed = errors.New("mdtransport: listener closed")
)

// Session is one multiplexed connection between a client and server.
type Session struct {
	pconn  net.PacketConn
	remote net.Addr
	codec  *security.Codec
	mtu    int
	arqCfg arq.Config
	logger arq.Logger

	isClient bool

	sessionID uint8
	cookie    uint8

	mu           sync.Mutex
	streams      map[uint16]*Stream
	nextStreamID uint16 // client-side allocator (odd/even not required here)

	txCh      chan []byte
	acceptCh  chan *Stream // server-side inbound streams
	accepted  chan struct{}
	closeOnce sync.Once
	closeCh   chan struct{}
}

func newSession(pconn net.PacketConn, remote net.Addr, codec *security.Codec, cfg SessionConfig, isClient bool) *Session {
	return &Session{
		pconn:        pconn,
		remote:       remote,
		codec:        codec,
		mtu:          cfg.MTU,
		arqCfg:       cfg.arqConfig(isClient),
		logger:       cfg.logger(),
		isClient:     isClient,
		streams:      make(map[uint16]*Stream),
		nextStreamID: 1,
		txCh:         make(chan []byte, 256),
		acceptCh:     make(chan *Stream, 16),
		closeCh:      make(chan struct{}),
	}
}

// writeLoop serializes all outbound datagrams for this session.
func (s *Session) writeLoop() {
	for {
		select {
		case <-s.closeCh:
			return
		case enc := <-s.txCh:
			_, _ = s.pconn.WriteTo(enc, s.remote)
		}
	}
}

// sendPacket builds, encrypts and enqueues one protocol packet.
func (s *Session) sendPacket(opts vpnproto.BuildOptions) bool {
	opts.SessionID = s.sessionID
	opts.SessionCookie = s.cookie
	raw, err := vpnproto.BuildRaw(opts)
	if err != nil {
		return false
	}
	enc, err := s.codec.Encrypt(raw)
	if err != nil {
		return false
	}
	// Copy: codec.Encrypt may reuse internal buffers across calls.
	buf := make([]byte, len(enc))
	copy(buf, enc)
	select {
	case s.txCh <- buf:
		return true
	case <-s.closeCh:
		return false
	}
}

// deliver routes one parsed inbound packet to the session or a stream.
func (s *Session) deliver(pkt vpnproto.Packet) {
	switch pkt.PacketType {
	case Enums.PACKET_SESSION_INIT, Enums.PACKET_SESSION_ACCEPT,
		Enums.PACKET_PING, Enums.PACKET_PONG:
		// Session-level packets are handled by the client/listener handshake
		// code; ping/pong keepalive is not yet wired (phase 5).
		return
	}

	s.mu.Lock()
	st := s.streams[pkt.StreamID]
	s.mu.Unlock()

	if st == nil {
		// A new inbound stream is created only on SYN (server side).
		if !s.isClient && pkt.PacketType == Enums.PACKET_STREAM_SYN {
			st = s.acceptInbound(pkt)
			if st == nil {
				return
			}
		} else {
			// Unknown stream: reset the peer so it can tear down.
			s.sendPacket(vpnproto.BuildOptions{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    pkt.StreamID,
				SequenceNum: pkt.SequenceNum,
			})
			return
		}
	}

	st.routePacket(pkt)
}

// acceptInbound creates the server-side ARQ for a freshly-seen stream, replies
// with SYN_ACK and queues the stream for AcceptStream.
func (s *Session) acceptInbound(syn vpnproto.Packet) *Stream {
	st := s.newStream(syn.StreamID)
	s.mu.Lock()
	if _, exists := s.streams[syn.StreamID]; exists {
		s.mu.Unlock()
		return s.streams[syn.StreamID]
	}
	s.streams[syn.StreamID] = st
	s.mu.Unlock()

	st.start()

	// Acknowledge the SYN so the client's ARQ setup completes.
	ackType, ok := Enums.ControlAckFor(syn.PacketType)
	if !ok {
		ackType = Enums.PACKET_STREAM_SYN_ACK
	}
	st.arqObj.SendControlPacketWithTTL(
		ackType,
		syn.SequenceNum,
		syn.FragmentID,
		syn.TotalFragments,
		nil,
		Enums.DefaultPacketPriority(ackType),
		false,
		nil,
		0,
	)

	select {
	case s.acceptCh <- st:
	case <-s.closeCh:
		return nil
	}
	return st
}

// newStream builds a Stream and its ARQ, wiring the in-process pipe.
func (s *Session) newStream(streamID uint16) *Stream {
	appSide, arqSide := net.Pipe()
	st := &Stream{
		Conn:     appSide,
		sess:     s,
		streamID: streamID,
		arqConn:  arqSide,
	}
	st.arqObj = arq.NewARQ(streamID, s.sessionID, st, arqSide, s.mtu, s.logger, s.arqCfg)
	return st
}

func (s *Session) removeStream(streamID uint16) {
	s.mu.Lock()
	delete(s.streams, streamID)
	s.mu.Unlock()
}

// OpenStream (client) allocates a stream ID and starts its ARQ, which emits the
// SYN during setup.
func (s *Session) OpenStream() (*Stream, error) {
	if !s.isClient {
		return nil, errors.New("mdtransport: OpenStream is client-only")
	}
	select {
	case <-s.closeCh:
		return nil, ErrSessionClosed
	default:
	}

	s.mu.Lock()
	id := s.nextStreamID
	s.nextStreamID++
	st := s.newStream(id)
	s.streams[id] = st
	s.mu.Unlock()

	st.start()
	return st, nil
}

// AcceptStream (server) returns the next inbound stream.
func (s *Session) AcceptStream() (*Stream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-s.closeCh:
		return nil, ErrSessionClosed
	}
}

// Conv returns a stable identifier for this session, for logging. It mirrors
// kcp.UDPSession.GetConv()'s role in the previous transport.
func (s *Session) Conv() uint32 { return uint32(s.sessionID) }

// CloseChan returns a channel closed when the session is torn down, mirroring
// smux.Session.CloseChan() so reconnect logic can detect session death.
func (s *Session) CloseChan() <-chan struct{} { return s.closeCh }

func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
		s.mu.Lock()
		for _, st := range s.streams {
			st.closeInternal()
		}
		s.streams = map[uint16]*Stream{}
		s.mu.Unlock()
	})
	return nil
}

// Stream is one reliable, ordered byte stream (replaces smux.Stream). It embeds
// the application side of an in-process pipe, so it satisfies net.Conn and the
// io.ReadWriteCloser contract VayDNS expects.
type Stream struct {
	net.Conn // application side of the pipe

	sess     *Session
	streamID uint16
	arqConn  net.Conn // ARQ side of the pipe (owned by the ARQ)
	arqObj   *arq.ARQ

	startOnce sync.Once
	closeOnce sync.Once
}

// PushTXPacket implements arq.PacketEnqueuer: the ARQ hands us an outbound
// protocol packet, which we tag with this stream's ID and send via the session.
func (st *Stream) PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, compressionType uint8, ttl time.Duration, payload []byte) bool {
	return st.sess.sendPacket(vpnproto.BuildOptions{
		PacketType:      packetType,
		StreamID:        st.streamID,
		SequenceNum:     sequenceNum,
		FragmentID:      fragmentID,
		TotalFragments:  totalFragments,
		CompressionType: compressionType,
		Payload:         payload,
	})
}

func (st *Stream) start() {
	st.startOnce.Do(func() {
		st.arqObj.Start()
		go func() {
			<-st.arqObj.Done()
			st.sess.removeStream(st.streamID)
			_ = st.Conn.Close()
		}()
	})
}

// routePacket feeds one inbound packet into this stream's ARQ, mirroring the
// MasterDnsVPN client/server dispatch.
func (st *Stream) routePacket(pkt vpnproto.Packet) {
	switch pkt.PacketType {
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		if st.arqObj.IsClosed() {
			st.sess.sendPacket(vpnproto.BuildOptions{PacketType: Enums.PACKET_STREAM_RST, StreamID: st.streamID})
			return
		}
		st.arqObj.ReceiveData(pkt.SequenceNum, pkt.Payload)
	case Enums.PACKET_STREAM_DATA_NACK:
		if !st.arqObj.IsClosed() {
			st.arqObj.HandleDataNack(pkt.SequenceNum)
		}
	case Enums.PACKET_STREAM_CLOSE_READ:
		st.arqObj.MarkCloseReadReceived()
	case Enums.PACKET_STREAM_CLOSE_WRITE:
		st.arqObj.MarkCloseWriteReceived()
	case Enums.PACKET_STREAM_RST:
		st.arqObj.MarkRstReceived()
		st.arqObj.Close("peer reset received", arq.CloseOptions{Force: true})
	default:
		// All ACK / SYN_ACK / control-ack packets.
		st.arqObj.HandleAckPacket(pkt.PacketType, pkt.SequenceNum, pkt.FragmentID)
	}
}

func (st *Stream) closeInternal() {
	st.closeOnce.Do(func() {
		st.arqObj.Close("session closed", arq.CloseOptions{Force: true})
		_ = st.arqConn.Close()
		_ = st.Conn.Close()
	})
}

// Close tears down the stream gracefully.
func (st *Stream) Close() error {
	st.closeOnce.Do(func() {
		st.arqObj.Close("local close", arq.CloseOptions{SendCloseWrite: true, SendCloseRead: true, AfterDrain: true})
		_ = st.Conn.Close()
	})
	return nil
}

// StreamID returns the protocol stream identifier.
func (st *Stream) StreamID() uint16 { return st.streamID }

// ID returns the stream identifier as a uint32, mirroring smux.Stream.ID() for
// logging compatibility.
func (st *Stream) ID() uint32 { return uint32(st.streamID) }

// --- client/server entry points ---

// Dial performs the client handshake over pconn toward remote and returns a
// ready Session.
func Dial(pconn net.PacketConn, remote net.Addr, cfg SessionConfig) (*Session, error) {
	codec, err := security.NewCodec(cfg.EncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, err
	}
	s := newSession(pconn, remote, codec, cfg, true)
	go s.writeLoop()

	accepted := make(chan error, 1)
	go s.clientReadLoop(accepted)

	// Send SESSION_INIT (sessionID 0) with a 4-byte nonce.
	nonce := make([]byte, 4)
	_, _ = rand.Read(nonce)
	s.sendPacket(vpnproto.BuildOptions{PacketType: Enums.PACKET_SESSION_INIT, Payload: nonce})

	select {
	case err := <-accepted:
		if err != nil {
			s.Close()
			return nil, err
		}
		return s, nil
	case <-time.After(handshakeTimeout):
		s.Close()
		return nil, ErrHandshakeFail
	}
}

// clientReadLoop reads from the (client) pconn, completing the handshake on the
// first SESSION_ACCEPT and routing everything else to streams.
func (s *Session) clientReadLoop(accepted chan<- error) {
	handshakeDone := false
	buf := make([]byte, readBufferSize)
	for {
		select {
		case <-s.closeCh:
			return
		default:
		}
		n, _, err := s.pconn.ReadFrom(buf)
		if err != nil {
			if !handshakeDone {
				accepted <- err
			}
			return
		}
		dec, err := s.codec.Decrypt(buf[:n])
		if err != nil {
			continue
		}
		pkt, err := vpnproto.Parse(dec)
		if err != nil {
			continue
		}
		if !handshakeDone && pkt.PacketType == Enums.PACKET_SESSION_ACCEPT {
			if ap, err := vpnproto.DecodeSessionAcceptPayload(pkt.Payload); err == nil {
				s.sessionID = ap.SessionID
				s.cookie = ap.SessionCookie
			} else {
				s.sessionID = pkt.SessionID
			}
			handshakeDone = true
			accepted <- nil
			continue
		}
		s.deliver(pkt)
	}
}

// Listener accepts inbound Sessions over a shared server pconn.
type Listener struct {
	pconn net.PacketConn
	cfg   SessionConfig
	codec *security.Codec

	mu        sync.Mutex
	sessions  map[string]*Session // keyed by remote addr string
	nextSID   uint32
	acceptCh  chan *Session
	closeOnce sync.Once
	closeCh   chan struct{}
}

// Listen wraps a server pconn and begins demultiplexing inbound sessions.
func Listen(pconn net.PacketConn, cfg SessionConfig) (*Listener, error) {
	codec, err := security.NewCodec(cfg.EncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		pconn:    pconn,
		cfg:      cfg,
		codec:    codec,
		sessions: make(map[string]*Session),
		acceptCh: make(chan *Session, 16),
		closeCh:  make(chan struct{}),
	}
	go l.readLoop()
	return l, nil
}

// Accept returns the next newly-established inbound Session.
func (l *Listener) Accept() (*Session, error) {
	select {
	case s := <-l.acceptCh:
		return s, nil
	case <-l.closeCh:
		return nil, ErrListenerClosed
	}
}

func (l *Listener) Close() error {
	l.closeOnce.Do(func() { close(l.closeCh) })
	return nil
}

func (l *Listener) readLoop() {
	buf := make([]byte, readBufferSize)
	for {
		select {
		case <-l.closeCh:
			return
		default:
		}
		n, addr, err := l.pconn.ReadFrom(buf)
		if err != nil {
			return
		}
		dec, err := l.codec.Decrypt(buf[:n])
		if err != nil {
			continue
		}
		pkt, err := vpnproto.Parse(dec)
		if err != nil {
			continue
		}

		key := addr.String()
		l.mu.Lock()
		s := l.sessions[key]
		l.mu.Unlock()

		if s == nil {
			if pkt.PacketType != Enums.PACKET_SESSION_INIT {
				continue
			}
			s = l.newServerSession(addr)
			l.mu.Lock()
			l.sessions[key] = s
			l.mu.Unlock()

			// Reply SESSION_ACCEPT carrying the assigned session id + cookie.
			ap := vpnproto.SessionAcceptPayload{SessionID: s.sessionID, SessionCookie: s.cookie}
			s.sendPacket(vpnproto.BuildOptions{
				PacketType: Enums.PACKET_SESSION_ACCEPT,
				Payload:    vpnproto.EncodeSessionAcceptPayload(ap),
			})

			select {
			case l.acceptCh <- s:
			case <-l.closeCh:
				return
			}
			continue
		}
		s.deliver(pkt)
	}
}

func (l *Listener) newServerSession(addr net.Addr) *Session {
	sid := uint8(atomic.AddUint32(&l.nextSID, 1))
	if sid == 0 {
		sid = uint8(atomic.AddUint32(&l.nextSID, 1))
	}
	cookie := make([]byte, 1)
	_, _ = rand.Read(cookie)

	s := newSession(l.pconn, addr, l.codec, l.cfg, false)
	s.sessionID = sid
	s.cookie = cookie[0]
	go s.writeLoop()
	return s
}
