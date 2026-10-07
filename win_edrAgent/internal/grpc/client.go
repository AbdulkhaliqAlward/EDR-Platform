// Package grpcclient provides gRPC client for Connection Manager communication.
package grpcclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/edr-platform/win-agent/internal/command"
	"github.com/edr-platform/win-agent/internal/config"
	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/logging"
	pb "github.com/edr-platform/win-agent/internal/pb"
)

// stringifyCommandType maps proto numeric enum values to stable string names.
// This stays compatible before/after regenerating edr.pb.go from edr.proto.
func stringifyCommandType(t pb.CommandType) string {
	switch int32(t) {
	case 0:
		return "COMMAND_TYPE_UNSPECIFIED"
	case 1:
		return "COMMAND_TYPE_UPDATE_CONFIG"
	case 2:
		return "COMMAND_TYPE_COLLECT_FORENSICS"
	case 3:
		return "COMMAND_TYPE_ISOLATE"
	case 4:
		return "COMMAND_TYPE_UNISOLATE"
	case 5:
		return "COMMAND_TYPE_RESTART_SERVICE"
	case 6:
		return "COMMAND_TYPE_UPDATE_AGENT"
	case 7:
		return "COMMAND_TYPE_TERMINATE_PROCESS"
	case 8:
		return "COMMAND_TYPE_ADJUST_RATE"
	case 9:
		return "COMMAND_TYPE_RUN_CMD"
	case 10:
		return "COMMAND_TYPE_RESTART"
	case 11:
		return "COMMAND_TYPE_SHUTDOWN"
	case 12:
		return "COMMAND_TYPE_UPDATE_FILTER_POLICY"
	case 13:
		return "COMMAND_TYPE_QUARANTINE_FILE"
	case 14:
		return "COMMAND_TYPE_BLOCK_IP"
	case 15:
		return "COMMAND_TYPE_UNBLOCK_IP"
	case 16:
		return "COMMAND_TYPE_BLOCK_DOMAIN"
	case 17:
		return "COMMAND_TYPE_UNBLOCK_DOMAIN"
	case 18:
		return "COMMAND_TYPE_UPDATE_SIGNATURES"
	case 19:
		return "COMMAND_TYPE_RESTORE_QUARANTINE_FILE"
	case 20:
		return "COMMAND_TYPE_DELETE_QUARANTINE_FILE"
	case 21:
		return "COMMAND_TYPE_UNINSTALL_AGENT"
	case 22:
		return "COMMAND_TYPE_POST_ISOLATION_TRIAGE"
	case 23:
		return "COMMAND_TYPE_PROCESS_TREE_SNAPSHOT"
	case 24:
		return "COMMAND_TYPE_PERSISTENCE_SCAN"
	case 25:
		return "COMMAND_TYPE_LSASS_ACCESS_AUDIT"
	case 26:
		return "COMMAND_TYPE_FILESYSTEM_TIMELINE"
	case 27:
		return "COMMAND_TYPE_NETWORK_LAST_SEEN"
	case 28:
		return "COMMAND_TYPE_AGENT_INTEGRITY_CHECK"
	default:
		return fmt.Sprintf("COMMAND_UNKNOWN_%d", int32(t))
	}
}

// Client handles gRPC communication with Connection Manager.
type Client struct {
	cfg    *config.Config
	logger *logging.Logger

	conn          *grpc.ClientConn
	serviceClient EventIngestionServiceClient
	mu            sync.RWMutex

	// Long-lived bidirectional stream for events + commands
	stream   EventIngestionService_StreamEventsClient
	streamMu sync.Mutex

	// sendMu serialises Send on the shared stream: gRPC forbids concurrent
	// SendMsg calls on one stream, and the batcher, the disk-queue processor
	// and RunSender all send.
	sendMu sync.Mutex

	// acks tracks sent batches until the server acknowledges durable
	// acceptance (ack_batch_id). Unconfirmed batches are retried from disk.
	acks *ackTracker

	// State
	connected    atomic.Bool
	reconnecting atomic.Bool
	lastError    error

	// Channels
	batchChan   chan *EventBatch
	commandChan chan *Command
	doneChan    chan struct{}

	// Metrics
	batchesSent   atomic.Uint64
	batchesFailed atomic.Uint64
	bytesTotal    atomic.Uint64

	// Re-enrollment signal: closed once when the server rejects with Unauthenticated
	reEnrollCh   chan struct{}
	reEnrollOnce sync.Once
}

// Command represents a command received from server.
type Command struct {
	ID         string
	Type       string
	Parameters map[string]string
	Priority   int
	ExpiresAt  time.Time
}

// NewClient creates a new gRPC client.
func NewClient(cfg *config.Config, logger *logging.Logger) *Client {
	return &Client{
		cfg:         cfg,
		logger:      logger,
		batchChan:   make(chan *EventBatch, 100),
		commandChan: make(chan *Command, 50),
		doneChan:    make(chan struct{}),
		reEnrollCh:  make(chan struct{}),
		acks:        newAckTracker(maxPendingAcks),
	}
}

// ReEnrollSignal returns a channel that is closed when the server rejects
// this agent with Unauthenticated, indicating the agent must wipe its
// local state and re-enroll to obtain a new identity.
func (c *Client) ReEnrollSignal() <-chan struct{} {
	return c.reEnrollCh
}

// Connect establishes connection to Connection Manager.
//
// FIX — Split-Brain (hostname-first dialing):
// The agent config MUST store a DNS hostname (e.g. "edr-c2.local:50051"), NOT a
// bare IP. When grpc.Dial receives a hostname, Go's internal DNS resolver
// re-resolves it on every reconnection attempt, so the gRPC transport always
// dials whatever IP the hostname currently maps to — the same IP that
// isolateNetwork() whitelists via net.LookupHost. This eliminates the
// Split-Brain where the firewall allows 129.1 but gRPC dials the stale 152.1.
//
// The fallback gateway-IP candidates are kept for the initial bootstrap phase
// (before the agent enrolls and writes a hostname to config), but once a
// hostname is in config it will always be tried first.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// ── ZOMBIE-STATE FIX ──────────────────────────────────────────────────────
	// Problem: after a docker-compose restart or server-side connection drop,
	// c.conn is non-nil but the underlying transport is in TransientFailure or
	// Shutdown state. The old guard `if c.conn != nil { return nil }` caused
	// Connect() to silently return without re-dialing, making RunReconnector
	// loop forever without actually fixing the connection.
	//
	// Fix: check the REAL transport state. If the conn exists but is no longer
	// Ready or Connecting, close it and re-dial.
	if c.conn != nil {
		state := c.conn.GetState()
		if state == connectivity.Ready || state == connectivity.Connecting {
			return nil // Genuinely healthy — nothing to do
		}
		// Stale / dead connection — close it before re-dialing.
		c.logger.Infof("Closing stale gRPC connection (state=%s) before re-dial", state)
		_ = c.conn.Close()
		c.conn = nil
		c.serviceClient = nil
		c.connected.Store(false)
		c.clearStream()
	}
	// ──────────────────────────────────────────────────────────────────────────

	var transportCreds credentials.TransportCredentials
	if c.cfg.Server.Insecure {
		transportCreds = insecure.NewCredentials()
		c.logger.Warn("Using PLAINTEXT gRPC (no TLS) — for debugging only")
	} else {
		tlsConfig, err := c.loadTLSConfig()
		if err != nil {
			c.lastError = err
			return fmt.Errorf("failed to load TLS config: %w", err)
		}
		transportCreds = credentials.NewTLS(tlsConfig)
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	// Build candidate addresses: hostname FIRST (DNS-based), then gateway fallbacks.
	// Keeping the hostname raw (not pre-resolved to IP) is the critical change:
	// grpc.Dial will call os.LookupHost internally on every reconnect attempt,
	// so it always dials the current IP — matching whatever the firewall allows.
	candidates := c.buildDialCandidates()

	var lastErr error
	for _, addr := range candidates {
		c.logger.Infof("Trying server address: %s (insecure=%v)", addr, c.cfg.Server.Insecure)

		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := grpc.DialContext(dialCtx, addr, append(opts, grpc.WithBlock())...)
		cancel()

		if err != nil {
			c.logger.Warnf("Failed to connect to %s: %v", addr, err)
			lastErr = err
			continue
		}

		c.conn = conn
		c.serviceClient = NewEventIngestionServiceClient(conn)
		// Do NOT call c.connected.Store(true) here — IsConnected() reads the
		// transport state directly from conn.GetState() now, so this flag is
		// only kept for backward compat with RunReconnector's loop condition.
		c.connected.Store(true)
		c.logger.Infof("Connected to server at %s", addr)

		// If we succeeded on a fallback address, persist it so future
		// reconnections start from the right place.
		if addr != c.cfg.Server.Address {
			c.logger.Infof("Updating server address from %s → %s", c.cfg.Server.Address, addr)
			c.cfg.Server.Address = addr
		}
		return nil
	}

	c.lastError = lastErr
	return fmt.Errorf("all addresses failed, last error: %w", lastErr)
}

// buildDialCandidates returns ordered dial targets for Connect().
//
// DESIGN — hostname-first to prevent Split-Brain:
// The primary address from config MUST be a DNS hostname (e.g. "edr-c2.local:50051").
// It is passed verbatim to grpc.Dial — we do NOT pre-resolve it to an IP here.
// This means Go's gRPC resolver calls net.LookupHost on every dial attempt,
// so it always dials whichever IP the hostname currently resolves to.
//
// isolateNetwork() calls net.LookupHost for the same hostname to build
// the firewall ALLOW rule → both use the same DNS record → same IP →
// no more Split-Brain.
//
// Gateway-IP fallbacks are appended for bootstrap resilience (before enrollment)
// but will NOT be tried if the hostname dial succeeds.
func (c *Client) buildDialCandidates() []string {
	primary := c.cfg.Server.Address
	_, port, err := net.SplitHostPort(primary)
	if err != nil {
		port = "50051"
	}

	// primary goes first — must be a hostname for DNS-based resolution.
	candidates := []string{primary}
	seen := map[string]bool{primary: true}

	// Gateway-IP fallbacks: useful when the agent has no DNS config yet
	// (e.g. fresh install before /etc/hosts or mDNS is configured).
	for _, gw := range discoverGatewayIPs() {
		addr := net.JoinHostPort(gw, port)
		if !seen[addr] {
			candidates = append(candidates, addr)
			seen[addr] = true
		}
	}

	// Localhost as last resort (single-machine dev/test setups).
	for _, host := range []string{"localhost", "127.0.0.1"} {
		addr := net.JoinHostPort(host, port)
		if !seen[addr] {
			candidates = append(candidates, addr)
			seen[addr] = true
		}
	}

	c.logger.Debugf("Dial candidates: %v", candidates)
	return candidates
}

// discoverGatewayIPs returns likely gateway IPs by inspecting network
// interfaces. The gateway is typically the .1 address of each non-loopback,
// non-link-local IPv4 subnet the agent is connected to.
func discoverGatewayIPs() []string {
	var gateways []string

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range ifaces {
		// Skip down, loopback, and virtual interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// Skip common virtual adapter names
		name := strings.ToLower(iface.Name)
		if strings.Contains(name, "loopback") || strings.Contains(name, "pseudo") {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			// Compute .1 of the subnet (typical gateway)
			gw := make(net.IP, len(ip))
			for i := range ip {
				gw[i] = ip[i] & ipNet.Mask[i]
			}
			gw[3] |= 1         // .1
			if !gw.Equal(ip) { // Don't add our own IP
				gateways = append(gateways, gw.String())
			}
		}
	}

	return gateways
}

// loadTLSConfig loads mTLS configuration.
// Prefers inline PEM data from Registry (zero disk footprint).
// Falls back to file paths for backward compatibility.
func (c *Client) loadTLSConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	// Load client certificate: prefer in-memory PEM from Registry
	if len(c.cfg.Certs.CertPEM) > 0 && len(c.cfg.Certs.KeyPEM) > 0 {
		cert, err = tls.X509KeyPair(c.cfg.Certs.CertPEM, c.cfg.Certs.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse client cert from Registry PEM: %w", err)
		}
	} else {
		cert, err = tls.LoadX509KeyPair(c.cfg.Certs.CertPath, c.cfg.Certs.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
	}

	// Load CA certificate: prefer in-memory PEM from Registry
	var caCert []byte
	if len(c.cfg.Certs.CACertPEM) > 0 {
		caCert = c.cfg.Certs.CACertPEM
	} else {
		caCert, err = os.ReadFile(c.cfg.Certs.CAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Build mTLS config with client cert + CA chain.
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// ServerName override: resolves SAN mismatch when the agent connects to a
	// custom deployment domain (e.g. "edr.internal", a bare IP injected via
	// hosts file) but the server certificate's SANs list only the internal
	// service name (e.g. "edr-connection-manager", "localhost").
	// Setting ServerName tells the TLS layer which name to validate against,
	// independent of the hostname used for the TCP connection.
	if c.cfg.Server.TLSServerName != "" {
		tlsCfg.ServerName = c.cfg.Server.TLSServerName
		c.logger.Infof("mTLS dialer: ServerName override → %q (dialing %s)",
			c.cfg.Server.TLSServerName, c.cfg.Server.Address)
	}

	return tlsCfg, nil
}

// Disconnect closes the connection and clears the active stream.
func (c *Client) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.clearStream()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.serviceClient = nil
		c.connected.Store(false)
		return err
	}
	return nil
}

// IsConnected returns the TRUE transport-layer connectivity state.
//
// FIX — Blind Watchdog (connectivity.Ready check):
// The previous implementation returned a stale atomic bool (c.connected) that
// was only updated at dial/disconnect time. The gRPC transport can transition
// to Idle, Connecting, or TransientFailure without us setting that bool, which
// caused the Watchdog to print "gRPC healthy ✓" even while the stream was
// reporting rpc error: code = Unavailable.
//
// The fix: read conn.GetState() directly from the ClientConn. This reflects the
// real underlying transport state maintained by the gRPC library:
//
//	connectivity.Ready          → transport is up, RPCs will succeed
//	connectivity.Idle           → no active RPCs; keepalive may wake it
//	connectivity.Connecting     → handshake in progress
//	connectivity.TransientFailure → last connect attempt failed, retrying
//	connectivity.Shutdown       → conn was closed
//
// Only connectivity.Ready means the Watchdog should consider the channel healthy.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return false
	}
	return conn.GetState() == connectivity.Ready
}

// SendBatch queues a proto EventBatch for sending (asynchronous).
func (c *Client) SendBatch(batch *EventBatch) error {
	if !c.connected.Load() {
		return fmt.Errorf("not connected")
	}

	select {
	case c.batchChan <- batch:
		return nil
	default:
		return fmt.Errorf("send queue full")
	}
}

// ackTimeout bounds how long a sent batch may wait for the server's
// acknowledgement before it is treated as undelivered and retried from disk.
const ackTimeout = 30 * time.Second

// maxPendingAcks bounds the in-flight confirmation window (memory held for
// batches awaiting acknowledgement). When full, new batches go to disk.
const maxPendingAcks = 256

// IsNotAcknowledged reports whether err means the server was reached but did
// not confirm the batch (as opposed to a connectivity failure).
func IsNotAcknowledged(err error) bool {
	return errors.Is(err, errNotAcknowledged)
}

// currentStream returns the long-lived stream, or nil.
func (c *Client) currentStream() EventIngestionService_StreamEventsClient {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	return c.stream
}

// sendOnStream serialises Send on the shared long-lived stream.
func (c *Client) sendOnStream(stream EventIngestionService_StreamEventsClient, batch *EventBatch) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return stream.Send(batch)
}

// SendBatchTracked sends a batch and returns as soon as it is written to the
// stream; delivery is confirmed asynchronously. If the server does not
// acknowledge it within ackTimeout, or the stream breaks first,
// onUnconfirmed receives the batch so the caller can persist it for retry.
// An error means the batch was not sent (caller persists it immediately).
func (c *Client) SendBatchTracked(ctx context.Context, batch *EventBatch, onUnconfirmed func(*EventBatch)) error {
	if stream := c.currentStream(); stream != nil {
		id := batch.GetBatchId()
		if err := c.acks.register(id, &pendingAck{batch: batch, deadline: time.Now().Add(ackTimeout), onUnconfirmed: onUnconfirmed}); err != nil {
			return err
		}
		if err := c.sendOnStream(stream, batch); err != nil {
			c.acks.cancel(id)
			c.clearStream()
			return fmt.Errorf("stream send failed: %w", err)
		}
		return nil
	}
	return c.sendShortLivedConfirmed(ctx, batch)
}

// SendBatchSync sends a batch and waits until the server acknowledges it.
// It returns nil only when the batch is confirmed durably accepted, so the
// disk-queue processor deletes a file only after confirmation.
func (c *Client) SendBatchSync(ctx context.Context, batch *EventBatch) error {
	if stream := c.currentStream(); stream != nil {
		id := batch.GetBatchId()
		done := make(chan error, 1)
		if err := c.acks.register(id, &pendingAck{batch: batch, deadline: time.Now().Add(ackTimeout), done: done}); err != nil {
			return err
		}
		if err := c.sendOnStream(stream, batch); err != nil {
			c.acks.cancel(id)
			c.clearStream()
			return fmt.Errorf("stream send failed: %w", err)
		}
		timer := time.NewTimer(ackTimeout + 5*time.Second) // backstop if the sweeper is not running
		defer timer.Stop()
		select {
		case err := <-done:
			return err // nil = acknowledged
		case <-timer.C:
			c.acks.cancel(id)
			return errNotAcknowledged
		case <-ctx.Done():
			c.acks.cancel(id)
			return ctx.Err()
		}
	}
	return c.sendShortLivedConfirmed(ctx, batch)
}

// sendShortLivedConfirmed sends one batch on a short-lived stream (used while
// RunStream has not yet established the long-lived one) and succeeds only
// if the server's response acknowledges this batch.
func (c *Client) sendShortLivedConfirmed(ctx context.Context, batch *EventBatch) error {
	c.mu.RLock()
	sc := c.serviceClient
	c.mu.RUnlock()
	if sc == nil {
		return fmt.Errorf("not connected")
	}

	// Bounded so the caller is never blocked indefinitely by a hung call.
	sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	shortStream, err := sc.StreamEvents(sendCtx)
	if err != nil {
		return fmt.Errorf("failed to open short-lived stream: %w", err)
	}
	if err := shortStream.Send(batch); err != nil {
		return fmt.Errorf("short-lived stream send failed: %w", err)
	}
	if err := shortStream.CloseSend(); err != nil {
		return fmt.Errorf("short-lived stream close failed: %w", err)
	}
	acked := false
	for {
		resp, err := shortStream.Recv()
		if err != nil {
			break // io.EOF after the server's response, or a stream error
		}
		if resp == nil {
			continue
		}
		if resp.GetAckBatchId() == batch.GetBatchId() {
			acked = true
		}
		c.forwardCommands(resp)
	}
	if !acked {
		return errNotAcknowledged
	}
	return nil
}

// forwardCommands delivers the commands in a server response to commandChan.
func (c *Client) forwardCommands(resp *CommandBatch) {
	for _, cmd := range resp.Commands {
		if cmd == nil {
			continue
		}
		select {
		case c.commandChan <- &Command{
			ID:         cmd.GetCommandId(),
			Type:       stringifyCommandType(cmd.GetType()),
			Parameters: cmd.GetParameters(),
			Priority:   int(cmd.GetPriority()),
			ExpiresAt:  commandExpiresAt(cmd),
		}:
		default:
			c.logger.Warn("Command channel full, dropping command")
		}
	}
}

// FlushUnconfirmed hands every batch still awaiting acknowledgement to its
// unconfirmed handler (the disk queue). Call on shutdown so in-flight
// batches survive a restart.
func (c *Client) FlushUnconfirmed() {
	c.acks.failAll()
}

// runAckSweeper periodically fails batches whose acknowledgement deadline
// passed, so they are retried from the disk queue.
func (c *Client) runAckSweeper(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			c.acks.expire(now)
		}
	}
}

// SendCommandResult sends the command execution result to the server (C2 feedback).
func (c *Client) SendCommandResult(ctx context.Context, res *command.Result, agentID string) error {
	if res == nil {
		return nil
	}
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		c.logger.Warnf("SendCommandResult skipped: not connected")
		return fmt.Errorf("not connected")
	}
	req := pb.NewCommandResultProto(
		res.CommandID,
		agentID,
		res.Status,
		res.Output,
		res.Error,
		res.Duration,
		res.Timestamp,
	)
	out := &emptypb.Empty{}
	err := conn.Invoke(ctx, pb.EventIngestionService_SendCommandResult_FullMethodName, req, out)
	if err != nil {
		c.logger.Warnf("SendCommandResult failed: %v", err)
		return err
	}
	c.logger.Debugf("Command result sent: id=%s status=%s", res.CommandID, res.Status)
	return nil
}

// SendHeartbeat sends a heartbeat to the server via unary Heartbeat RPC.
// This converts the local HeartbeatRequest struct to the proto HeartbeatRequest
// message and invokes the Heartbeat RPC.
func (c *Client) SendHeartbeat(req *HeartbeatRequest) (*HeartbeatResponse, error) {
	c.mu.RLock()
	sc := c.serviceClient
	conn := c.conn
	c.mu.RUnlock()

	if sc == nil || conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Map local status to proto enum
	var protoStatus pb.AgentStatus
	switch req.Status {
	case StatusHealthy:
		protoStatus = pb.AgentStatus_AGENT_STATUS_HEALTHY
	case StatusDegraded:
		protoStatus = pb.AgentStatus_AGENT_STATUS_DEGRADED
	case StatusCritical:
		protoStatus = pb.AgentStatus_AGENT_STATUS_CRITICAL
	case StatusUpdating:
		protoStatus = pb.AgentStatus_AGENT_STATUS_UPDATING
	case StatusIsolated:
		protoStatus = pb.AgentStatus_AGENT_STATUS_ISOLATED
	default:
		protoStatus = pb.AgentStatus_AGENT_STATUS_UNKNOWN
	}

	// Build proto HeartbeatRequest with ALL fields
	protoReq := &pb.HeartbeatRequest{
		AgentId:         req.AgentID,
		Timestamp:       timestamppb.New(req.Timestamp),
		Status:          protoStatus,
		CpuUsage:        float32(req.CPUUsage),
		MemoryUsedMb:    int64(req.MemoryUsedMB),
		MemoryTotalMb:   int64(req.MemoryTotalMB),
		DiskTotalMb:     int64(req.CPUCount), // Repurpose unused field for CPU count
		EventsGenerated: int64(req.EventsGenerated),
		EventsSent:      int64(req.EventsSent),
		QueueDepth:      int32(req.QueueDepth),
		EventsDropped:   int64(req.EventsDropped),
		IpAddresses:     req.IPAddresses,
		AgentVersion:    req.Version,
		CertExpiresAt:   req.CertExpiresAt,
		SysmonInstalled: req.SysmonInstalled,
		SysmonRunning:   req.SysmonRunning,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attach supplemental context as gRPC metadata (avoids proto schema changes).
	// The server reads these headers to update the agent's tags in the DB.
	if req.Profile != "" || req.LoggedInUser != "" || req.SignatureServerVersion >= 0 {
		md := metadata.Pairs()
		if req.Profile != "" {
			md.Append("x-agent-profile", req.Profile)
		}
		if req.LoggedInUser != "" {
			md.Append("x-agent-logged-in-user", req.LoggedInUser)
		}
		md.Append("x-agent-signature-server-version", strconv.FormatInt(req.SignatureServerVersion, 10))
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	protoResp, err := sc.Heartbeat(ctx, protoReq)
	if err != nil {
		return nil, fmt.Errorf("heartbeat RPC failed: %w", err)
	}

	resp := &HeartbeatResponse{
		ServerStatus:          protoResp.GetServerStatus().String(),
		HasPendingCommands:    protoResp.GetHasPendingCommands(),
		CertRenewalRequired:   protoResp.GetCertRenewalRequired(),
		ConfigUpdateAvailable: protoResp.GetConfigUpdateAvailable(),
		NewConfig:             protoResp.GetNewConfig(),
		RecommendedBatchSize:  int(protoResp.GetRecommendedBatchSize()),
		RecommendedIntervalMs: int(protoResp.GetRecommendedIntervalMs()),
	}
	if protoResp.GetServerTimestamp() != nil {
		resp.AckTimestamp = protoResp.GetServerTimestamp().AsTime()
	}

	return resp, nil
}

// Commands returns channel for receiving commands.
func (c *Client) Commands() <-chan *Command {
	return c.commandChan
}

// RunSender starts the batch sending loop.
func (c *Client) RunSender(ctx context.Context) {
	c.logger.Debug("gRPC sender started")

	for {
		select {
		case <-ctx.Done():
			c.logger.Debug("gRPC sender stopped")
			return

		case batch := <-c.batchChan:
			if err := c.sendBatchInternal(ctx, batch); err != nil {
				c.logger.Errorf("Failed to send batch: %v", err)
				c.batchesFailed.Add(1)
			} else {
				c.batchesSent.Add(1)
				c.bytesTotal.Add(uint64(len(batch.Payload)))
			}
		}
	}
}

// sendBatchInternal sends a proto EventBatch to the server via the long-lived stream when set,
// otherwise opens a short-lived stream for this batch.
func (c *Client) sendBatchInternal(ctx context.Context, batch *EventBatch) error {
	if !c.connected.Load() {
		return fmt.Errorf("not connected")
	}

	c.streamMu.Lock()
	stream := c.stream
	c.streamMu.Unlock()

	if stream != nil {
		if err := c.sendOnStream(stream, batch); err != nil {
			c.clearStream()
			return fmt.Errorf("failed to send batch: %w", err)
		}
		c.logger.Debugf("Batch sent: id=%s events=%d size=%d",
			batch.BatchId, batch.EventCount, len(batch.Payload))
		return nil
	}

	// Fallback: short-lived stream when RunStream has not established one yet
	c.mu.RLock()
	sc := c.serviceClient
	c.mu.RUnlock()
	if sc == nil {
		return fmt.Errorf("service client not initialized")
	}
	stream, err := sc.StreamEvents(ctx)
	if err != nil {
		c.connected.Store(false)
		return fmt.Errorf("failed to open stream: %w", err)
	}
	if err := stream.Send(batch); err != nil {
		return fmt.Errorf("failed to send batch: %w", err)
	}
	if err := stream.CloseSend(); err != nil {
		return fmt.Errorf("failed to close send: %w", err)
	}
	resp, _ := stream.Recv()
	if resp != nil && len(resp.Commands) > 0 {
		for _, cmd := range resp.Commands {
			if cmd == nil {
				continue
			}
			select {
			case c.commandChan <- &Command{
				ID:         cmd.GetCommandId(),
				Type:       stringifyCommandType(cmd.GetType()),
				Parameters: cmd.GetParameters(),
				Priority:   int(cmd.GetPriority()),
				ExpiresAt:  commandExpiresAt(cmd),
			}:
			default:
				c.logger.Warn("Command channel full, dropping command")
			}
		}
	}
	c.logger.Debugf("Batch sent: id=%s events=%d size=%d",
		batch.BatchId, batch.EventCount, len(batch.Payload))
	return nil
}

// BuildEventBatchProto builds a proto EventBatch from an internal event.Batch (for StreamClient and tests).
func (c *Client) BuildEventBatchProto(batch *event.Batch) *EventBatch {
	if batch == nil {
		return nil
	}
	comp := CompressionNone
	switch batch.Compression {
	case "snappy":
		comp = CompressionSnappy
	case "gzip":
		comp = CompressionGzip
	}
	return &EventBatch{
		BatchId:     batch.ID,
		AgentId:     batch.AgentID,
		Timestamp:   timestamppb.New(batch.Timestamp),
		Compression: comp,
		Payload:     batch.Payload,
		EventCount:  int32(batch.EventCount),
		Checksum:    batch.Checksum,
		Metadata: map[string]string{
			"timestamp": batch.Timestamp.Format(time.RFC3339),
		},
	}
}

// RunStream establishes a long-lived bidirectional stream, runs a reconnection loop,
// and spawns a goroutine that Recv()s CommandBatch messages and forwards commands to commandChan.
// RunStream returns when ctx is cancelled.
func (c *Client) RunStream(ctx context.Context) {
	c.logger.Debug("gRPC RunStream started")
	go c.runAckSweeper(ctx)

	backoff := c.cfg.Server.ReconnectDelay
	maxBackoff := c.cfg.Server.MaxReconnectDelay
	authBackoff := time.Duration(0)

	for {
		select {
		case <-ctx.Done():
			c.clearStream()
			c.logger.Debug("gRPC RunStream stopped (context)")
			return
		default:
		}

		if !c.connected.Load() {
			time.Sleep(backoff)
			continue
		}

		c.mu.RLock()
		sc := c.serviceClient
		c.mu.RUnlock()
		if sc == nil {
			time.Sleep(backoff)
			continue
		}

		stream, err := sc.StreamEvents(ctx)
		if err != nil {
			// ── Detect server-side rejection for unknown/revoked agents ──
			if st, ok := grpcstatus.FromError(err); ok && st.Code() == codes.Unauthenticated {
				if c.canReEnroll() {
					c.logger.Warnf("Server rejected agent: %s — triggering re-enrollment", st.Message())
					c.reEnrollOnce.Do(func() { close(c.reEnrollCh) })
					return // Stop reconnecting — agent must re-enroll
				}
				if !c.waitAfterAuthRejection(ctx, st.Message(), &authBackoff) {
					return
				}
				continue
			}
			c.logger.Warnf("StreamEvents failed: %v", err)
			backoff = c.nextBackoff(backoff, maxBackoff)
			time.Sleep(backoff)
			continue
		}

		c.streamMu.Lock()
		c.stream = stream
		c.streamMu.Unlock()

		backoff = c.cfg.Server.ReconnectDelay
		c.logger.Info("Bidirectional stream established")

		recvDone := make(chan struct{})
		var recvErr error
		go func() {
			defer close(recvDone)
			recvErr = c.recvLoop(ctx, stream)
		}()

		select {
		case <-ctx.Done():
			c.clearStream()
			<-recvDone
			return
		case <-recvDone:
			c.clearStream()
			// ── Check if recv got Unauthenticated (server rejected unknown/revoked agent) ──
			if recvErr != nil {
				if st, ok := grpcstatus.FromError(recvErr); ok && st.Code() == codes.Unauthenticated {
					if c.canReEnroll() {
						c.logger.Warnf("Server rejected agent (recv): %s — triggering re-enrollment", st.Message())
						c.reEnrollOnce.Do(func() { close(c.reEnrollCh) })
						return // Stop reconnecting — agent must re-enroll
					}
					if !c.waitAfterAuthRejection(ctx, st.Message(), &authBackoff) {
						return
					}
					continue
				}
			}
			authBackoff = 0 // stream was accepted; a later rejection starts the backoff over
			backoff = c.nextBackoff(backoff, maxBackoff)
			c.logger.Debugf("Stream recv ended; reconnecting in %v", backoff)
			time.Sleep(backoff)
		}
	}
}

// canReEnroll reports whether automatic re-enrollment can actually succeed.
// Re-enrollment needs the bootstrap token, which zero-embed builds keep only
// in memory during -install and zero afterwards. Without it, the re-enroll
// path cannot obtain a new identity, so tearing down the stream for it would
// leave the agent unable to receive commands until the service restarts.
func (c *Client) canReEnroll() bool {
	return strings.TrimSpace(c.cfg.Certs.BootstrapToken) != ""
}

// waitAfterAuthRejection handles an Unauthenticated rejection when
// re-enrollment is not possible: it keeps the current identity and waits
// before RunStream retries, backing off from 30s up to 5 minutes so a
// genuinely deleted agent does not hammer the server. Returns false if ctx
// was cancelled while waiting.
func (c *Client) waitAfterAuthRejection(ctx context.Context, reason string, delay *time.Duration) bool {
	const (
		minAuthBackoff = 30 * time.Second
		maxAuthBackoff = 5 * time.Minute
	)
	if *delay < minAuthBackoff {
		*delay = minAuthBackoff
	} else {
		*delay = c.nextBackoff(*delay, maxAuthBackoff)
	}
	c.logger.Warnf("Server rejected agent: %s — no enrollment token on this device, so re-enrollment is not possible; "+
		"keeping current identity and retrying in %v (reinstall with a new token if this agent was deleted on the server)",
		reason, *delay)
	select {
	case <-ctx.Done():
		return false
	case <-time.After(*delay):
		return true
	}
}

// recvLoop continuously calls stream.Recv() and forwards CommandBatch commands to commandChan.
// It returns the error from Recv() so the caller can check for Unauthenticated status.
func (c *Client) recvLoop(ctx context.Context, stream EventIngestionService_StreamEventsClient) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		resp, err := stream.Recv()
		if err != nil {
			c.logger.Warnf("Stream Recv error (stream broken): %v", err)
			return err
		}
		if resp == nil {
			continue
		}
		if id := resp.GetAckBatchId(); id != "" {
			c.acks.ack(id)
		}
		c.forwardCommands(resp)
	}
}

// commandExpiresAt returns the ExpiresAt time from a proto Command, or zero time if unset.
func commandExpiresAt(cmd *pb.Command) time.Time {
	if cmd == nil {
		return time.Time{}
	}
	ts := cmd.GetExpiresAt()
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// clearStream sets stream to nil under streamMu so senders stop using a dead stream.
func (c *Client) clearStream() {
	c.streamMu.Lock()
	c.stream = nil
	c.streamMu.Unlock()
	// Batches sent on the lost stream can never be acknowledged now: hand
	// them back for retry instead of waiting for their deadline.
	if c.acks != nil {
		c.acks.failAll()
	}
}

// nextBackoff returns the next backoff duration (exponential, capped by max).
func (c *Client) nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

// RunReceiver starts the command receiving loop using a persistent gRPC stream.
// Deprecated: use RunStream for a single long-lived bidirectional stream.
func (c *Client) RunReceiver(ctx context.Context) {
	c.RunStream(ctx)
}

// RunReconnector handles automatic reconnection.
//
// ZOMBIE-STATE FIX:
// Previously checked `c.connected.Load()` (an atomic bool set only at dial/
// disconnect time) which is permanently out of sync with the gRPC transport
// state after a silent failure. The fix: use `c.IsConnected()` which reads
// `conn.GetState() == connectivity.Ready` directly from the transport layer.
func (c *Client) RunReconnector(ctx context.Context) {
	c.logger.Debug("Reconnector started")

	delay := c.cfg.Server.ReconnectDelay
	if delay <= 0 {
		delay = time.Second
	}
	maxDelay := c.cfg.Server.MaxReconnectDelay
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}

	for {
		select {
		case <-ctx.Done():
			c.logger.Debug("Reconnector stopped")
			return
		default:
		}

		// Use the REAL transport state, not the stale atomic bool.
		if !c.IsConnected() && !c.reconnecting.Load() {
			c.reconnecting.Store(true)

			c.logger.Infof("[Reconnector] Connection lost — reconnecting in %v...", delay)
			select {
			case <-ctx.Done():
				c.reconnecting.Store(false)
				return
			case <-time.After(delay):
			}

			if err := c.Connect(ctx); err != nil {
				c.logger.Warnf("[Reconnector] Reconnection failed: %v", err)
				// Exponential backoff
				delay = delay * 2
				if delay > maxDelay {
					delay = maxDelay
				}
			} else {
				c.logger.Info("[Reconnector] Reconnection successful")
				delay = c.cfg.Server.ReconnectDelay // Reset delay on success
			}

			c.reconnecting.Store(false)
		}
		time.Sleep(time.Second)
	}
}

// Stats returns client statistics.
func (c *Client) Stats() ClientStats {
	return ClientStats{
		Connected:     c.connected.Load(),
		BatchesSent:   c.batchesSent.Load(),
		BatchesFailed: c.batchesFailed.Load(),
		BytesTotal:    c.bytesTotal.Load(),
	}
}

// ClientStats holds gRPC client statistics.
type ClientStats struct {
	Connected     bool
	BatchesSent   uint64
	BatchesFailed uint64
	BytesTotal    uint64
}
