package bridge

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/server/connection"
	"github.com/quic-go/quic-go"
)

var (
	ServerTcpEnable  = false
	ServerKcpEnable  = false
	ServerQuicEnable = false
	ServerTlsEnable  = false
	ServerWsEnable   = false
	ServerWssEnable  = false
	ServerSecureMode = false
)

var bridgeHandshakeReadTimeout time.Duration = 10
var currentBridgeListenerRuntimeRoot = connection.CurrentBridgeRuntime
var currentBridgeQUICRuntimeRoot = connection.CurrentQUICRuntime
var currentBridgeDBRoot = file.GetDb

func currentBridgeListenerRuntime() connection.BridgeRuntimeConfig {
	if currentBridgeListenerRuntimeRoot != nil {
		return currentBridgeListenerRuntimeRoot()
	}
	return connection.CurrentBridgeRuntime()
}

func currentBridgeQUICRuntime() connection.QUICRuntimeConfig {
	if currentBridgeQUICRuntimeRoot != nil {
		return currentBridgeQUICRuntimeRoot()
	}
	return connection.CurrentQUICRuntime()
}

func currentBridgeDB() *file.DbUtils {
	if currentBridgeDBRoot != nil {
		if db := currentBridgeDBRoot(); db != nil {
			return db
		}
	}
	return file.GetDb()
}

type Bridge struct {
	Client             *sync.Map
	Register           *sync.Map
	VirtualTcpListener *conn.VirtualListener
	VirtualTlsListener *conn.VirtualListener
	VirtualWsListener  *conn.VirtualListener
	VirtualWssListener *conn.VirtualListener
	OpenHost           chan *file.Host
	OpenTask           chan *file.Tunnel
	SecretChan         chan *conn.Secret
	ipVerify           atomic.Bool
	runList            *sync.Map //map[int]interface{}
	disconnectTime     atomic.Int64
	p2pSessions        *p2pSessionManager
	p2pAssociations    *p2pAssociationManager
	closeClientHook      atomic.Value
	closeNodeHook        atomic.Value
	clientConnectHook    atomic.Value
	clientDisconnectHook atomic.Value
}

func NewTunnel(ipVerify bool, runList *sync.Map, disconnectTime int) *Bridge {
	bridge := &Bridge{
		Client:          &sync.Map{},
		Register:        &sync.Map{},
		OpenHost:        make(chan *file.Host, 100),
		OpenTask:        make(chan *file.Tunnel, 100),
		SecretChan:      make(chan *conn.Secret, 100),
		runList:         runList,
		p2pAssociations: newP2PAssociationManager(),
	}
	bridge.p2pSessions = newP2PSessionManager(bridge.p2pAssociations)
	bridge.ipVerify.Store(ipVerify)
	bridge.disconnectTime.Store(int64(disconnectTime))
	return bridge
}

func (s *Bridge) IPVerifyEnabled() bool {
	if s == nil {
		return false
	}
	return s.ipVerify.Load()
}

func (s *Bridge) SetIPVerify(enabled bool) {
	if s == nil {
		return
	}
	s.ipVerify.Store(enabled)
}

func (s *Bridge) DisconnectTimeout() int {
	if s == nil {
		return 0
	}
	return int(s.disconnectTime.Load())
}

func (s *Bridge) SetDisconnectTimeout(seconds int) {
	if s == nil {
		return
	}
	s.disconnectTime.Store(int64(seconds))
}

type closeClientHookEntry struct {
	run func(int)
}

type closeNodeHookEntry struct {
	run func(int, string)
}

type clientConnectHookEntry struct {
	run func(int)
}

type clientDisconnectHookEntry struct {
	run func(int)
}

type bridgeRuntimeClientLookupState uint8

const (
	bridgeRuntimeClientMissing bridgeRuntimeClientLookupState = iota
	bridgeRuntimeClientReady
	bridgeRuntimeClientInvalid
)

type bridgeRuntimeClientLookupResult struct {
	client  *Client
	state   bridgeRuntimeClientLookupState
	cleaned bool
}

func (s *Bridge) SetCloseClientHook(hook func(int)) {
	if s == nil {
		return
	}
	s.closeClientHook.Store(closeClientHookEntry{run: hook})
}

func (s *Bridge) SetCloseNodeHook(hook func(int, string)) {
	if s == nil {
		return
	}
	s.closeNodeHook.Store(closeNodeHookEntry{run: hook})
}

func (s *Bridge) SetClientConnectHook(hook func(int)) {
	if s == nil {
		return
	}
	s.clientConnectHook.Store(clientConnectHookEntry{run: hook})
}

func (s *Bridge) SetClientDisconnectHook(hook func(int)) {
	if s == nil {
		return
	}
	s.clientDisconnectHook.Store(clientDisconnectHookEntry{run: hook})
}

func (s *Bridge) notifyClientConnect(id int) {
	if s == nil || id == 0 {
		return
	}
	value := s.clientConnectHook.Load()
	if value == nil {
		return
	}
	entry, ok := value.(clientConnectHookEntry)
	if !ok || entry.run == nil {
		return
	}
	entry.run(id)
}

func (s *Bridge) notifyClientDisconnect(id int) {
	if s == nil || id == 0 {
		return
	}
	value := s.clientDisconnectHook.Load()
	if value == nil {
		return
	}
	entry, ok := value.(clientDisconnectHookEntry)
	if !ok || entry.run == nil {
		return
	}
	entry.run(id)
}

func (s *Bridge) notifyCloseClient(id int) {
	if s == nil || id == 0 {
		return
	}
	value := s.closeClientHook.Load()
	if value == nil {
		return
	}
	entry, ok := value.(closeClientHookEntry)
	if !ok || entry.run == nil {
		return
	}
	entry.run(id)
	s.notifyClientDisconnect(id)
}

func (s *Bridge) notifyCloseNode(id int, uuid string) {
	if s == nil || id == 0 || strings.TrimSpace(uuid) == "" {
		return
	}
	value := s.closeNodeHook.Load()
	if value == nil {
		return
	}
	entry, ok := value.(closeNodeHookEntry)
	if !ok || entry.run == nil {
		return
	}
	entry.run(id, uuid)
}

func (s *Bridge) DelClient(id int) {
	result := s.lookupRuntimeClient(id)
	if result.state != bridgeRuntimeClientReady || result.client == nil {
		return
	}
	_ = result.client.Close()
	if !s.removeCurrentClient(id, result.client) {
		return
	}
	if currentBridgeDB().IsPubClient(id) {
		return
	}
	s.notifyCloseClient(id)
}

func (s *Bridge) loadRuntimeClient(id int) (*Client, bool) {
	result := s.lookupRuntimeClient(id)
	return result.client, result.state == bridgeRuntimeClientReady
}

func (s *Bridge) loadOrStoreRuntimeClient(id int, candidate *Client) (*Client, bool) {
	if s == nil || s.Client == nil || candidate == nil || id == 0 {
		return nil, false
	}
	for {
		value, loaded := s.Client.LoadOrStore(id, candidate)
		if !loaded {
			return candidate, false
		}
		result := s.runtimeClientFromValue(id, value, true)
		if result.state == bridgeRuntimeClientReady && result.client != nil {
			return result.client, true
		}
	}
}

func (s *Bridge) lookupRuntimeClient(id int) bridgeRuntimeClientLookupResult {
	if s == nil || s.Client == nil || id == 0 {
		return bridgeRuntimeClientLookupResult{state: bridgeRuntimeClientMissing}
	}
	value, ok := s.Client.Load(id)
	if !ok {
		return bridgeRuntimeClientLookupResult{state: bridgeRuntimeClientMissing}
	}
	return s.runtimeClientFromValue(id, value, true)
}

func (s *Bridge) runtimeClientFromValue(id int, value interface{}, cleanupInvalid bool) bridgeRuntimeClientLookupResult {
	client, ok := value.(*Client)
	if ok && client != nil {
		return bridgeRuntimeClientLookupResult{client: client, state: bridgeRuntimeClientReady}
	}
	result := bridgeRuntimeClientLookupResult{state: bridgeRuntimeClientInvalid}
	if cleanupInvalid && s != nil && s.Client != nil {
		result.cleaned = s.Client.CompareAndDelete(id, value)
	}
	return result
}

func (s *Bridge) removeCurrentClient(id int, client *Client) bool {
	if s == nil || s.Client == nil || client == nil {
		return false
	}
	return s.Client.CompareAndDelete(id, client)
}

func (s *Bridge) removeEmptyRuntimeClient(id int, client *Client) bool {
	if s == nil || client == nil || id <= 0 {
		return false
	}
	if client.NodeCount() != 0 {
		return false
	}
	if !s.removeCurrentClient(id, client) {
		return false
	}
	if !currentBridgeDB().IsPubClient(id) {
		s.notifyCloseClient(id)
	}
	return true
}

func (s *Bridge) removeClientEntryIfCurrent(key, value interface{}) bool {
	if s == nil || s.Client == nil || key == nil || value == nil {
		return false
	}
	return s.Client.CompareAndDelete(key, value)
}

func (s *Bridge) removeRegistrationIfCurrent(ip string, expiresAt time.Time) bool {
	if s == nil || s.Register == nil || ip == "" {
		return false
	}
	return s.Register.CompareAndDelete(ip, expiresAt)
}

func (s *Bridge) removeRegistrationValueIfCurrent(ip string, value interface{}) bool {
	if s == nil || s.Register == nil || ip == "" {
		return false
	}
	return s.Register.CompareAndDelete(ip, value)
}

func (s *Bridge) removeRegistrationEntryIfCurrent(key, value interface{}) bool {
	if s == nil || s.Register == nil || key == nil || value == nil {
		return false
	}
	return s.Register.CompareAndDelete(key, value)
}

func (s *Bridge) CleanupExpiredRegistrations(now time.Time) int {
	if s == nil || s.Register == nil {
		return 0
	}
	removed := 0
	s.Register.Range(func(key, value interface{}) bool {
		ip, ok := key.(string)
		if !ok {
			if s.removeRegistrationEntryIfCurrent(key, value) {
				removed++
			}
			return true
		}
		expireAt, ok := value.(time.Time)
		if !ok {
			if s.removeRegistrationValueIfCurrent(ip, value) {
				removed++
			}
			return true
		}
		if !expireAt.After(now) && s.removeRegistrationIfCurrent(ip, expireAt) {
			removed++
		}
		return true
	})
	return removed
}

func (s *Bridge) IsServer() bool {
	return true
}

const bridgeHealthReadRetryMax = 3

type bridgeClientHealthUpdate struct {
	clientID  int
	routeUUID string
	info      string
	healthy   bool
}

func buildBridgeClientHealthUpdate(clientID int, routeUUID, info string, healthy bool) bridgeClientHealthUpdate {
	return bridgeClientHealthUpdate{
		clientID:  clientID,
		routeUUID: strings.TrimSpace(routeUUID),
		info:      strings.TrimSpace(info),
		healthy:   healthy,
	}
}

func readBridgeClientHealthUpdate(clientID int, c *conn.Conn, routeUUID string, retry *int) (bridgeClientHealthUpdate, bool) {
	if c == nil || retry == nil {
		return bridgeClientHealthUpdate{}, false
	}
	for {
		info, healthy, err := c.GetHealthInfo()
		if err == nil {
			*retry = 0
			return buildBridgeClientHealthUpdate(clientID, routeUUID, info, healthy), true
		}
		if conn.IsTimeout(err) && *retry < bridgeHealthReadRetryMax {
			*retry++
			continue
		}
		logs.Trace("GetHealthInfo error, id=%d, retry=%d, detail=%s", clientID, *retry, conn.DescribeNetError(err, c.Conn))
		return bridgeClientHealthUpdate{}, false
	}
}

func (s *Bridge) consumeBridgeClientHealth(clientID int, c *conn.Conn, routeUUID string) {
	if s == nil || clientID <= 0 || c == nil {
		return
	}
	retry := 0
	for {
		update, ok := readBridgeClientHealthUpdate(clientID, c, routeUUID, &retry)
		if !ok {
			return
		}
		s.applyBridgeClientTargetHealth(update)
	}
}

func bridgeClientRouteUUID(node *Node) string {
	if node == nil {
		return ""
	}
	return strings.TrimSpace(node.UUID)
}

func (s *Bridge) cleanupBridgeClientHealthSignal(client *Client, node *Node, signal *conn.Conn) {
	if s == nil || client == nil || node == nil || signal == nil {
		return
	}
	if !node.CloseIfSignalCurrent(signal) {
		return
	}
	if client.closeAndRemoveNodeIfCurrent(bridgeClientRouteUUID(node), node) {
		s.removeEmptyRuntimeClient(client.Id, client)
	}
}

func (s *Bridge) GetHealthFromClient(id int, c *conn.Conn, client *Client, node *Node) {
	if id <= 0 || c == nil {
		return
	}
	s.consumeBridgeClientHealth(id, c, bridgeClientRouteUUID(node))
	s.cleanupBridgeClientHealthSignal(client, node, c)
}

func (s *Bridge) applyBridgeTaskTargetHealth(update bridgeClientHealthUpdate) {
	currentBridgeDB().RangeTasks(func(v *file.Tunnel) bool {
		if v.Client != nil && v.Client.Id == update.clientID && v.Mode == "tcp" {
			v.UpdateRuntimeTargetHealth(update.routeUUID, update.info, update.healthy)
		}
		return true
	})
}

func (s *Bridge) applyBridgeHostTargetHealth(update bridgeClientHealthUpdate) {
	currentBridgeDB().RangeHosts(func(v *file.Host) bool {
		if v.Client != nil && v.Client.Id == update.clientID {
			v.UpdateRuntimeTargetHealth(update.routeUUID, update.info, update.healthy)
		}
		return true
	})
}

func (s *Bridge) applyBridgeClientTargetHealth(update bridgeClientHealthUpdate) {
	if s == nil || update.clientID <= 0 {
		return
	}
	s.applyBridgeTaskTargetHealth(update)
	s.applyBridgeHostTargetHealth(update)
}

func (s *Bridge) ping() {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	for range ticker.C {
		closedClients := s.collectPingClosedClients()
		for _, clientId := range closedClients {
			logs.Info("the client %d closed", clientId)
			s.DelClient(clientId)
		}
	}
}

func (s *Bridge) collectPingClosedClients() []int {
	if s == nil || s.Client == nil {
		return nil
	}
	closedClients := make([]int, 0)
	s.Client.Range(func(key, value interface{}) bool {
		clientID, ok := key.(int)
		if !ok {
			s.removeClientEntryIfCurrent(key, value)
			return true
		}
		if clientID <= 0 {
			return true
		}
		result := s.runtimeClientFromValue(clientID, value, false)
		if result.state != bridgeRuntimeClientReady || result.client == nil {
			logs.Trace("Client %d is nil", clientID)
			closedClients = append(closedClients, clientID)
			return true
		}
		client := result.client
		health := client.collectPingHealth()
		if health.state == clientPingHealthEmpty {
			if s.removeEmptyRuntimeClient(clientID, client) {
				return true
			}
		}
		if health.state != clientPingHealthHealthy {
			if _, shouldClose := client.notePingUnavailable(); shouldClose {
				logs.Trace("Stop client %d", clientID)
				closedClients = append(closedClients, clientID)
			}
			return true
		}
		client.resetPingRetry()
		return true
	})
	return closedClients
}

var (
	bridgeGetReservedTLSListener = connection.GetBridgeReservedTLSListener
	bridgeGetTCPListener         = connection.GetBridgeTcpListener
	bridgeGetTLSListener         = connection.GetBridgeTlsListener
	bridgeGetWSListener          = connection.GetBridgeWsListener
	bridgeGetWSSListener         = connection.GetBridgeWssListener
)

type bridgeListenerBootstrap struct {
	reservedTLSListener   net.Listener
	tcpListener           net.Listener
	tlsListener           net.Listener
	wsListener            net.Listener
	wssListener           net.Listener
	useReservedTLSGateway bool
}

func (b *bridgeListenerBootstrap) close() {
	if b == nil {
		return
	}
	for _, listener := range []net.Listener{
		b.reservedTLSListener,
		b.tcpListener,
		b.tlsListener,
		b.wsListener,
		b.wssListener,
	} {
		if listener != nil {
			_ = listener.Close()
		}
	}
}

func (b *bridgeListenerBootstrap) openReservedTLSListener() error {
	if !ServerTlsEnable || !ServerWssEnable {
		return nil
	}
	listener, err := bridgeGetReservedTLSListener()
	if err != nil {
		return err
	}
	b.reservedTLSListener = listener
	b.useReservedTLSGateway = listener != nil
	return nil
}

func (b *bridgeListenerBootstrap) openTCPListener() error {
	if !ServerTcpEnable {
		return nil
	}
	listener, err := bridgeGetTCPListener()
	if err != nil {
		return err
	}
	b.tcpListener = listener
	return nil
}

func (b *bridgeListenerBootstrap) openTLSListener() error {
	if !ServerTlsEnable || b.useReservedTLSGateway {
		return nil
	}
	listener, err := bridgeGetTLSListener()
	if err != nil {
		return err
	}
	b.tlsListener = listener
	return nil
}

func (b *bridgeListenerBootstrap) openWSListener() error {
	if !ServerWsEnable {
		return nil
	}
	listener, err := bridgeGetWSListener()
	if err != nil {
		return err
	}
	b.wsListener = listener
	return nil
}

func (b *bridgeListenerBootstrap) openWSSListener() error {
	if !ServerWssEnable || b.useReservedTLSGateway {
		return nil
	}
	listener, err := bridgeGetWSSListener()
	if err != nil {
		return err
	}
	b.wssListener = listener
	return nil
}

func bootstrapBridgeListeners() (_ *bridgeListenerBootstrap, err error) {
	bootstrap := &bridgeListenerBootstrap{}
	defer func() {
		if err != nil {
			bootstrap.close()
		}
	}()

	if err = bootstrap.openReservedTLSListener(); err != nil {
		return nil, err
	}
	if err = bootstrap.openTCPListener(); err != nil {
		return nil, err
	}
	if err = bootstrap.openTLSListener(); err != nil {
		return nil, err
	}
	if err = bootstrap.openWSListener(); err != nil {
		return nil, err
	}
	if err = bootstrap.openWSSListener(); err != nil {
		return nil, err
	}
	return bootstrap, nil
}

func (s *Bridge) startBridgeTCPListener(listeners *bridgeListenerBootstrap) {
	s.VirtualTcpListener = conn.NewVirtualListener(nil)
	go conn.Accept(s.VirtualTcpListener, func(c net.Conn) {
		s.CliProcess(conn.NewConn(c), common.CONN_TCP)
	})
	if listeners != nil && listeners.tcpListener != nil {
		s.VirtualTcpListener.SetAddr(listeners.tcpListener.Addr())
		go conn.Accept(listeners.tcpListener, s.VirtualTcpListener.ServeVirtual)
	}
}

func (s *Bridge) startBridgeTLSListener(listeners *bridgeListenerBootstrap) {
	s.VirtualTlsListener = conn.NewVirtualListener(nil)
	if listeners != nil && listeners.useReservedTLSGateway {
		go conn.Accept(s.VirtualTlsListener, func(c net.Conn) {
			s.CliProcess(conn.NewConn(c), common.CONN_TLS)
		})
	} else {
		go conn.Accept(s.VirtualTlsListener, func(c net.Conn) {
			tlsConn := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{crypt.GetCert()}})
			s.CliProcess(conn.NewConn(tlsConn), common.CONN_TLS)
		})
	}
	if listeners != nil && listeners.tlsListener != nil {
		s.VirtualTlsListener.SetAddr(listeners.tlsListener.Addr())
		go conn.Accept(listeners.tlsListener, s.VirtualTlsListener.ServeVirtual)
	}
}

func (s *Bridge) startBridgeWSListener(listeners *bridgeListenerBootstrap, bridgeCfg connection.BridgeRuntimeConfig) {
	s.VirtualWsListener = conn.NewVirtualListener(nil)
	wsLn := conn.NewWSListener(s.VirtualWsListener, bridgeCfg.Path, bridgeCfg.TrustedIPs, bridgeCfg.RealIPHeader)
	go conn.Accept(wsLn, func(c net.Conn) {
		s.CliProcess(conn.NewConn(c), common.CONN_WS)
	})
	if listeners != nil && listeners.wsListener != nil {
		s.VirtualWsListener.SetAddr(listeners.wsListener.Addr())
		go conn.Accept(listeners.wsListener, s.VirtualWsListener.ServeVirtual)
	}
}

func (s *Bridge) startBridgeWSSListener(listeners *bridgeListenerBootstrap, bridgeCfg connection.BridgeRuntimeConfig) {
	s.VirtualWssListener = conn.NewVirtualListener(nil)
	var wssLn net.Listener = conn.NewWSSListener(s.VirtualWssListener, bridgeCfg.Path, crypt.GetCert(), bridgeCfg.TrustedIPs, bridgeCfg.RealIPHeader)
	if listeners != nil && listeners.useReservedTLSGateway {
		wssLn = conn.NewWSListener(s.VirtualWssListener, bridgeCfg.Path, bridgeCfg.TrustedIPs, bridgeCfg.RealIPHeader)
	}
	go conn.Accept(wssLn, func(c net.Conn) {
		s.CliProcess(conn.NewConn(c), common.CONN_WSS)
	})
	if listeners != nil && listeners.wssListener != nil {
		s.VirtualWssListener.SetAddr(listeners.wssListener.Addr())
		go conn.Accept(listeners.wssListener, s.VirtualWssListener.ServeVirtual)
	}
}

func (s *Bridge) startBridgeReservedTLSGateway(listeners *bridgeListenerBootstrap) {
	if listeners == nil || !listeners.useReservedTLSGateway || listeners.reservedTLSListener == nil {
		return
	}
	s.VirtualTlsListener.SetAddr(listeners.reservedTLSListener.Addr())
	s.VirtualWssListener.SetAddr(listeners.reservedTLSListener.Addr())
	go conn.Accept(listeners.reservedTLSListener, s.handleReservedTLSConn)
}

func (s *Bridge) startBridgeKCPListener(bridgeCfg connection.BridgeRuntimeConfig) {
	if !ServerKcpEnable {
		return
	}
	logs.Info("Server start, the bridge type is kcp, the bridge port is %d", bridgeCfg.KCPPort)
	go func() {
		addr := common.BuildAddress(bridgeCfg.KCPIP, strconv.Itoa(bridgeCfg.KCPPort))
		err := conn.NewKcpListenerAndProcess(addr, func(c net.Conn) {
			s.CliProcess(conn.NewConn(c), "kcp")
		})
		if err != nil {
			logs.Error("KCP listener error: %v", err)
		}
	}()
}

func buildBridgeQUICConfig(quicCfg connection.QUICRuntimeConfig) *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:    time.Duration(quicCfg.KeepAliveSec) * time.Second,
		MaxIdleTimeout:     time.Duration(quicCfg.IdleTimeoutSec) * time.Second,
		MaxIncomingStreams: quicCfg.MaxStreams,
	}
}

func buildBridgeQUICTLSConfig(quicCfg connection.QUICRuntimeConfig) *tls.Config {
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{crypt.GetCert()}}
	tlsCfg.NextProtos = quicCfg.ALPN
	return tlsCfg
}

func (s *Bridge) startBridgeQUICListener(bridgeCfg connection.BridgeRuntimeConfig, quicCfg connection.QUICRuntimeConfig) {
	if !ServerQuicEnable {
		return
	}
	logs.Info("Server start, the bridge type is quic, the bridge port is %d", bridgeCfg.QUICPort)
	go func() {
		addr := common.BuildAddress(bridgeCfg.QUICIP, strconv.Itoa(bridgeCfg.QUICPort))
		err := conn.NewQuicListenerAndProcess(addr, buildBridgeQUICTLSConfig(quicCfg), buildBridgeQUICConfig(quicCfg), func(c net.Conn) {
			s.CliProcess(conn.NewConn(c), "quic")
		})
		if err != nil {
			logs.Error("QUIC listener error: %v", err)
		}
	}()
}

func (s *Bridge) StartTunnel() error {
	bridgeCfg := currentBridgeListenerRuntime()
	quicCfg := currentBridgeQUICRuntime()
	listeners, err := bootstrapBridgeListeners()
	if err != nil {
		return err
	}
	go s.ping()
	s.startBridgeTCPListener(listeners)
	s.startBridgeTLSListener(listeners)
	s.startBridgeWSListener(listeners, bridgeCfg)
	s.startBridgeWSSListener(listeners, bridgeCfg)
	s.startBridgeReservedTLSGateway(listeners)
	s.startBridgeKCPListener(bridgeCfg)
	s.startBridgeQUICListener(bridgeCfg, quicCfg)
	return nil
}

const (
	httpGet     = 716984
	httpPost    = 807983
	httpHead    = 726965
	httpPut     = 808585
	httpDelete  = 686976
	httpConnect = 677978
	httpOptions = 798084
	httpTrace   = 848265
	clientHello = 848384
)

func isBridgeGatewayHTTPPrefix(prefix []byte) bool {
	switch common.BytesToNum(prefix) {
	case httpConnect, httpDelete, httpGet, httpHead, httpOptions, httpPost, httpPut, httpTrace:
		return true
	default:
		return false
	}
}

func isBridgeGatewayWebsocketRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return false
	}
	path := r.URL.Path
	if path == "" {
		path = r.URL.EscapedPath()
	}
	if path == "" {
		path = r.RequestURI
	}
	return path == currentBridgeListenerRuntime().Path
}

type bridgeReservedTLSGateway struct {
	tlsConn *tls.Conn
	prefix  []byte
}

type bridgeReservedTLSRequest struct {
	conn *conn.Conn
	rb   []byte
	req  *http.Request
}

func acceptReservedTLSGateway(raw net.Conn) (bridgeReservedTLSGateway, error) {
	if raw == nil {
		return bridgeReservedTLSGateway{}, io.EOF
	}
	tlsConn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{crypt.GetCert()}})
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return bridgeReservedTLSGateway{}, err
	}
	prefix := make([]byte, 3)
	if _, err := io.ReadFull(tlsConn, prefix); err != nil {
		_ = tlsConn.Close()
		return bridgeReservedTLSGateway{}, err
	}
	return bridgeReservedTLSGateway{
		tlsConn: tlsConn,
		prefix:  prefix,
	}, nil
}

func (s *Bridge) routeReservedTLSProtocol(gateway bridgeReservedTLSGateway) bool {
	switch common.BytesToNum(gateway.prefix) {
	case clientHello:
		s.VirtualTlsListener.ServeVirtual(conn.NewConn(gateway.tlsConn).SetRb(gateway.prefix))
		return true
	default:
		if !isBridgeGatewayHTTPPrefix(gateway.prefix) {
			_ = gateway.tlsConn.Close()
			return true
		}
		return false
	}
}

func readReservedTLSGatewayRequest(gateway bridgeReservedTLSGateway) (bridgeReservedTLSRequest, error) {
	c := conn.NewConn(gateway.tlsConn).SetRb(gateway.prefix)
	_, _, rb, req, err := c.GetHost()
	if err != nil {
		_ = c.Close()
		return bridgeReservedTLSRequest{}, err
	}
	return bridgeReservedTLSRequest{
		conn: c,
		rb:   rb,
		req:  req,
	}, nil
}

func (s *Bridge) serveReservedTLSWebsocket(request bridgeReservedTLSRequest) {
	if request.conn == nil || !isBridgeGatewayWebsocketRequest(request.req) {
		if request.conn != nil {
			_ = request.conn.Close()
		}
		return
	}
	s.VirtualWssListener.ServeVirtual(request.conn.SetRb(request.rb))
}

func (s *Bridge) handleReservedTLSConn(raw net.Conn) {
	gateway, err := acceptReservedTLSGateway(raw)
	if err != nil {
		return
	}
	if s.routeReservedTLSProtocol(gateway) {
		return
	}
	request, err := readReservedTLSGatewayRequest(gateway)
	if err != nil {
		return
	}
	s.serveReservedTLSWebsocket(request)
}

func (s *Bridge) loadClientNode(clientID int, uuid string) *Node {
	if clientID == 0 {
		return nil
	}
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return nil
	}
	client, ok := s.loadRuntimeClient(clientID)
	if !ok {
		return nil
	}
	node, ok := client.GetNodeByUUID(uuid)
	if !ok || node == nil {
		return nil
	}
	return node
}

func (s *Bridge) LoadClientNodeRuntime(clientID int, uuid string) any {
	return s.loadClientNode(clientID, uuid)
}

func (s *Bridge) ClientOnlineNodeCount(clientID int) int {
	client, ok := s.loadRuntimeClient(clientID)
	if !ok || client == nil {
		return 0
	}
	return client.OnlineNodeCount()
}

func (s *Bridge) ClientHasMultipleOnlineNodes(clientID int) bool {
	client, ok := s.loadRuntimeClient(clientID)
	if !ok || client == nil {
		return false
	}
	return client.HasMultipleOnlineNodes()
}

func (s *Bridge) SelectClientRouteUUID(clientID int) string {
	client, ok := s.loadRuntimeClient(clientID)
	if !ok || client == nil {
		return ""
	}
	if ClientSelectMode == Primary {
		if node := client.currentNodeIfOnline(); node != nil {
			return strings.TrimSpace(node.UUID)
		}
	}
	node := client.GetNode()
	if node == nil {
		return ""
	}
	return strings.TrimSpace(node.UUID)
}

func (s *Bridge) ClientSelectionCanRotate() bool {
	return ClientSelectMode != Primary
}

func (s *Bridge) AddClientNodeConn(clientID int, uuid string) {
	if node := s.loadClientNode(clientID, uuid); node != nil {
		node.AddConn()
	}
}

func (s *Bridge) CutClientNodeConn(clientID int, uuid string) {
	if node := s.loadClientNode(clientID, uuid); node != nil {
		node.CutConn()
	}
}

func (s *Bridge) ObserveClientNodeBridgeTraffic(clientID int, uuid string, in, out int64) {
	if node := s.loadClientNode(clientID, uuid); node != nil {
		node.ObserveBridgeTraffic(in, out)
	}
}

func (s *Bridge) ObserveClientNodeServiceTraffic(clientID int, uuid string, in, out int64) {
	if node := s.loadClientNode(clientID, uuid); node != nil {
		node.ObserveServiceTraffic(in, out)
	}
}
