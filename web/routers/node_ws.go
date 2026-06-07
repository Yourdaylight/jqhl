package routers

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/servercfg"
	"github.com/djylb/nps/server"
	webapi "github.com/djylb/nps/web/api"
	webservice "github.com/djylb/nps/web/service"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var nodeWSUpgrader = websocket.Upgrader{
	CheckOrigin: allowNodeWebSocketOrigin,
}

const nodeWSWriteTimeout = 10 * time.Second
const nodeWSInvalidateWriteTimeout = time.Second
const nodeRealtimeInvalidationParallelism = 64

type nodeWSFrame struct {
	ID        string            `json:"id,omitempty"`
	Type      string            `json:"type"`
	Method    string            `json:"method,omitempty"`
	Path      string            `json:"path,omitempty"`
	Body      json.RawMessage   `json:"body,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Status    int               `json:"status,omitempty"`
	Error     string            `json:"error,omitempty"`
	Encoding  string            `json:"encoding,omitempty"`
	Timestamp int64             `json:"timestamp,omitempty"`
	NodeID    string            `json:"node_id,omitempty"`
	Schema    int               `json:"schema_version,omitempty"`
	APIBase   string            `json:"api_base,omitempty"`
	Actor     *webapi.Actor     `json:"actor,omitempty"`
}

type nodeWSActorState struct {
	mu    sync.RWMutex
	actor *webapi.Actor
}

type nodeWSAuthMode string

const (
	nodeWSAuthModeStatic        nodeWSAuthMode = "static"
	nodeWSAuthModeSession       nodeWSAuthMode = "session"
	nodeWSAuthModeToken         nodeWSAuthMode = "standalone_token"
	nodeWSAuthModePlatformToken nodeWSAuthMode = "platform_token"
)

type nodeWSAuthRefresher struct {
	mu       sync.Mutex
	state    *State
	mode     nodeWSAuthMode
	actor    *webapi.Actor
	identity *webservice.SessionIdentity
	token    string
	lookup   func(string) string
}

type nodeWSDispatchBase struct {
	Context       context.Context
	Host          string
	RemoteAddr    string
	ClientIP      string
	Metadata      webapi.RequestMetadata
	Resolver      webservice.PermissionResolver
	Subscriptions *nodeWSSubscriptionRegistry
}

type wsAPIContext struct {
	baseCtx         context.Context
	method          string
	host            string
	remoteAddr      string
	clientIP        string
	requestHeaders  map[string]string
	params          map[string]string
	rawBody         []byte
	session         map[string]interface{}
	sessionResolver webservice.PermissionResolver
	actor           *webapi.Actor
	metadata        webapi.RequestMetadata

	written        bool
	status         int
	contentType    string
	responseBody   []byte
	responseMode   wsResponseBodyMode
	responseHeader map[string]string
}

type wsResponseBodyMode uint8

const (
	wsResponseBodyModeUnknown wsResponseBodyMode = iota
	wsResponseBodyModeJSON
	wsResponseBodyModeText
	wsResponseBodyModeBinary
)

type wsSessionEditor struct {
	ctx *wsAPIContext
}

type nodeRealtimeSessionRegistry struct {
	mu       sync.Mutex
	nextID   int64
	sessions map[int64]func(string, string)
}

func newNodeRealtimeSessionRegistry() *nodeRealtimeSessionRegistry {
	return &nodeRealtimeSessionRegistry{
		sessions: make(map[int64]func(string, string)),
	}
}

func (r *nodeRealtimeSessionRegistry) Register(invalidate func(string, string)) func() {
	if r == nil || invalidate == nil {
		return func() {}
	}
	r.mu.Lock()
	r.nextID++
	id := r.nextID
	r.sessions[id] = invalidate
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		delete(r.sessions, id)
		r.mu.Unlock()
	}
}

func (r *nodeRealtimeSessionRegistry) InvalidateAll(reason, configEpoch string) {
	if r == nil {
		return
	}
	reason = strings.TrimSpace(reason)
	configEpoch = strings.TrimSpace(configEpoch)
	r.mu.Lock()
	handlers := make([]func(string, string), 0, len(r.sessions))
	for id, invalidate := range r.sessions {
		if invalidate == nil {
			delete(r.sessions, id)
			continue
		}
		handlers = append(handlers, invalidate)
		delete(r.sessions, id)
	}
	r.mu.Unlock()
	dispatchNodeRealtimeInvalidations(handlers, reason, configEpoch)
}

func dispatchNodeRealtimeInvalidations(handlers []func(string, string), reason, configEpoch string) {
	handlers = compactNodeRealtimeInvalidationHandlers(handlers)
	switch len(handlers) {
	case 0:
		return
	case 1:
		go handlers[0](reason, configEpoch)
		return
	}
	if len(handlers) <= nodeRealtimeInvalidationParallelism || nodeRealtimeInvalidationParallelism <= 0 {
		for _, invalidate := range handlers {
			go invalidate(reason, configEpoch)
		}
		return
	}
	go func() {
		runNodeRealtimeInvalidations(handlers, reason, configEpoch, nodeRealtimeInvalidationWorkers(len(handlers)))
	}()
}

func compactNodeRealtimeInvalidationHandlers(handlers []func(string, string)) []func(string, string) {
	if len(handlers) == 0 {
		return nil
	}
	compacted := handlers[:0]
	for _, invalidate := range handlers {
		if invalidate != nil {
			compacted = append(compacted, invalidate)
		}
	}
	return compacted
}

func nodeRealtimeInvalidationWorkers(count int) int {
	switch {
	case count <= 1:
		return count
	case nodeRealtimeInvalidationParallelism <= 0:
		return count
	case count > nodeRealtimeInvalidationParallelism:
		return nodeRealtimeInvalidationParallelism
	default:
		return count
	}
}

func runNodeRealtimeInvalidations(handlers []func(string, string), reason, configEpoch string, workers int) {
	if len(handlers) == 0 {
		return
	}
	if workers <= 1 {
		for _, invalidate := range handlers {
			invalidate(reason, configEpoch)
		}
		return
	}
	if workers > len(handlers) {
		workers = len(handlers)
	}
	jobs := make(chan func(string, string), workers)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for invalidate := range jobs {
				invalidate(reason, configEpoch)
			}
		}()
	}
	for _, invalidate := range handlers {
		jobs <- invalidate
	}
	close(jobs)
	wg.Wait()
}

func nodeEpochChangedFrame(configEpoch, reason string) nodeWSFrame {
	body := map[string]interface{}{
		"resync_required": true,
	}
	if strings.TrimSpace(configEpoch) != "" {
		body["config_epoch"] = strings.TrimSpace(configEpoch)
	}
	if strings.TrimSpace(reason) != "" {
		body["reason"] = strings.TrimSpace(reason)
	}
	return newNodeControlFrame("epoch_changed", 409, body)
}

func newNodeControlFrame(frameType string, status int, body interface{}) nodeWSFrame {
	frame := nodeWSFrame{
		Type:      strings.TrimSpace(frameType),
		Status:    status,
		Timestamp: time.Now().Unix(),
	}
	if body == nil {
		return frame
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return frame
	}
	frame.Body = raw
	return frame
}

func newNodeWSPongFrame(frameID string) nodeWSFrame {
	return nodeWSFrame{
		ID:        strings.TrimSpace(frameID),
		Type:      "pong",
		Timestamp: time.Now().Unix(),
	}
}

func newNodeWSErrorFrame(frameID string, status int, message string) nodeWSFrame {
	return nodeWSFrame{
		ID:        strings.TrimSpace(frameID),
		Type:      "error",
		Status:    status,
		Error:     strings.TrimSpace(message),
		Timestamp: time.Now().Unix(),
	}
}

func writeNodeWSEventFrame(writeFrame func(nodeWSFrame) error, event webapi.Event) error {
	if writeFrame == nil {
		return net.ErrClosed
	}
	body, _ := json.Marshal(event)
	return writeFrame(nodeWSFrame{
		Type:      "event",
		Body:      body,
		Timestamp: time.Now().Unix(),
	})
}

func deliverNodeReverseEvent(platformID string, runtimeStatus webservice.ManagementPlatformRuntimeStatusStore, event webapi.Event, writeFrame func(nodeWSFrame) error, closeConn func()) bool {
	if err := writeNodeWSEventFrame(writeFrame, event); err != nil {
		if closeConn != nil {
			closeConn()
		}
		return false
	}
	if runtimeStatus != nil {
		runtimeStatus.NoteReverseEvent(platformID)
	}
	return true
}

func registerNodeRealtimeInvalidationConn(state *State, conn *websocket.Conn, writeMu *sync.Mutex) func() {
	if state == nil || state.RealtimeSessions == nil || conn == nil {
		return func() {}
	}
	return state.RealtimeSessions.Register(func(reason, configEpoch string) {
		if writeMu != nil {
			writeMu.Lock()
			defer writeMu.Unlock()
		}
		_ = writeNodeWSFrameWithTimeout(conn, nodeEpochChangedFrame(configEpoch, reason), nodeWSInvalidateWriteTimeout)
		_ = conn.Close()
	})
}

func runNodeSubscriptionEventLoop(sub *nodeEventSubscription, done <-chan struct{}, deliver func(webapi.Event) bool, handleOverflow func()) {
	if sub == nil || deliver == nil {
		return
	}
	for {
		select {
		case event := <-sub.Events():
			if !deliver(event) {
				return
			}
		case <-sub.Done():
			stopDrain := false
			drainNodeSubscriptionEvents(sub, func(event webapi.Event) {
				if stopDrain {
					return
				}
				if !deliver(event) {
					stopDrain = true
				}
			})
			if handleOverflow != nil {
				handleOverflow()
			}
			return
		case <-done:
			return
		}
	}
}

func newNodeWSActorState(actor *webapi.Actor) *nodeWSActorState {
	return &nodeWSActorState{actor: cloneActor(actor)}
}

func newNodeWSAuthRefresher(state *State, c *gin.Context, actor *webapi.Actor) *nodeWSAuthRefresher {
	refresher := &nodeWSAuthRefresher{
		state: state,
		mode:  nodeWSAuthModeStatic,
		actor: cloneActor(actor),
	}
	if state == nil || c == nil {
		return refresher
	}
	if token := standaloneTokenFromRequest(c); token != "" {
		refresher.mode = nodeWSAuthModeToken
		refresher.token = token
		return refresher
	}
	if _, ok := c.Get(nodePlatformContextKey); ok {
		if token := nodeTokenFromRequest(c); token != "" {
			refresher.mode = nodeWSAuthModePlatformToken
			refresher.token = token
			refresher.lookup = snapshotNodePlatformLookup(c)
			return refresher
		}
	}
	if identity := sessionIdentityFromSession(c, state.PermissionResolver()); identity != nil && identity.Authenticated {
		refresher.mode = nodeWSAuthModeSession
		refresher.identity = identity
	}
	return refresher
}

func (r *nodeWSAuthRefresher) Refresh(now time.Time) (*webapi.Actor, error) {
	if r == nil {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.IsZero() {
		now = time.Now()
	}
	switch r.mode {
	case nodeWSAuthModeToken:
		resolved, err := resolveStandaloneTokenActorIdentity(r.state, r.token, now)
		if err != nil {
			return nil, err
		}
		if resolved == nil {
			r.actor = webapi.AnonymousActor()
			return cloneActor(r.actor), nil
		}
		r.actor = resolved.actor
		return cloneActor(r.actor), nil
	case nodeWSAuthModePlatformToken:
		cfg := r.state.CurrentConfig()
		if cfg == nil || !cfg.Runtime.HasManagementPlatforms() {
			return nil, webservice.ErrUnauthenticated
		}
		platform, ok := cfg.Runtime.FindManagementPlatformByToken(r.token)
		if !ok || subtle.ConstantTimeCompare([]byte(platform.Token), []byte(r.token)) != 1 {
			return nil, webservice.ErrUnauthenticated
		}
		if !platform.SupportsDirect() {
			return nil, webservice.ErrForbidden
		}
		serviceUser, err := ensurePlatformServiceUser(r.state, platform)
		if err != nil {
			return nil, err
		}
		if serviceUser == nil || serviceUser.Id <= 0 {
			return nil, errors.New("platform service user is unavailable")
		}
		r.actor, err = platformActorFromLookup(platform, serviceUser.Id, func() ([]int, error) {
			return platformOwnedClientIDs(r.state, serviceUser.Id)
		}, r.lookup)
		if err != nil {
			return nil, err
		}
		return cloneActor(r.actor), nil
	case nodeWSAuthModeSession:
		resolved, err := refreshSessionActorIdentity(r.state, r.identity, now)
		if err != nil {
			return nil, err
		}
		if resolved == nil {
			r.identity = nil
			r.actor = webapi.AnonymousActor()
			return cloneActor(r.actor), nil
		}
		r.identity = resolved.identity
		r.actor = resolved.actor
		return cloneActor(r.actor), nil
	default:
		return cloneActor(r.actor), nil
	}
}

func newWSAPIContextFromBase(base nodeWSDispatchBase, actor *webapi.Actor, frame nodeWSFrame) (*wsAPIContext, error) {
	params, err := decodeWSParams(frame.Path, frame.Body)
	if err != nil {
		return nil, err
	}
	requestHeaders := make(map[string]string, len(frame.Headers))
	for key, value := range frame.Headers {
		requestHeaders[strings.ToLower(strings.TrimSpace(key))] = value
	}
	resolver := base.Resolver
	if isNilRouterServiceValue(resolver) {
		resolver = webservice.DefaultPermissionResolver()
	}
	session := map[string]interface{}{}
	webapi.ApplyActorSessionMapWithResolver(session, actor, "ws", resolver)
	if base.Context == nil {
		base.Context = context.Background()
	}
	return &wsAPIContext{
		baseCtx:         base.Context,
		method:          strings.ToUpper(strings.TrimSpace(frame.Method)),
		host:            base.Host,
		remoteAddr:      base.RemoteAddr,
		clientIP:        base.ClientIP,
		requestHeaders:  requestHeaders,
		params:          params,
		rawBody:         frame.Body,
		session:         session,
		sessionResolver: resolver,
		actor:           cloneActor(actor),
		metadata:        base.Metadata,
		responseHeader:  requestMetadataResponseHeaders(base.Metadata),
	}, nil
}

func (c *wsAPIContext) BaseContext() context.Context {
	if c == nil || c.baseCtx == nil {
		return context.Background()
	}
	return c.baseCtx
}

func (c *wsAPIContext) String(key string) string {
	if c == nil {
		return ""
	}
	return c.params[strings.TrimSpace(key)]
}

func (c *wsAPIContext) LookupString(key string) (string, bool) {
	if c == nil {
		return "", false
	}
	value, ok := c.params[strings.TrimSpace(key)]
	return value, ok
}

func (c *wsAPIContext) Int(key string, def ...int) int {
	value := strings.TrimSpace(c.String(key))
	if value == "" {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}
	parsed, _ := strconv.Atoi(value)
	return parsed
}

func (c *wsAPIContext) Bool(key string, def ...bool) bool {
	value := strings.TrimSpace(c.String(key))
	if value == "" {
		if len(def) > 0 {
			return def[0]
		}
		return false
	}
	parsed, _ := strconv.ParseBool(value)
	return parsed
}

func (c *wsAPIContext) Method() string {
	if c == nil || c.method == "" {
		return http.MethodGet
	}
	return c.method
}

func (c *wsAPIContext) Host() string {
	if c == nil {
		return ""
	}
	return c.host
}

func (c *wsAPIContext) RemoteAddr() string {
	if c == nil {
		return ""
	}
	return c.remoteAddr
}

func (c *wsAPIContext) ClientIP() string {
	if c == nil {
		return ""
	}
	return c.clientIP
}

func (c *wsAPIContext) RequestHeader(key string) string {
	if c == nil {
		return ""
	}
	return c.requestHeaders[strings.ToLower(strings.TrimSpace(key))]
}

func (c *wsAPIContext) RawBodyView() []byte {
	if c == nil {
		return nil
	}
	return c.rawBody
}

func (c *wsAPIContext) RawBody() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.rawBody...)
}

func (c *wsAPIContext) SessionValue(key string) interface{} {
	if c == nil {
		return nil
	}
	return c.session[strings.TrimSpace(key)]
}

func (c *wsAPIContext) SetSessionValue(key string, value interface{}) {
	if c == nil {
		return
	}
	if c.session == nil {
		c.session = make(map[string]interface{})
	}
	c.session[strings.TrimSpace(key)] = value
}

func (c *wsAPIContext) DeleteSessionValue(key string) {
	if c == nil {
		return
	}
	delete(c.session, strings.TrimSpace(key))
}

func (c *wsAPIContext) MutateSession(fn func(webapi.SessionEditor)) {
	if c == nil || fn == nil {
		return
	}
	fn(wsSessionEditor{ctx: c})
}

func (e wsSessionEditor) Set(key string, value interface{}) {
	if e.ctx == nil {
		return
	}
	e.ctx.SetSessionValue(key, value)
}

func (e wsSessionEditor) Delete(key string) {
	if e.ctx == nil {
		return
	}
	e.ctx.DeleteSessionValue(key)
}

func (c *wsAPIContext) SetParam(key, value string) {
	if c == nil {
		return
	}
	if c.params == nil {
		c.params = make(map[string]string)
	}
	c.params[strings.TrimSpace(key)] = strings.TrimSpace(value)
}

func (c *wsAPIContext) RespondJSON(status int, value interface{}) {
	body, _ := json.Marshal(value)
	c.write(status, "application/json; charset=utf-8", body, wsResponseBodyModeJSON)
}

func (c *wsAPIContext) RespondString(status int, body string) {
	c.write(status, "text/plain; charset=utf-8", []byte(body), wsResponseBodyModeText)
}

func (c *wsAPIContext) RespondData(status int, contentType string, data []byte) {
	c.write(status, contentType, data, wsResponseBodyModeForData(contentType))
}

func (c *wsAPIContext) Redirect(status int, location string) {
	c.SetResponseHeader("Location", location)
	c.write(status, "text/plain; charset=utf-8", nil, wsResponseBodyModeText)
}

func (c *wsAPIContext) SetResponseHeader(key, value string) {
	if c == nil {
		return
	}
	if c.responseHeader == nil {
		c.responseHeader = make(map[string]string)
	}
	c.responseHeader[key] = value
}

func (c *wsAPIContext) IsWritten() bool {
	if c == nil {
		return false
	}
	return c.written
}

func (c *wsAPIContext) Actor() *webapi.Actor {
	if c == nil {
		return nil
	}
	return c.actor
}

func (c *wsAPIContext) SetActor(actor *webapi.Actor) {
	if c == nil {
		return
	}
	c.actor = cloneActor(actor)
	if c.session == nil {
		c.session = make(map[string]interface{})
	}
	webapi.ApplyActorSessionMapWithResolver(c.session, actor, "ws", c.sessionResolver)
}

func (c *wsAPIContext) Metadata() webapi.RequestMetadata {
	if c == nil {
		return webapi.RequestMetadata{}
	}
	return c.metadata
}

func wsResponseBodyModeForData(contentType string) wsResponseBodyMode {
	switch {
	case isWSJSONContentType(contentType):
		return wsResponseBodyModeUnknown
	case isWSTextContentType(contentType):
		return wsResponseBodyModeText
	case strings.TrimSpace(contentType) != "":
		return wsResponseBodyModeBinary
	default:
		return wsResponseBodyModeUnknown
	}
}

func (c *wsAPIContext) write(status int, contentType string, body []byte, mode wsResponseBodyMode) {
	if c == nil {
		return
	}
	c.written = true
	c.status = status
	c.contentType = contentType
	c.responseBody = body
	c.responseMode = mode
	if contentType != "" {
		if c.responseHeader == nil {
			c.responseHeader = make(map[string]string)
		}
		c.responseHeader["Content-Type"] = contentType
	}
}

func decodeWSParams(rawPath string, rawBody json.RawMessage) (map[string]string, error) {
	params := make(map[string]string)
	parsedPath, err := url.Parse(strings.TrimSpace(rawPath))
	if err != nil {
		return nil, err
	}
	for key, values := range parsedPath.Query() {
		if len(values) == 0 {
			continue
		}
		params[key] = values[len(values)-1]
	}
	if len(rawBody) == 0 {
		return params, nil
	}
	var payload interface{}
	decoder := json.NewDecoder(bytes.NewReader(rawBody))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	objectPayload, ok := payload.(map[string]interface{})
	if !ok {
		return params, nil
	}
	for key, value := range objectPayload {
		params[key] = webapi.StringifyRequestValue(value)
	}
	return params, nil
}

func nodeWSRefreshAuthFailureFrame(frameID string, err error) nodeWSFrame {
	detail := requestAuthFailureDetail(err)
	if strings.TrimSpace(frameID) == "" {
		return newNodeControlFrame("unauthorized", detail.status, map[string]interface{}{
			"error":  detail.message,
			"reason": "identity_invalid",
		})
	}
	response := nodeWSFrame{
		ID:        strings.TrimSpace(frameID),
		Type:      "response",
		Status:    detail.status,
		Timestamp: time.Now().Unix(),
		Headers:   map[string]string{"Content-Type": "application/json; charset=utf-8"},
	}
	body, _ := json.Marshal(webapi.ManagementErrorResponse{
		Error: webapi.ManagementErrorDetail{
			Code:    detail.code,
			Message: detail.message,
		},
	})
	response.Body = body
	return response
}

func (s *nodeWSActorState) Current() *webapi.Actor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneActor(s.actor)
}

func (s *nodeWSActorState) Update(actor *webapi.Actor) *webapi.Actor {
	if s == nil {
		return cloneActor(actor)
	}
	cloned := cloneActor(actor)
	s.mu.Lock()
	s.actor = cloned
	s.mu.Unlock()
	return cloneActor(cloned)
}

func allowNodeWebSocketOrigin(r *http.Request) bool {
	return allowNodeWebSocketOriginWithConfig(servercfg.Current(), r)
}

func allowNodeWebSocketOriginWithConfig(cfg *servercfg.Snapshot, r *http.Request) bool {
	if r == nil {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	requestHost := forwardedOrRequestHost(r)
	if sameOriginHostPort(parsed, requestHost, requestSchemeForOrigin(r)) {
		return true
	}
	return cfg != nil && cfg.StandaloneAllowsOrigin(origin)
}

func requestSchemeForOrigin(r *http.Request) string {
	requestScheme := "http"
	if r != nil && r.TLS != nil {
		requestScheme = "https"
	}
	if r != nil {
		if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
			requestScheme = strings.ToLower(strings.TrimSpace(strings.Split(forwarded, ",")[0]))
		}
	}
	return requestScheme
}

func forwardedOrRequestHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return strings.TrimSpace(r.Host)
}

func sameOriginHostPort(origin *url.URL, requestHost, requestScheme string) bool {
	if origin == nil {
		return false
	}
	originHost := strings.ToLower(strings.TrimSpace(origin.Hostname()))
	requestName, requestPort := splitHostPortDefault(requestHost, requestScheme)
	if originHost == "" || requestName == "" || !strings.EqualFold(originHost, requestName) {
		return false
	}
	originPort := origin.Port()
	if originPort == "" {
		originPort = defaultPortForScheme(origin.Scheme)
	}
	if requestPort == "" {
		requestPort = defaultPortForScheme(requestScheme)
	}
	return originPort == requestPort && strings.EqualFold(origin.Scheme, requestScheme)
}

func splitHostPortDefault(host, scheme string) (string, string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", defaultPortForScheme(scheme)
	}
	if strings.Contains(host, ":") {
		if name, port, err := net.SplitHostPort(host); err == nil {
			return strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(port)
		}
	}
	return strings.ToLower(host), defaultPortForScheme(scheme)
}

func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "https", "wss":
		return "443"
	default:
		return "80"
	}
}

func cloneNodeWSFrame(frame *nodeWSFrame) *nodeWSFrame {
	if frame == nil {
		return nil
	}
	cloned := *frame
	if len(frame.Body) > 0 {
		cloned.Body = append(json.RawMessage(nil), frame.Body...)
	}
	if len(frame.Headers) > 0 {
		cloned.Headers = make(map[string]string, len(frame.Headers))
		for key, value := range frame.Headers {
			cloned.Headers[key] = value
		}
	}
	if frame.Actor != nil {
		cloned.Actor = cloneActor(frame.Actor)
	}
	return &cloned
}

func writeNodeWSFrame(conn *websocket.Conn, frame nodeWSFrame) error {
	return writeNodeWSFrameWithTimeout(conn, frame, nodeWSWriteTimeout)
}

func writeNodeWSFrameWithTimeout(conn *websocket.Conn, frame nodeWSFrame, timeout time.Duration) error {
	if conn == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = nodeWSWriteTimeout
	}
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	defer func() {
		_ = conn.SetWriteDeadline(time.Time{})
	}()
	return conn.WriteJSON(frame)
}

func nodeWebSocketHandler(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		if state == nil || state.App == nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		actor := currentActor(c)
		if actor == nil || strings.TrimSpace(actor.Kind) == "" || actor.Kind == "anonymous" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webapi.ManagementErrorResponse{
				Error: webapi.ManagementErrorDetail{
					Code:    "unauthorized",
					Message: "unauthorized",
				},
			})
			return
		}

		upgrader := nodeWSUpgrader
		upgrader.CheckOrigin = func(r *http.Request) bool {
			return allowNodeWebSocketOriginWithConfig(state.CurrentConfig(), r)
		}
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		actorState := newNodeWSActorState(actor)
		subscriptions := newNodeWSSubscriptionRegistry()
		authRefresher := newNodeWSAuthRefresher(state, c, actor)

		cfg := state.CurrentConfig()
		nodeRoutes := webapi.NodeDirectRouteCatalog(cfg.Web.BaseURL)
		writeMu := sync.Mutex{}
		writeFrame := func(frame nodeWSFrame) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			return writeNodeWSFrame(conn, frame)
		}
		unregisterRealtime := registerNodeRealtimeInvalidationConn(state, conn, &writeMu)
		defer unregisterRealtime()
		hello := nodeWSFrame{
			Type:      "hello",
			NodeID:    state.App.NodeID,
			Schema:    webservice.NodeSchemaVersion,
			APIBase:   nodeRoutes.APIBase,
			Actor:     actorState.Current(),
			Timestamp: time.Now().Unix(),
		}
		hello.Body, _ = json.Marshal(nodeWSHelloBody(state, cfg, nodeWSInitialSyncFields(cfg, actor)))
		if err := writeFrame(hello); err != nil {
			return
		}
		sub := (*nodeEventSubscription)(nil)
		if state.NodeEvents != nil {
			sub = state.NodeEvents.Subscribe(actorState.Current())
			defer sub.Close()
		}
		refreshActor := func() (*webapi.Actor, error) {
			refreshedActor, err := authRefresher.Refresh(time.Now())
			if err != nil {
				return nil, err
			}
			current := actorState.Update(refreshedActor)
			if sub != nil {
				sub.SetActor(current)
			}
			return current, nil
		}
		done := make(chan struct{})
		var backgroundWG sync.WaitGroup
		if sub != nil {
			backgroundWG.Add(1)
			go func() {
				defer backgroundWG.Done()
				var lastSequence int64
				deliverEvent := func(event webapi.Event) bool {
					refreshedActor, err := refreshActor()
					if err != nil {
						_ = writeFrame(nodeWSRefreshAuthFailureFrame("", err))
						_ = conn.Close()
						return false
					}
					if state.NodeEvents != nil && !state.NodeEvents.allowsEvent(refreshedActor, event) {
						return true
					}
					lastSequence = event.Sequence
					body, _ := json.Marshal(event)
					if err := writeFrame(nodeWSFrame{
						Type:      "event",
						Body:      body,
						Timestamp: time.Now().Unix(),
					}); err != nil {
						_ = conn.Close()
						return false
					}
					for _, frame := range subscriptions.EventFrames(state, event) {
						if err := writeFrame(frame); err != nil {
							_ = conn.Close()
							return false
						}
					}
					return true
				}
				runNodeSubscriptionEventLoop(sub, done, deliverEvent, func() {
					if overflowSequence, overflowed := sub.OverflowSequence(); overflowed {
						if err := writeFrame(nodeEventResyncRequiredFrame(state, lastSequence, overflowSequence)); err != nil {
							_ = conn.Close()
						}
						_ = conn.Close()
					}
				})
			}()
		}
		defer func() {
			close(done)
			backgroundWG.Wait()
		}()

		for {
			var frame nodeWSFrame
			if err := conn.ReadJSON(&frame); err != nil {
				return
			}
			if _, err := refreshActor(); err != nil {
				_ = writeFrame(nodeWSRefreshAuthFailureFrame(frame.ID, err))
				return
			}
			switch strings.ToLower(strings.TrimSpace(frame.Type)) {
			case "ping":
				if err := writeFrame(newNodeWSPongFrame(frame.ID)); err != nil {
					return
				}
			case "request":
				response := dispatchNodeWSRequestWithBase(state, nodeWSDispatchBase{
					Context:       c.Request.Context(),
					Host:          c.Request.Host,
					RemoteAddr:    c.Request.RemoteAddr,
					ClientIP:      resolvedManagementClientIP(requestAPIContext(c), state),
					Metadata:      currentRequestMetadata(c),
					Resolver:      state.PermissionResolver(),
					Subscriptions: subscriptions,
				}, actorState.Current(), frame)
				if err := writeFrame(response); err != nil {
					return
				}
				maybeInvalidateRealtimeSessionsAfterConfigImport(state, frame, response)
			default:
				if err := writeFrame(newNodeWSErrorFrame(frame.ID, http.StatusBadRequest, "unsupported frame type")); err != nil {
					return
				}
			}
		}
	}
}

func nodeEventResyncRequiredFrame(state *State, lastSequence, overflowSequence int64) nodeWSFrame {
	body := map[string]interface{}{
		"reason":            "event_overflow",
		"resync_required":   true,
		"last_sequence":     lastSequence,
		"overflow_sequence": overflowSequence,
	}
	if state != nil && state.NodeEventLog != nil {
		logState := state.NodeEventLog.State()
		body["config_epoch"] = state.RuntimeIdentity().ConfigEpoch()
		body["changes_cursor"] = logState.Cursor
		body["changes_window"] = logState.MaxEntries
		if logState.OldestCursor > 0 {
			body["changes_oldest_cursor"] = logState.OldestCursor
		}
		if logState.HistoryMaxEntries > 0 {
			body["changes_durable"] = true
			body["changes_history_window"] = logState.HistoryMaxEntries
		}
		if logState.HistoryOldestCursor > 0 {
			body["changes_history_oldest_cursor"] = logState.HistoryOldestCursor
		}
	}
	return newNodeControlFrame("resync_required", http.StatusConflict, body)
}

func nodeWSHelloBody(state *State, cfg *servercfg.Snapshot, extra map[string]interface{}) map[string]interface{} {
	input := webservice.NodeDescriptorInput{Config: cfg, LiveOnlyEvents: webapi.NodeLiveOnlyEvents()}
	if state != nil {
		runtimeIdentity := state.RuntimeIdentity()
		eventLogState := state.NodeEventLog.State()
		input.BootID = runtimeIdentity.BootID()
		input.RuntimeStartedAt = runtimeIdentity.StartedAt()
		input.ConfigEpoch = runtimeIdentity.ConfigEpoch()
		input.ChangesCursor = eventLogState.Cursor
		input.ChangesOldestCursor = eventLogState.OldestCursor
		input.ChangesHistoryOldestCursor = eventLogState.HistoryOldestCursor
		input.ChangesWindow = eventLogState.MaxEntries
		input.ChangesHistoryWindow = eventLogState.HistoryMaxEntries
		input.BatchMaxItems = state.NodeBatchMaxItems
		if state.Idempotency != nil {
			input.IdempotencyTTLSeconds = int(state.Idempotency.TTL() / time.Second)
		}
	}
	return webservice.BuildNodeDescriptor(input).HelloBody(extra)
}

func nodeWSInitialSyncFields(cfg *servercfg.Snapshot, actor *webapi.Actor) map[string]interface{} {
	scope := nodeWSInitialSyncScope(actor)
	nodeRoutes := webapi.NodeDirectRouteCatalog(cfg.Web.BaseURL)
	routes := []string{nodeRoutes.OverviewURL(false)}
	completeConfig := false
	if scope == "full" {
		routes = []string{nodeRoutes.OverviewURL(true)}
		completeConfig = true
	}
	return map[string]interface{}{
		"initial_sync_required":        true,
		"initial_sync_scope":           scope,
		"initial_sync_routes":          routes,
		"initial_sync_complete_config": completeConfig,
	}
}

func nodeWSInitialSyncScope(actor *webapi.Actor) string {
	if actor == nil {
		return "user"
	}
	if actor.IsAdmin {
		return "full"
	}
	switch strings.TrimSpace(actor.Kind) {
	case "platform_admin":
		return "account"
	case "platform_user":
		return "user"
	case "user":
		return "user"
	default:
		return "user"
	}
}

type nodeWSSubscription struct {
	ID        int64 `json:"id"`
	CreatedAt int64 `json:"created_at,omitempty"`
	UpdatedAt int64 `json:"updated_at,omitempty"`
	nodeEventSinkConfig
}

type nodeWSSubscriptionWriteRequest struct {
	Name            string            `json:"name"`
	Enabled         *bool             `json:"enabled,omitempty"`
	EventNames      []string          `json:"event_names,omitempty"`
	Resources       []string          `json:"resources,omitempty"`
	Actions         []string          `json:"actions,omitempty"`
	UserIDs         []int             `json:"user_ids,omitempty"`
	ClientIDs       []int             `json:"client_ids,omitempty"`
	TunnelIDs       []int             `json:"tunnel_ids,omitempty"`
	HostIDs         []int             `json:"host_ids,omitempty"`
	ContentMode     string            `json:"content_mode,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	BodyTemplate    string            `json:"body_template,omitempty"`
	HeaderTemplates map[string]string `json:"header_templates,omitempty"`
}

type nodeWSSubscriptionStatusRequest struct {
	Enabled *bool `json:"enabled"`
}

type nodeWSSubscriptionListPayload struct {
	Timestamp int64                       `json:"timestamp"`
	Items     []nodeWSSubscriptionPayload `json:"items"`
}

type nodeWSSubscriptionMutationPayload struct {
	Timestamp int64                      `json:"timestamp"`
	Item      *nodeWSSubscriptionPayload `json:"item,omitempty"`
}

type nodeWSSubscriptionPayload struct {
	ID              int64             `json:"id"`
	Name            string            `json:"name,omitempty"`
	Enabled         bool              `json:"enabled"`
	EventNames      []string          `json:"event_names,omitempty"`
	Resources       []string          `json:"resources,omitempty"`
	Actions         []string          `json:"actions,omitempty"`
	UserIDs         []int             `json:"user_ids,omitempty"`
	ClientIDs       []int             `json:"client_ids,omitempty"`
	TunnelIDs       []int             `json:"tunnel_ids,omitempty"`
	HostIDs         []int             `json:"host_ids,omitempty"`
	ContentMode     string            `json:"content_mode,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	BodyTemplate    string            `json:"body_template,omitempty"`
	HeaderTemplates map[string]string `json:"header_templates,omitempty"`
	CreatedAt       int64             `json:"created_at,omitempty"`
	UpdatedAt       int64             `json:"updated_at,omitempty"`
}

type nodeWSSubscriptionRegistry struct {
	mu    sync.RWMutex
	next  int64
	items map[int64]nodeWSSubscription
}

type nodeWSSubscriptionScrubCandidate struct {
	id   int64
	item nodeWSSubscription
}

type nodeWSSubscriptionScrubPlan struct {
	id              int64
	selector        nodeEventSelector
	scrubbed        nodeEventSelector
	selectorChanged bool
	disable         bool
}

var (
	errNodeWSSubscriptionsUnavailable = errors.New("websocket subscriptions are unavailable")
	errNodeWSSubscriptionNotFound     = errors.New("subscription not found")
	errNodeWSSubscriptionInvalidID    = errors.New("invalid subscription id")
	errNodeWSSubscriptionEnabledReq   = errors.New("missing enabled")
	errNodeWSSubscriptionInvalidMode  = errors.New("invalid content_mode")
)

func newNodeWSSubscriptionRegistry() *nodeWSSubscriptionRegistry {
	return &nodeWSSubscriptionRegistry{items: make(map[int64]nodeWSSubscription)}
}

func (r *nodeWSSubscriptionRegistry) List() []nodeWSSubscriptionPayload {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]nodeWSSubscriptionPayload, 0, len(r.items))
	for _, item := range r.items {
		items = append(items, buildNodeWSSubscriptionPayload(item))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func (r *nodeWSSubscriptionRegistry) Get(id int64) (nodeWSSubscriptionPayload, bool) {
	if r == nil || id <= 0 {
		return nodeWSSubscriptionPayload{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.items[id]
	if !ok {
		return nodeWSSubscriptionPayload{}, false
	}
	return buildNodeWSSubscriptionPayload(item), true
}

func (r *nodeWSSubscriptionRegistry) Create(request nodeWSSubscriptionWriteRequest) (nodeWSSubscriptionPayload, error) {
	config, err := buildNodeWSSubscriptionConfig(0, nil, request)
	if err != nil {
		return nodeWSSubscriptionPayload{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	config.ID = r.next
	now := time.Now().Unix()
	config.CreatedAt = now
	config.UpdatedAt = now
	r.items[config.ID] = config
	return buildNodeWSSubscriptionPayload(config), nil
}

func (r *nodeWSSubscriptionRegistry) Update(id int64, request nodeWSSubscriptionWriteRequest) (nodeWSSubscriptionPayload, error) {
	if r == nil || id <= 0 {
		return nodeWSSubscriptionPayload{}, errNodeWSSubscriptionNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.items[id]
	if !ok {
		return nodeWSSubscriptionPayload{}, errNodeWSSubscriptionNotFound
	}
	config, err := buildNodeWSSubscriptionConfig(id, &current, request)
	if err != nil {
		return nodeWSSubscriptionPayload{}, err
	}
	config.CreatedAt = current.CreatedAt
	config.UpdatedAt = time.Now().Unix()
	r.items[id] = config
	return buildNodeWSSubscriptionPayload(config), nil
}

func (r *nodeWSSubscriptionRegistry) SetEnabled(id int64, enabled bool) (nodeWSSubscriptionPayload, error) {
	if r == nil || id <= 0 {
		return nodeWSSubscriptionPayload{}, errNodeWSSubscriptionNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.items[id]
	if !ok {
		return nodeWSSubscriptionPayload{}, errNodeWSSubscriptionNotFound
	}
	current.Enabled = enabled
	current.UpdatedAt = time.Now().Unix()
	r.items[id] = current
	return buildNodeWSSubscriptionPayload(current), nil
}

func (r *nodeWSSubscriptionRegistry) Delete(id int64) bool {
	if r == nil || id <= 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[id]; !ok {
		return false
	}
	delete(r.items, id)
	return true
}

func (r *nodeWSSubscriptionRegistry) EventFrames(state *State, event webapi.Event) []nodeWSFrame {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	current := make([]nodeWSSubscription, 0, len(r.items))
	for _, item := range r.items {
		current = append(current, item)
	}
	r.mu.RUnlock()
	frames := make([]nodeWSFrame, 0)
	for _, item := range current {
		if !item.Enabled || !matchesNodeEventSelector(item.Selector, event) {
			continue
		}
		payload, err := renderNodeEventSinkPayload(state, strconv.FormatInt(item.ID, 10), "ws_subscription", item.nodeEventSinkConfig, event)
		if err != nil {
			continue
		}
		frame := nodeWSFrame{
			ID:        strconv.FormatInt(item.ID, 10),
			Type:      "callback",
			Timestamp: time.Now().Unix(),
			Headers:   map[string]string{"X-Subscription-ID": strconv.FormatInt(item.ID, 10)},
		}
		for key, value := range payload.Headers {
			frame.Headers[key] = value
		}
		frame = buildNodeWSRenderedFrame(frame, payload)
		frames = append(frames, frame)
	}
	if nodeEventMayInvalidateSelectors(event) {
		r.scrubEvent(state, event)
	}
	return frames
}

func (r *nodeWSSubscriptionRegistry) scrubEvent(state *State, event webapi.Event) {
	if r == nil || state == nil {
		return
	}
	r.scrubWithLookup(buildNodeWebhookResourceLookup(state)())
}

func (r *nodeWSSubscriptionRegistry) scrubWithLookup(lookup nodeEventResourceLookup) {
	if r == nil {
		return
	}
	plans := buildNodeWSSubscriptionScrubPlans(r.snapshotScrubCandidates(), lookup)
	if len(plans) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, plan := range plans {
		r.applyScrubPlanLocked(plan)
	}
}

func (r *nodeWSSubscriptionRegistry) snapshotScrubCandidates() []nodeWSSubscriptionScrubCandidate {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	candidates := make([]nodeWSSubscriptionScrubCandidate, 0, len(r.items))
	for id, item := range r.items {
		candidates = append(candidates, nodeWSSubscriptionScrubCandidate{
			id:   id,
			item: item,
		})
	}
	return candidates
}

func buildNodeWSSubscriptionScrubPlans(candidates []nodeWSSubscriptionScrubCandidate, lookup nodeEventResourceLookup) []nodeWSSubscriptionScrubPlan {
	if len(candidates) == 0 {
		return nil
	}
	lookup = memoizeNodeEventResourceLookup(lookup)
	plans := make([]nodeWSSubscriptionScrubPlan, 0, len(candidates))
	for _, candidate := range candidates {
		scrubbed, disable := scrubNodeEventSelector(candidate.item.Selector, lookup)
		selectorChanged := !nodeEventSelectorEqual(candidate.item.Selector, scrubbed)
		if !selectorChanged && !disable {
			continue
		}
		plans = append(plans, nodeWSSubscriptionScrubPlan{
			id:              candidate.id,
			selector:        candidate.item.Selector,
			scrubbed:        scrubbed,
			selectorChanged: selectorChanged,
			disable:         disable,
		})
	}
	return plans
}

func (r *nodeWSSubscriptionRegistry) applyScrubPlanLocked(plan nodeWSSubscriptionScrubPlan) bool {
	if r == nil {
		return false
	}
	current, ok := r.items[plan.id]
	if !ok || !nodeEventSelectorEqual(current.Selector, plan.selector) {
		return false
	}
	if plan.disable {
		delete(r.items, plan.id)
		return true
	}
	if !plan.selectorChanged {
		return false
	}
	current.Selector = plan.scrubbed
	current.UpdatedAt = time.Now().Unix()
	r.items[plan.id] = current
	return true
}

func buildNodeWSSubscriptionConfig(id int64, current *nodeWSSubscription, request nodeWSSubscriptionWriteRequest) (nodeWSSubscription, error) {
	config := nodeWSSubscription{
		ID: id,
		nodeEventSinkConfig: nodeEventSinkConfig{
			Name: request.Name,
			Selector: nodeEventSelector{
				EventNames: request.EventNames,
				Resources:  request.Resources,
				Actions:    request.Actions,
				UserIDs:    request.UserIDs,
				ClientIDs:  request.ClientIDs,
				TunnelIDs:  request.TunnelIDs,
				HostIDs:    request.HostIDs,
			},
			ContentMode:     request.ContentMode,
			ContentType:     request.ContentType,
			BodyTemplate:    request.BodyTemplate,
			HeaderTemplates: cloneNodeHeaderTemplates(request.HeaderTemplates),
		},
	}
	if current != nil {
		config.Enabled = current.Enabled
		config.CreatedAt = current.CreatedAt
	}
	if request.Enabled != nil {
		config.Enabled = *request.Enabled
	}
	if current == nil && request.Enabled == nil {
		config.Enabled = true
	}
	var err error
	config.nodeEventSinkConfig, err = prepareNodeEventSinkConfig(config.nodeEventSinkConfig)
	if err != nil {
		return nodeWSSubscription{}, err
	}
	if config.ContentMode == "" {
		return nodeWSSubscription{}, errNodeWSSubscriptionInvalidMode
	}
	return config, nil
}

func buildNodeWSSubscriptionPayload(config nodeWSSubscription) nodeWSSubscriptionPayload {
	return nodeWSSubscriptionPayload{
		ID:              config.ID,
		Name:            config.Name,
		Enabled:         config.Enabled,
		EventNames:      append([]string(nil), config.Selector.EventNames...),
		Resources:       append([]string(nil), config.Selector.Resources...),
		Actions:         append([]string(nil), config.Selector.Actions...),
		UserIDs:         append([]int(nil), config.Selector.UserIDs...),
		ClientIDs:       append([]int(nil), config.Selector.ClientIDs...),
		TunnelIDs:       append([]int(nil), config.Selector.TunnelIDs...),
		HostIDs:         append([]int(nil), config.Selector.HostIDs...),
		ContentMode:     config.ContentMode,
		ContentType:     config.ContentType,
		BodyTemplate:    config.BodyTemplate,
		HeaderTemplates: cloneNodeHeaderTemplates(config.HeaderTemplates),
		CreatedAt:       config.CreatedAt,
		UpdatedAt:       config.UpdatedAt,
	}
}

func stampNodeWSSubscriptionResponseDataTimestamp(data interface{}, timestamp int64) interface{} {
	switch typed := data.(type) {
	case nodeWSSubscriptionListPayload:
		typed.Timestamp = timestamp
		return typed
	case *nodeWSSubscriptionListPayload:
		if typed == nil {
			return typed
		}
		cloned := *typed
		cloned.Timestamp = timestamp
		return &cloned
	case nodeWSSubscriptionMutationPayload:
		typed.Timestamp = timestamp
		return typed
	case *nodeWSSubscriptionMutationPayload:
		if typed == nil {
			return typed
		}
		cloned := *typed
		cloned.Timestamp = timestamp
		return &cloned
	default:
		return data
	}
}

func buildNodeWSRealtimeSubscriptionManagementDataFrame(frame nodeWSFrame, metadata webapi.RequestMetadata, configEpoch string, timestamp int64, data interface{}) nodeWSFrame {
	return buildNodeWSManagementDataFrame(frame, metadata, configEpoch, timestamp, stampNodeWSSubscriptionResponseDataTimestamp(data, timestamp))
}

func nodeWSSubscriptionErrorDetail(err error) (int, string, string) {
	if err == nil {
		return http.StatusOK, "", ""
	}
	message := strings.TrimSpace(err.Error())
	switch {
	case errors.Is(err, errNodeWSSubscriptionsUnavailable) || message == errNodeWSSubscriptionsUnavailable.Error():
		return http.StatusBadRequest, "realtime_subscriptions_unavailable", errNodeWSSubscriptionsUnavailable.Error()
	case errors.Is(err, errNodeWSSubscriptionNotFound) || message == errNodeWSSubscriptionNotFound.Error():
		return http.StatusNotFound, "subscription_not_found", errNodeWSSubscriptionNotFound.Error()
	case errors.Is(err, errNodeWSSubscriptionInvalidID) || message == errNodeWSSubscriptionInvalidID.Error():
		return http.StatusBadRequest, "invalid_subscription_id", errNodeWSSubscriptionInvalidID.Error()
	case errors.Is(err, errNodeWSSubscriptionEnabledReq) || message == errNodeWSSubscriptionEnabledReq.Error():
		return http.StatusBadRequest, "enabled_required", errNodeWSSubscriptionEnabledReq.Error()
	case errors.Is(err, errNodeWSSubscriptionInvalidMode) || message == errNodeWSSubscriptionInvalidMode.Error():
		return http.StatusBadRequest, "invalid_content_mode", errNodeWSSubscriptionInvalidMode.Error()
	case message == "invalid body_template":
		return http.StatusBadRequest, "invalid_body_template", message
	case strings.HasPrefix(message, "invalid header_templates"):
		return http.StatusBadRequest, "invalid_header_templates", message
	default:
		return http.StatusInternalServerError, "request_failed", message
	}
}

func writeWSSubscriptionError(ctx *wsAPIContext, err error) {
	status, code, message := nodeWSSubscriptionErrorDetail(err)
	writeWSManagementError(ctx, status, code, message, nil)
}

func dispatchNodeWSRealtimeSubscriptionCollectionRequest(registry *nodeWSSubscriptionRegistry, ctx *wsAPIContext, metadata webapi.RequestMetadata, configEpoch, method string, response nodeWSFrame) nodeWSFrame {
	if registry == nil {
		writeWSSubscriptionError(ctx, errNodeWSSubscriptionsUnavailable)
		return buildNodeWSResponseFrame(response, ctx)
	}
	handler, matched := resolveNodeWSManagedCollectionMethod(method, []nodeWSManagedCollectionMethodSpec{
		{
			method: http.MethodGet,
			handler: func() nodeWSFrame {
				timestamp := time.Now().Unix()
				return buildNodeWSRealtimeSubscriptionManagementDataFrame(response, metadata, configEpoch, timestamp, nodeWSSubscriptionListPayload{
					Items: registry.List(),
				})
			},
		},
		{
			method: http.MethodPost,
			handler: func() nodeWSFrame {
				var request nodeWSSubscriptionWriteRequest
				if !decodeCanonicalNodeWSBody(ctx, &request) {
					return buildNodeWSResponseFrame(response, ctx)
				}
				item, err := registry.Create(request)
				if err != nil {
					writeWSSubscriptionError(ctx, err)
					return buildNodeWSResponseFrame(response, ctx)
				}
				timestamp := time.Now().Unix()
				return buildNodeWSRealtimeSubscriptionManagementDataFrame(response, metadata, configEpoch, timestamp, nodeWSSubscriptionMutationPayload{
					Item: &item,
				})
			},
		},
	})
	if !matched {
		return buildNodeWSMethodNotAllowedManagementFrame(response, ctx)
	}
	return handler()
}

func dispatchNodeWSRealtimeSubscriptionItemRequest(registry *nodeWSSubscriptionRegistry, ctx *wsAPIContext, metadata webapi.RequestMetadata, configEpoch, method, path string, response nodeWSFrame) nodeWSFrame {
	if registry == nil {
		writeWSSubscriptionError(ctx, errNodeWSSubscriptionsUnavailable)
		return buildNodeWSResponseFrame(response, ctx)
	}
	request, err := resolveNodeWSManagedItemRequest(path, "/realtime/subscriptions/")
	if err != nil {
		if errors.Is(err, errNodeWSManagedItemInvalidID) {
			writeWSSubscriptionError(ctx, errNodeWSSubscriptionInvalidID)
			return buildNodeWSResponseFrame(response, ctx)
		}
		return buildNodeWSUnknownPathManagementFrame(response, ctx)
	}
	handler, pathMatched, methodMatched := resolveNodeWSManagedItemAction(request.Action, method, []nodeWSManagedItemActionSpec{
		{
			action: "",
			method: http.MethodGet,
			handler: func(request nodeWSManagedItemRequest) nodeWSFrame {
				item, ok := registry.Get(request.ID)
				if !ok {
					writeWSSubscriptionError(ctx, errNodeWSSubscriptionNotFound)
					return buildNodeWSResponseFrame(response, ctx)
				}
				timestamp := time.Now().Unix()
				return buildNodeWSRealtimeSubscriptionManagementDataFrame(response, metadata, configEpoch, timestamp, nodeWSSubscriptionMutationPayload{
					Item: &item,
				})
			},
		},
		{
			action: "update",
			method: http.MethodPost,
			handler: func(request nodeWSManagedItemRequest) nodeWSFrame {
				var update nodeWSSubscriptionWriteRequest
				if !decodeCanonicalNodeWSBody(ctx, &update) {
					return buildNodeWSResponseFrame(response, ctx)
				}
				item, err := registry.Update(request.ID, update)
				if err != nil {
					writeWSSubscriptionError(ctx, err)
					return buildNodeWSResponseFrame(response, ctx)
				}
				timestamp := time.Now().Unix()
				return buildNodeWSRealtimeSubscriptionManagementDataFrame(response, metadata, configEpoch, timestamp, nodeWSSubscriptionMutationPayload{
					Item: &item,
				})
			},
		},
		{
			action: "status",
			method: http.MethodPost,
			handler: func(request nodeWSManagedItemRequest) nodeWSFrame {
				var statusRequest nodeWSSubscriptionStatusRequest
				if !decodeCanonicalNodeWSBody(ctx, &statusRequest) {
					return buildNodeWSResponseFrame(response, ctx)
				}
				if statusRequest.Enabled == nil {
					writeWSSubscriptionError(ctx, errNodeWSSubscriptionEnabledReq)
					return buildNodeWSResponseFrame(response, ctx)
				}
				item, err := registry.SetEnabled(request.ID, *statusRequest.Enabled)
				if err != nil {
					writeWSSubscriptionError(ctx, err)
					return buildNodeWSResponseFrame(response, ctx)
				}
				timestamp := time.Now().Unix()
				return buildNodeWSRealtimeSubscriptionManagementDataFrame(response, metadata, configEpoch, timestamp, nodeWSSubscriptionMutationPayload{
					Item: &item,
				})
			},
		},
		{
			action: "delete",
			method: http.MethodPost,
			handler: func(request nodeWSManagedItemRequest) nodeWSFrame {
				if !registry.Delete(request.ID) {
					writeWSSubscriptionError(ctx, errNodeWSSubscriptionNotFound)
					return buildNodeWSResponseFrame(response, ctx)
				}
				timestamp := time.Now().Unix()
				return buildNodeWSRealtimeSubscriptionManagementDataFrame(response, metadata, configEpoch, timestamp, nodeWSSubscriptionMutationPayload{})
			},
		},
	})
	switch {
	case !pathMatched:
		return buildNodeWSUnknownPathManagementFrame(response, ctx)
	case !methodMatched:
		return buildNodeWSMethodNotAllowedManagementFrame(response, ctx)
	default:
		return handler(request)
	}
}

func buildNodeWSRenderedFrame(frame nodeWSFrame, payload nodeRenderedEventSinkPayload) nodeWSFrame {
	frame.Headers["Content-Type"] = payload.ContentType
	switch payload.BodyMode {
	case wsResponseBodyModeJSON:
		frame.Body = payload.Body
		return frame
	case wsResponseBodyModeText:
		frame.Body = marshalNodeWSTextFrameBody(payload.Body)
		frame.Encoding = "text"
		return frame
	}
	if isWSJSONContentType(payload.ContentType) && json.Valid(payload.Body) {
		frame.Body = payload.Body
		return frame
	}
	frame.Body = marshalNodeWSTextFrameBody(payload.Body)
	frame.Encoding = "text"
	return frame
}

type nodeReverseHelloRequest struct {
	LastBootID   string `json:"last_boot_id,omitempty"`
	ChangesAfter int64  `json:"changes_after,omitempty"`
	ChangesLimit int    `json:"changes_limit,omitempty"`
}

type nodeReverseHelloAck struct {
	BootID                    string               `json:"boot_id"`
	RuntimeStartedAt          int64                `json:"runtime_started_at"`
	ConfigEpoch               string               `json:"config_epoch,omitempty"`
	ResyncRequired            bool                 `json:"resync_required"`
	Reason                    string               `json:"reason,omitempty"`
	InitialSyncRequired       bool                 `json:"initial_sync_required"`
	InitialSyncScope          string               `json:"initial_sync_scope,omitempty"`
	InitialSyncRoutes         []string             `json:"initial_sync_routes,omitempty"`
	InitialSyncCompleteConfig bool                 `json:"initial_sync_complete_config"`
	Replay                    nodeEventLogSnapshot `json:"replay"`
}

const nodeReverseHelloGracePeriod = 5 * time.Second

const (
	nodeReverseInitialBackoff = time.Second
	nodeReverseMaxBackoff     = 15 * time.Second
)

type nodeReverseManager struct {
	state  *State
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	connMu sync.Mutex
	conns  map[*websocket.Conn]struct{}
}

func newNodeReverseManager(state *State) *nodeReverseManager {
	parent := context.Background()
	if state != nil {
		parent = state.BaseContext()
	}
	ctx, cancel := context.WithCancel(parent)
	return &nodeReverseManager{
		state:  state,
		ctx:    ctx,
		cancel: cancel,
		conns:  make(map[*websocket.Conn]struct{}),
	}
}

func StartNodeReverseConnectors(state *State) func() {
	if state == nil {
		return func() {}
	}
	platforms := state.CurrentConfig().Runtime.EnabledReverseManagementPlatforms()
	if len(platforms) == 0 {
		return func() {}
	}
	manager := newNodeReverseManager(state)
	runtimeStatus := ensureNodeManagementPlatformRuntimeStore(state)
	for _, platform := range platforms {
		runtimeStatus.NoteConfigured(platform.PlatformID, platform.ConnectMode, platform.ReverseWSURL, platform.ReverseEnabled)
		manager.wg.Add(1)
		go manager.runPlatform(platform)
	}
	return func() {
		manager.cancel()
		manager.closeAllConns()
		manager.wg.Wait()
	}
}

func (m *nodeReverseManager) runPlatform(platform servercfg.ManagementPlatformConfig) {
	defer m.wg.Done()
	backoff := nodeReverseInitialBackoff
	for {
		select {
		case <-m.ctx.Done():
			m.runtimeStatus().NoteReverseDisconnected(platform.PlatformID, nil)
			return
		default:
		}
		connected, err := m.connectAndServe(platform)
		if err != nil {
			m.runtimeStatus().NoteReverseDisconnected(platform.PlatformID, err)
			logs.Warn("node reverse ws for platform %s stopped: %v", platform.PlatformID, err)
		}
		delay, nextBackoff := nodeReverseRetryDelay(backoff, connected)
		if !waitNodeDelay(m.ctx, delay) {
			return
		}
		backoff = nextBackoff
	}
}

func nodeReverseRetryDelay(backoff time.Duration, connected bool) (time.Duration, time.Duration) {
	if backoff < nodeReverseInitialBackoff {
		backoff = nodeReverseInitialBackoff
	}
	if connected {
		return nodeReverseInitialBackoff, nodeReverseInitialBackoff
	}
	return backoff, nextNodeReverseBackoff(backoff)
}

func nextNodeReverseBackoff(backoff time.Duration) time.Duration {
	if backoff < nodeReverseInitialBackoff {
		return nodeReverseInitialBackoff
	}
	if backoff >= nodeReverseMaxBackoff {
		return nodeReverseMaxBackoff
	}
	backoff *= 2
	if backoff > nodeReverseMaxBackoff {
		return nodeReverseMaxBackoff
	}
	return backoff
}

func (m *nodeReverseManager) connectAndServe(platform servercfg.ManagementPlatformConfig) (bool, error) {
	serviceUser, err := ensurePlatformServiceUser(m.state, platform)
	if err != nil {
		return false, err
	}
	if serviceUser == nil || serviceUser.Id <= 0 {
		return false, nil
	}
	headers := http.Header{}
	headers.Set("X-Node-Token", platform.Token)
	headers.Set("X-Node-ID", m.state.App.NodeID)
	headers.Set("X-Platform-ID", platform.PlatformID)
	headers.Set("X-Node-Schema-Version", strconv.Itoa(webservice.NodeSchemaVersion))
	headers.Set("X-Node-Connect-Mode", "reverse")
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
	}
	conn, _, err := dialer.DialContext(m.ctx, platform.ReverseWSURL, headers)
	if err != nil {
		return false, err
	}
	m.registerConn(conn)
	defer func() { _ = conn.Close() }()
	defer m.unregisterConn(conn)

	m.runtimeStatus().NoteReverseConnected(platform.PlatformID)
	return true, m.serveConn(platform, serviceUser.Id, conn)
}

func (m *nodeReverseManager) registerConn(conn *websocket.Conn) {
	if m == nil || conn == nil {
		return
	}
	m.connMu.Lock()
	defer m.connMu.Unlock()
	m.conns[conn] = struct{}{}
}

func (m *nodeReverseManager) unregisterConn(conn *websocket.Conn) {
	if m == nil || conn == nil {
		return
	}
	m.connMu.Lock()
	defer m.connMu.Unlock()
	delete(m.conns, conn)
}

func (m *nodeReverseManager) closeAllConns() {
	if m == nil {
		return
	}
	m.connMu.Lock()
	conns := make([]*websocket.Conn, 0, len(m.conns))
	for conn := range m.conns {
		conns = append(conns, conn)
	}
	m.connMu.Unlock()
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func (m *nodeReverseManager) serveConn(platform servercfg.ManagementPlatformConfig, serviceUserID int, conn *websocket.Conn) error {
	subActor, err := fixedPlatformAdminActor(platform, serviceUserID, "reverse", "reverse:"+platform.PlatformID, func() ([]int, error) {
		return platformOwnedClientIDs(m.state, serviceUserID)
	})
	if err != nil {
		return err
	}
	sub := (*nodeEventSubscription)(nil)
	if m.state.NodeEvents != nil {
		sub = m.state.NodeEvents.Subscribe(subActor)
		defer sub.Close()
	}
	writeMu := sync.Mutex{}
	writeFrame := func(frame nodeWSFrame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeNodeWSFrame(conn, frame)
	}
	closeConn := func() { _ = conn.Close() }
	unregisterRealtime := registerNodeRealtimeInvalidationConn(m.state, conn, &writeMu)
	defer unregisterRealtime()
	if err := writeFrame(m.reverseHelloFrame(platform, subActor)); err != nil {
		return err
	}
	runtimeStatus := m.runtimeStatus()
	runtimeStatus.NoteReverseHello(platform.PlatformID)

	done := make(chan struct{})
	var backgroundWG sync.WaitGroup
	defer func() {
		close(done)
		backgroundWG.Wait()
	}()
	eventsReady := make(chan struct{})
	var activateEventsOnce sync.Once
	var helloWindowClosed int32
	var skipUntilSequence int64
	activateEvents := func() {
		activateEventsOnce.Do(func() {
			close(eventsReady)
		})
	}
	closeHelloWindow := func() {
		atomic.StoreInt32(&helloWindowClosed, 1)
	}
	if sub != nil {
		backgroundWG.Add(1)
		go func() {
			defer backgroundWG.Done()
			select {
			case <-eventsReady:
			case <-done:
				return
			}
			var lastSequence int64
			deliverEvent := func(event webapi.Event) bool {
				if event.Sequence <= atomic.LoadInt64(&skipUntilSequence) {
					return true
				}
				lastSequence = event.Sequence
				closeHelloWindow()
				return deliverNodeReverseEvent(platform.PlatformID, runtimeStatus, event, writeFrame, closeConn)
			}
			runNodeSubscriptionEventLoop(sub, done, deliverEvent, func() {
				if overflowSequence, overflowed := sub.OverflowSequence(); overflowed {
					closeHelloWindow()
					_ = writeFrame(nodeEventResyncRequiredFrame(m.state, lastSequence, overflowSequence))
					closeConn()
				}
			})
		}()
	}
	backgroundWG.Add(1)
	go func(interval int) {
		defer backgroundWG.Done()
		runNodeReverseKeepaliveLoop(
			done,
			platform.PlatformID,
			interval,
			runtimeStatus,
			activateEvents,
			writeFrame,
			closeConn,
		)
	}(platform.ReverseHeartbeatSeconds)

	// Periodic full tunnel state reporting (60s)
	backgroundWG.Add(1)
	go func() {
		defer backgroundWG.Done()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				report := buildTunnelFullReportFrame(m.state, platform.PlatformID)
				if report != nil {
					_ = writeFrame(*report)
				}
			}
		}
	}()

	reverseHost := reverseWSHost(platform.ReverseWSURL)
	base := nodeWSDispatchBase{
		Context:    m.ctx,
		Host:       reverseHost,
		RemoteAddr: reverseHost,
		Resolver:   m.state.PermissionResolver(),
		Metadata: webapi.RequestMetadata{
			Source: "reverse-ws",
		},
	}
	for {
		var frame nodeWSFrame
		if err := conn.ReadJSON(&frame); err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(frame.Type)) {
		case "hello":
			if atomic.LoadInt32(&helloWindowClosed) != 0 {
				if err := writeFrame(newNodeWSErrorFrame(frame.ID, http.StatusConflict, "reverse hello is only supported before realtime traffic starts")); err != nil {
					return err
				}
				continue
			}
			ack, replayCursor, err := m.handleReverseHello(platform, serviceUserID, frame)
			if err != nil {
				if err := writeFrame(newNodeWSErrorFrame(frame.ID, http.StatusBadRequest, err.Error())); err != nil {
					return err
				}
				continue
			}
			atomic.StoreInt64(&skipUntilSequence, replayCursor)
			if err := writeFrame(ack); err != nil {
				return err
			}
		case "ping":
			closeHelloWindow()
			activateEvents()
			if err := writeFrame(newNodeWSPongFrame(frame.ID)); err != nil {
				return err
			}
		case "pong":
			closeHelloWindow()
			activateEvents()
			runtimeStatus.NoteReversePong(platform.PlatformID)
		case "request":
			closeHelloWindow()
			activateEvents()
			actor, actorErr := reversePlatformActor(m.state, platform, serviceUserID, frame.Headers)
			if actorErr != nil {
				ctx, ctxErr := newWSAPIContextFromBase(base, nil, frame)
				if ctxErr != nil {
					return ctxErr
				}
				response := buildNodeWSManagementErrorFrame(nodeWSFrame{
					ID:        frame.ID,
					Type:      "response",
					Timestamp: time.Now().Unix(),
				}, ctx, http.StatusInternalServerError, "request_failed", actorErr.Error(), nil)
				if err := writeFrame(response); err != nil {
					return err
				}
				break
			}
			response := dispatchNodeWSRequestWithBase(
				m.state,
				base,
				actor,
				frame,
			)
			if err := writeFrame(response); err != nil {
				return err
			}
			maybeInvalidateRealtimeSessionsAfterConfigImport(m.state, frame, response)
		default:
			closeHelloWindow()
			activateEvents()
			if err := writeFrame(newNodeWSErrorFrame(frame.ID, http.StatusBadRequest, "unsupported frame type")); err != nil {
				return err
			}
		}
	}
}

func runNodeReverseKeepaliveLoop(done <-chan struct{}, platformID string, interval int, runtimeStatus webservice.ManagementPlatformRuntimeStatusStore, activateEvents func(), writeFrame func(nodeWSFrame) error, closeConn func()) {
	if interval <= 0 {
		interval = 30
	}
	heartbeatInterval := time.Duration(interval) * time.Second
	graceTimer := time.NewTimer(nodeReverseHelloGracePeriod)
	defer graceTimer.Stop()
	heartbeatTimer := time.NewTimer(heartbeatInterval)
	defer heartbeatTimer.Stop()

	var graceC <-chan time.Time = graceTimer.C
	for {
		select {
		case <-done:
			return
		case <-graceC:
			activateEvents()
			graceC = nil
		case <-heartbeatTimer.C:
			frame := nodeWSFrame{
				ID:        "ping-" + strconvFormatInt(time.Now().UnixNano()),
				Type:      "ping",
				Timestamp: time.Now().Unix(),
			}
			if err := writeFrame(frame); err != nil {
				if closeConn != nil {
					closeConn()
				}
				return
			}
			if runtimeStatus != nil {
				runtimeStatus.NoteReversePing(platformID)
			}
			heartbeatTimer.Reset(heartbeatInterval)
		}
	}
}

func (m *nodeReverseManager) handleReverseHello(platform servercfg.ManagementPlatformConfig, serviceUserID int, frame nodeWSFrame) (nodeWSFrame, int64, error) {
	req := nodeReverseHelloRequest{}
	if len(frame.Body) > 0 {
		if err := json.Unmarshal(frame.Body, &req); err != nil {
			return nodeWSFrame{}, 0, err
		}
	}
	actor, err := reversePlatformActor(m.state, platform, serviceUserID, frame.Headers)
	if err != nil {
		return nodeWSFrame{}, 0, err
	}
	replay := queryNodeChangesRequest(m.state, actor, nodeChangesQueryRequest{
		After:   req.ChangesAfter,
		Limit:   req.ChangesLimit,
		Durable: true,
	})
	descriptor := webservice.BuildNodeDescriptor(webservice.NodeDescriptorInput{
		NodeID:           m.state.App.NodeID,
		Config:           m.state.CurrentConfig(),
		BootID:           m.state.RuntimeIdentity().BootID(),
		RuntimeStartedAt: m.state.RuntimeIdentity().StartedAt(),
		ConfigEpoch:      m.state.RuntimeIdentity().ConfigEpoch(),
	})
	ack := nodeReverseHelloAck{
		BootID:           descriptor.BootID,
		RuntimeStartedAt: descriptor.RuntimeStartedAt,
		ConfigEpoch:      descriptor.ConfigEpoch,
		Replay:           replay,
	}
	initialSync := nodeWSInitialSyncFields(m.state.CurrentConfig(), actor)
	ack.InitialSyncRequired, _ = initialSync["initial_sync_required"].(bool)
	ack.InitialSyncScope, _ = initialSync["initial_sync_scope"].(string)
	ack.InitialSyncCompleteConfig, _ = initialSync["initial_sync_complete_config"].(bool)
	if routes, ok := initialSync["initial_sync_routes"].([]string); ok {
		ack.InitialSyncRoutes = append([]string(nil), routes...)
	}
	lastBootID := strings.TrimSpace(req.LastBootID)
	switch {
	case lastBootID == "":
		ack.ResyncRequired = true
		ack.Reason = "missing_boot_id"
	case lastBootID != ack.BootID:
		ack.ResyncRequired = true
		ack.Reason = "boot_changed"
	case replay.Gap:
		ack.ResyncRequired = true
		ack.Reason = "changes_gap"
	}
	body, _ := json.Marshal(ack)
	return nodeWSFrame{
		ID:        frame.ID,
		Type:      "hello_ack",
		Timestamp: time.Now().Unix(),
		Body:      body,
	}, replay.Cursor, nil
}

func (m *nodeReverseManager) reverseHelloFrame(platform servercfg.ManagementPlatformConfig, actor *webapi.Actor) nodeWSFrame {
	cfg := m.state.CurrentConfig()
	nodeRoutes := webapi.NodeDirectRouteCatalog(cfg.Web.BaseURL)
	extra := nodeWSInitialSyncFields(cfg, actor)
	extra["platform_id"] = platform.PlatformID
	extra["connect_mode"] = "reverse"
	body, _ := json.Marshal(nodeWSHelloBody(m.state, cfg, extra))
	return nodeWSFrame{
		Type:      "hello",
		NodeID:    m.state.App.NodeID,
		Schema:    webservice.NodeSchemaVersion,
		APIBase:   nodeRoutes.APIBase,
		Actor:     cloneActor(actor),
		Timestamp: time.Now().Unix(),
		Body:      body,
	}
}

func reversePlatformActor(state *State, platform servercfg.ManagementPlatformConfig, serviceUserID int, headers map[string]string) (*webapi.Actor, error) {
	return platformActorFromLookup(platform, serviceUserID, func() ([]int, error) {
		return platformOwnedClientIDs(state, serviceUserID)
	}, func(key string) string {
		if len(headers) == 0 {
			return ""
		}
		if value, ok := headers[key]; ok {
			return value
		}
		return headers[strings.ToLower(strings.TrimSpace(key))]
	})
}

func reverseWSHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return parsed.Host
}

func strconvFormatInt(value int64) string {
	return strconv.FormatInt(value, 10)
}

func (m *nodeReverseManager) runtimeStatus() webservice.ManagementPlatformRuntimeStatusStore {
	if m != nil && m.state != nil {
		return ensureNodeManagementPlatformRuntimeStore(m.state)
	}
	return webservice.NewInMemoryManagementPlatformRuntimeStatusStore()
}


// buildTunnelFullReportFrame collects all tunnels and builds a WS event frame.
func buildTunnelFullReportFrame(state *State, platformID string) *nodeWSFrame {
	if state == nil {
		return nil
	}
	allTunnels, _ := server.GetTunnel(0, 99999, "", 0, "", "", "")
	if len(allTunnels) == 0 {
		return nil
	}
	tunnelSnapshots := make([]map[string]interface{}, 0, len(allTunnels))
	for _, t := range allTunnels {
		targetAddr := ""
		if t.Target != nil {
			targetAddr = t.Target.TargetStr
		}
		snap := map[string]interface{}{
			"id":          t.Id,
			"port":        t.Port,
			"mode":        t.Mode,
			"status":      t.Status,
			"run_status":  t.RunStatus,
			"remark":      t.Remark,
			"target":      targetAddr,
			"target_type": t.TargetType,
			"now_conn":    t.NowConn,
			"max_conn":    t.MaxConn,
			"expire_at":   t.ExpireAt,
			"rate_limit":  t.RateLimit,
		}
		if t.Client != nil {
			snap["client_id"] = t.Client.Id
		}
		if t.Flow != nil {
			snap["flow_in"] = t.Flow.InletFlow
			snap["flow_out"] = t.Flow.ExportFlow
			snap["flow_limit"] = t.Flow.FlowLimit
		}
		if t.ServiceTraffic != nil {
			snap["service_traffic_in"] = t.ServiceTraffic.InletBytes
			snap["service_traffic_out"] = t.ServiceTraffic.ExportBytes
		}
		tunnelSnapshots = append(tunnelSnapshots, snap)
	}

	event := webapi.Event{
		Name:     "tunnel.full_report",
		Resource: "tunnel",
		Action:   "report",
		Fields: map[string]interface{}{
			"platform_id": platformID,
			"tunnels":     tunnelSnapshots,
			"reported_at": time.Now().Unix(),
			"count":       len(tunnelSnapshots),
		},
	}
	body, err := json.Marshal(event)
	if err != nil {
		logs.Warn("[rev-ws] failed to marshal tunnel full report: %v", err)
		return nil
	}
	frame := &nodeWSFrame{
		Type:      "event",
		ID:        "tunnel-report-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		Timestamp: time.Now().Unix(),
		Body:      body,
	}
	return frame
}
