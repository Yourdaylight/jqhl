package routers

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/servercfg"
	webapi "github.com/djylb/nps/web/api"
	"github.com/djylb/nps/web/framework"
	webservice "github.com/djylb/nps/web/service"
	"github.com/gin-gonic/gin"
)

type Runtime struct {
	Handler http.Handler
	State   *State
	Stop    func()
	Err     error
}

var initSessionStore = framework.InitSessionStore

var (
	activeManagedRuntimeMu sync.Mutex
	activeManagedRuntime   *Runtime
)

const nodePlatformContextKey = "nps.node.platform"

type nodePlatformContext struct {
	Config        servercfg.ManagementPlatformConfig
	ServiceUserID int
}

const (
	standaloneCORSAllowedMethods = "GET, POST, OPTIONS"
	standaloneCORSAllowedHeaders = "Authorization, Content-Type, Idempotency-Key, X-Idempotency-Key, X-Node-Token, X-Operation-ID, X-Request-ID, X-Correlation-ID, X-NPS-Source"
	standaloneCORSExposedHeaders = "X-Request-ID, X-Operation-ID, X-Idempotent-Replay"
)

func Init() http.Handler {
	return NewRuntime(nil).Handler
}

func InitNode() http.Handler {
	state := NewState(nil)
	engine := gin.New()
	engine.RedirectTrailingSlash = false
	engine.RedirectFixedPath = false
	engine.HandleMethodNotAllowed = false
	engine.Use(gin.Recovery())
	engine.NoRoute(func(c *gin.Context) {
		c.AbortWithStatus(http.StatusNotFound)
	})
	engine.NoMethod(func(c *gin.Context) {
		c.AbortWithStatus(http.StatusMethodNotAllowed)
	})
	registerNodeRoutes(engine, state)
	return engine
}

func NewRuntime(cfg *servercfg.Snapshot) *Runtime {
	state := NewState(cfg)
	handler, err := buildEngineWithError(state)
	if err != nil {
		logs.Error("initialize web runtime error %v", err)
	}
	return &Runtime{
		Handler: handler,
		State:   state,
		Stop:    state.Close,
		Err:     err,
	}
}

func NewManagedRuntime(cfg *servercfg.Snapshot) *Runtime {
	runtime := NewRuntime(cfg)
	if runtime.Err != nil {
		return runtime
	}
	baseStop := runtime.Stop
	reverseStop := StartNodeReverseConnectors(runtime.State)
	callbackStop := StartNodeCallbackDispatchers(runtime.State)
	webhookStop := StartNodeWebhookDispatchers(runtime.State)
	runtime.Stop = wrapManagedRuntimeStop(webhookStop, callbackStop, reverseStop, baseStop)
	return runtime
}

func ReplaceManagedRuntime(cfg *servercfg.Snapshot) *Runtime {
	runtime := NewManagedRuntime(cfg)
	if runtime != nil && runtime.Err != nil {
		if runtime.Stop != nil {
			runtime.Stop()
		}
		return runtime
	}
	activeManagedRuntimeMu.Lock()
	previous := activeManagedRuntime
	activeManagedRuntime = runtime
	activeManagedRuntimeMu.Unlock()
	if previous != nil && previous.Stop != nil {
		previous.Stop()
	}
	return runtime
}

func StopManagedRuntime() {
	activeManagedRuntimeMu.Lock()
	current := activeManagedRuntime
	activeManagedRuntime = nil
	activeManagedRuntimeMu.Unlock()
	if current != nil && current.Stop != nil {
		current.Stop()
	}
}

func wrapManagedRuntimeStop(stops ...func()) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			for _, stop := range stops {
				if stop != nil {
					stop()
				}
			}
		})
	}
}

func buildEngine(state *State) http.Handler {
	handler, _ := buildEngineWithError(state)
	return handler
}

func buildEngineWithError(state *State) (http.Handler, error) {
	cfg := state.CurrentConfig()
	basePath := servercfg.NormalizeBaseURL(cfg.Web.BaseURL)

	framework.SetSessionConfigProvider(state.CurrentConfig)
	if err := initSessionStore(cfg); err != nil {
		return startupErrorHandler(), fmt.Errorf("init session store: %w", err)
	}

	engine := gin.New()
	engine.RedirectTrailingSlash = false
	engine.RedirectFixedPath = false
	engine.HandleMethodNotAllowed = false
	engine.Use(gin.Recovery())
	engine.Use(standaloneCORSMiddleware(state))
	engine.NoRoute(unknownRouteHandler(cfg.Web.CloseOnNotFound))
	engine.NoMethod(unknownRouteHandler(cfg.Web.CloseOnNotFound))

	engine.Static(joinBase(basePath, "/static"), filepath.Join(common.GetRunPath(), "web", "static"))
	registerNodeRoutes(engine, state)
	registerLegacyCompatRoutes(engine, state)

	group := engine.Group(basePath)
	group.Use(sessionMiddleware())
	group.Use(requestContextMiddleware(state))
	group.GET("/captcha/new", framework.CaptchaNewHandler(basePath))
	group.GET("/captcha/:id", framework.CaptchaImageHandler())
	registerSessionRoutes(group, state)

	return engine, nil
}

func startupErrorHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "management runtime initialization failed", http.StatusInternalServerError)
	})
}

func unknownRouteHandler(closeOnNotFound bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if closeOnNotFound && dropConnection(c) {
			c.Abort()
			return
		}
		c.AbortWithStatus(http.StatusNotFound)
	}
}

func dropConnection(c *gin.Context) bool {
	if c == nil || c.Writer == nil || c.Writer.Written() {
		return false
	}
	unwrapper, ok := c.Writer.(interface{ Unwrap() http.ResponseWriter })
	if !ok {
		return false
	}
	hijacker, ok := unwrapper.Unwrap().(http.Hijacker)
	if !ok {
		return false
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func registerSessionRoutes(group *gin.RouterGroup, state *State) {
	group.GET("/api/system/discovery", optionalNodeDiscoveryAccessMiddleware(state), handle(state.App.ManagementDiscovery))
	registerSessionActionRoutes(group, state, state.SessionActions)
}

func registerSessionActionRoutes(group *gin.RouterGroup, state *State, specs []webapi.ActionSpec) {
	for _, spec := range specs {
		handlers := appendActionHandler(actionRouteMiddlewares(state, spec), handle(spec.Handler))
		registerActionRoute(group, spec.Method, sessionActionRelativePath(spec.Path), handlers)
	}
}

func actionRouteMiddlewares(state *State, spec webapi.ActionSpec) []gin.HandlerFunc {
	middlewares := make([]gin.HandlerFunc, 0, 3)
	if strings.HasPrefix(spec.Path, "/api/") {
		middlewares = append(middlewares, managementNoStoreMiddleware())
	}
	if spec.Method == http.MethodPost && (strings.HasPrefix(spec.Path, "/api/auth/") || spec.Path == "/api/access/ip-limit/actions/register") {
		middlewares = append(middlewares, loginBodyLimitMiddleware(state))
		middlewares = append(middlewares, apiInputMiddleware())
	}
	if spec.Protected && (strings.TrimSpace(spec.Permission) != "" || spec.ClientScope || spec.Ownership != webapi.ActionOwnershipNone) {
		middlewares = append(middlewares, protectedActionAccessMiddleware(state, spec))
		return middlewares
	}
	if permission := strings.TrimSpace(spec.Permission); permission != "" {
		middlewares = append(middlewares, permissionMiddleware(state, permission))
	}
	if spec.ClientScope {
		middlewares = append(middlewares, clientScopeMiddleware(state))
	}
	switch spec.Ownership {
	case webapi.ActionOwnershipClient:
		middlewares = append(middlewares, clientOwnershipMiddleware(state))
	case webapi.ActionOwnershipTunnel:
		middlewares = append(middlewares, tunnelOwnershipMiddleware(state))
	case webapi.ActionOwnershipHost:
		middlewares = append(middlewares, hostOwnershipMiddleware(state))
	}
	return middlewares
}

func loginBodyLimitMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request == nil || c.Request.Body == nil {
			c.Next()
			return
		}

		maxBody := int64(0)
		if state != nil {
			maxBody = state.LoginPolicy().Settings().MaxLoginBody
		}
		if maxBody <= 0 {
			c.Next()
			return
		}

		if c.Request.ContentLength > maxBody {
			abortRequestEntityTooLarge(c)
			return
		}

		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBody)
		contentType := strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Type")))
		if c.Request.Method == http.MethodPost &&
			(strings.HasPrefix(contentType, "application/x-www-form-urlencoded") ||
				strings.HasPrefix(contentType, "multipart/form-data")) {
			if err := c.Request.ParseForm(); err != nil {
				if strings.Contains(err.Error(), "http: request body too large") {
					abortRequestEntityTooLarge(c)
					return
				}
				c.AbortWithStatusJSON(http.StatusBadRequest, webapi.ManagementErrorResponse{
					Error: webapi.ManagementErrorDetail{
						Code:    "invalid_json_body",
						Message: "invalid json body",
					},
				})
				return
			}
		}

		c.Next()
	}
}

func registerActionRoute(group *gin.RouterGroup, method, path string, handlers []gin.HandlerFunc) {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet:
		group.GET(path, handlers...)
	case http.MethodPost:
		group.POST(path, handlers...)
	default:
		group.Handle(method, path, handlers...)
	}
}

func appendActionHandler(middlewares []gin.HandlerFunc, handler gin.HandlerFunc) []gin.HandlerFunc {
	handlers := make([]gin.HandlerFunc, 0, len(middlewares)+1)
	handlers = append(handlers, middlewares...)
	handlers = append(handlers, handler)
	return handlers
}

func sessionActionRelativePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func registerNodeRoutes(engine *gin.Engine, state *State) {
	if engine == nil || state == nil || !nodeRoutesEnabled(state.CurrentConfig()) {
		return
	}
	basePath := servercfg.NormalizeBaseURL(state.CurrentConfig().Web.BaseURL)
	group := engine.Group(basePath)
	group.Use(sessionMiddleware(), nodeRequestContextMiddleware(state))
	runtimeGroup := subgroup(group, "/api", managementNoStoreMiddleware(), apiInputMiddleware(), nodeAccessMiddleware(state), nodeIdempotencyMiddleware(state))
	registerNodeRuntimeRoutes(runtimeGroup, state)
}

func registerNodeRuntimeRoutes(group *gin.RouterGroup, state *State) {
	if group == nil || state == nil {
		return
	}
	registerNodeProtectedActionRoutes(group, state, state.ProtectedActions)
	group.GET("/ws", nodeWebSocketHandler(state))
	group.POST("/batch", nodeBatchHTTPHandler(state))
}

func registerNodeProtectedActionRoutes(group *gin.RouterGroup, state *State, specs []webapi.ActionSpec) {
	for _, spec := range orderedNodeProtectedActionSpecs(specs) {
		registerNodeProtectedActionRoute(group, state, spec)
	}
}

func registerNodeProtectedActionRoute(group *gin.RouterGroup, state *State, spec webapi.ActionSpec) {
	if group == nil {
		return
	}
	handler := nodeProtectedActionHTTPHandler(state, spec)
	if handler == nil {
		return
	}
	registerActionRoute(
		group,
		spec.Method,
		nodeProtectedActionGinPath(spec.Path),
		appendActionHandler(nodeProtectedActionMiddlewares(state, spec), handler),
	)
}

func nodeProtectedActionMiddlewares(state *State, spec webapi.ActionSpec) []gin.HandlerFunc {
	middlewares := make([]gin.HandlerFunc, 0, 2)
	if auditKind := nodeProtectedActionAuditKind(spec); auditKind != "" {
		middlewares = append(middlewares, nodeOperationAuditMiddleware(state, auditKind))
	}
	if spec.Protected {
		middlewares = append(middlewares, nodeProtectedActionAccessMiddleware(state, spec))
	}
	return middlewares
}

func nodeProtectedActionAccessMiddleware(state *State, spec webapi.ActionSpec) gin.HandlerFunc {
	scopeAllowed := nodeProtectedActionScopeAllowed(spec)
	return func(c *gin.Context) {
		if scopeAllowed != nil && !scopeAllowed(actorNodeScopeWithAuthz(state.Authorization(), currentActor(c))) {
			abortForbidden(c)
			return
		}

		var authz webservice.AuthorizationService = webservice.DefaultAuthorizationService{}
		if state != nil {
			authz = state.Authorization()
		}
		result, err := webservice.ResolveProtectedActionAccess(authz, webservice.ProtectedActionAccessInput{
			Principal:         currentPrincipal(c),
			Permission:        spec.Permission,
			ClientScope:       spec.ClientScope,
			Ownership:         string(spec.Ownership),
			RequestedClientID: requestedClientID(c),
			ResourceID:        requestID(c),
		})
		if err != nil {
			abortAccessError(c, state, err)
			return
		}
		if result.ResolvedClientID > 0 {
			framework.SetRequestData(c, "client_id", result.ResolvedClientID)
			framework.SetRequestParam(c, "client_id", strconv.Itoa(result.ResolvedClientID))
		}
		c.Next()
	}
}

func nodeProtectedActionHTTPHandler(state *State, spec webapi.ActionSpec) gin.HandlerFunc {
	if override := nodeProtectedActionHTTPHandlerOverride(state, spec); override != nil {
		return override
	}
	if spec.Handler == nil {
		return nil
	}
	return handle(spec.Handler)
}

func nodeProtectedActionHTTPHandlerOverride(state *State, spec webapi.ActionSpec) gin.HandlerFunc {
	switch nodeProtectedActionKey(spec) {
	case "system/changes":
		return nodeChangesHTTPHandler(state)
	case "system/import":
		return nodeConfigImportHTTPHandler(state)
	case "callbacks_queue/list":
		return nodeCallbackQueueHTTPHandler(state)
	case "callbacks_queue/replay":
		return nodeCallbackQueueReplayHTTPHandler(state)
	case "callbacks_queue/clear":
		return nodeCallbackQueueClearHTTPHandler(state)
	case "webhooks/list":
		return nodeWebhookListHTTPHandler(state)
	case "webhooks/read":
		return nodeWebhookGetHTTPHandler(state)
	case "webhooks/create":
		return nodeWebhookCreateHTTPHandler(state)
	case "webhooks/update":
		return nodeWebhookUpdateHTTPHandler(state)
	case "webhooks/status":
		return nodeWebhookStatusHTTPHandler(state)
	case "webhooks/delete":
		return nodeWebhookDeleteHTTPHandler(state)
	default:
		return nil
	}
}

func nodeProtectedActionRelativePath(path string) string {
	path = sessionActionRelativePath(path)
	if path == "/api" {
		return "/"
	}
	if strings.HasPrefix(path, "/api/") {
		return strings.TrimPrefix(path, "/api")
	}
	return path
}

func nodeProtectedActionGinPath(path string) string {
	path = nodeProtectedActionRelativePath(path)
	replacer := strings.NewReplacer("{id}", ":id", "{key}", ":key")
	return replacer.Replace(path)
}

func nodeProtectedActionKey(spec webapi.ActionSpec) string {
	resource := strings.ToLower(strings.TrimSpace(spec.Resource))
	action := strings.ToLower(strings.TrimSpace(spec.Action))
	if resource == "" || action == "" {
		return ""
	}
	return resource + "/" + action
}

func orderedNodeProtectedActionSpecs(specs []webapi.ActionSpec) []webapi.ActionSpec {
	if len(specs) == 0 {
		return nil
	}
	ordered := append([]webapi.ActionSpec(nil), specs...)
	sort.SliceStable(ordered, func(i, j int) bool {
		leftPath := nodeProtectedActionRelativePath(ordered[i].Path)
		rightPath := nodeProtectedActionRelativePath(ordered[j].Path)
		leftParams := strings.Count(leftPath, "{")
		rightParams := strings.Count(rightPath, "{")
		if leftParams != rightParams {
			return leftParams < rightParams
		}
		leftStaticSegments := nodeProtectedActionStaticSegmentCount(leftPath)
		rightStaticSegments := nodeProtectedActionStaticSegmentCount(rightPath)
		if leftStaticSegments != rightStaticSegments {
			return leftStaticSegments > rightStaticSegments
		}
		if len(leftPath) != len(rightPath) {
			return len(leftPath) > len(rightPath)
		}
		if ordered[i].Method != ordered[j].Method {
			return ordered[i].Method < ordered[j].Method
		}
		return leftPath < rightPath
	})
	return ordered
}

func nodeProtectedActionStaticSegmentCount(path string) int {
	count := 0
	for _, part := range strings.Split(strings.Trim(strings.TrimSpace(path), "/"), "/") {
		part = strings.TrimSpace(part)
		if part == "" || strings.Contains(part, "{") {
			continue
		}
		count++
	}
	return count
}

func nodeProtectedActionAuditKind(spec webapi.ActionSpec) string {
	switch nodeProtectedActionKey(spec) {
	case "settings_global/update",
		"security_bans/delete",
		"security_bans/delete_all",
		"security_bans/clean",
		"users/create",
		"users/update",
		"users/status",
		"users/delete",
		"clients/create",
		"clients/clear_all",
		"clients/update",
		"clients/status",
		"clients/clear",
		"clients/delete",
		"tunnels/create",
		"tunnels/update",
		"tunnels/start",
		"tunnels/stop",
		"tunnels/clear",
		"tunnels/delete",
		"hosts/create",
		"hosts/update",
		"hosts/start",
		"hosts/stop",
		"hosts/clear",
		"hosts/delete",
		"webhooks/create",
		"webhooks/update",
		"webhooks/status",
		"webhooks/delete":
		return "resource"
	default:
		return ""
	}
}

func nodeProtectedActionScopeAllowed(spec webapi.ActionSpec) func(webservice.NodeAccessScope) bool {
	switch nodeProtectedActionKey(spec) {
	case "system/overview":
		return func(scope webservice.NodeAccessScope) bool {
			return scope.CanViewStatus() || scope.CanViewUsage()
		}
	case "system/dashboard":
		return func(scope webservice.NodeAccessScope) bool {
			return scope.IsFullAccess()
		}
	case "system/registration", "system/operations", "system/status":
		return func(scope webservice.NodeAccessScope) bool {
			return scope.CanViewStatus()
		}
	case "system/usage_snapshot":
		return func(scope webservice.NodeAccessScope) bool {
			return scope.CanViewUsage()
		}
	case "system/export":
		return func(scope webservice.NodeAccessScope) bool {
			return scope.CanExportConfig()
		}
	case "system/sync":
		return func(scope webservice.NodeAccessScope) bool {
			return scope.CanSync()
		}
	case "traffic/write":
		return func(scope webservice.NodeAccessScope) bool {
			return scope.CanWriteTraffic()
		}
	case "callbacks_queue/list":
		return func(scope webservice.NodeAccessScope) bool {
			return scope.CanViewCallbackQueue()
		}
	case "callbacks_queue/replay", "callbacks_queue/clear":
		return func(scope webservice.NodeAccessScope) bool {
			return scope.CanManageCallbackQueue()
		}
	default:
		return nil
	}
}

func nodeAccessMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor := currentActor(c)
		if actor != nil && strings.TrimSpace(actor.Kind) != "" && !strings.EqualFold(actor.Kind, webservice.RoleAnonymous) {
			metadata := currentRequestMetadata(c)
			metadata.Source = "node-api-local"
			setRequestMetadata(c, metadata)
			c.Next()
			return
		}

		token := nodeTokenFromRequest(c)
		if strings.TrimSpace(token) != "" {
			nodeTokenAccess(state, c, token)
			return
		}

		msg := "invalid node token"
		if sessionInvalidated(c) {
			msg = "unauthorized"
		} else if _, hasSession := framework.SessionValue(c, webservice.SessionIdentityKey).(string); hasSession {
			msg = "unauthorized"
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, webapi.ManagementErrorResponse{
			Error: webapi.ManagementErrorDetail{
				Code:    "unauthorized",
				Message: msg,
			},
		})
	}
}

func optionalNodeDiscoveryAccessMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor := currentActor(c)
		if actor != nil && strings.TrimSpace(actor.Kind) != "" && !strings.EqualFold(actor.Kind, webservice.RoleAnonymous) {
			c.Next()
			return
		}

		token := nodeTokenFromRequest(c)
		if strings.TrimSpace(token) == "" {
			c.Next()
			return
		}

		nodeTokenAccess(state, c, token)
	}
}

func nodeOperationAuditMiddleware(state *State, kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		startedAt := time.Now()
		operationID := currentNodeHTTPOperationID(c)
		setNodeHTTPOperationHeader(c, operationID)
		c.Next()
		if state == nil {
			return
		}
		status := c.Writer.Status()
		err := nodeOperationErrorFromStatus(status)
		state.RuntimeStatus().NoteOperation(strings.TrimSpace(kind), err)
		recordNodeOperation(
			state,
			currentActor(c),
			currentRequestMetadata(c),
			operationID,
			strings.TrimSpace(kind),
			startedAt,
			1,
			nodeOperationSuccessCount(status),
			nodeOperationErrorCount(status),
			[]string{canonicalNodeOperationPath(state, c.Request.URL.Path)},
		)
	}
}

func nodeRoutesEnabled(cfg *servercfg.Snapshot) bool {
	return cfg != nil
}

func nodeRequestContextMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		runRequestIdentityMiddleware(c, state, "node-api")
	}
}

func nodeTokenAccess(state *State, c *gin.Context, actual string) {
	cfg := (*servercfg.Snapshot)(nil)
	if state != nil {
		cfg = state.CurrentConfig()
	}
	if cfg == nil || !cfg.Runtime.HasManagementPlatforms() {
		c.AbortWithStatusJSON(http.StatusUnauthorized, webapi.ManagementErrorResponse{
			Error: webapi.ManagementErrorDetail{
				Code:    "node_management_unavailable",
				Message: "node management platform is not configured",
			},
		})
		return
	}
	platform, ok := cfg.Runtime.FindManagementPlatformByToken(actual)
	if !ok || subtle.ConstantTimeCompare([]byte(platform.Token), []byte(actual)) != 1 {
		c.AbortWithStatusJSON(http.StatusUnauthorized, webapi.ManagementErrorResponse{
			Error: webapi.ManagementErrorDetail{
				Code:    "unauthorized",
				Message: "invalid node token",
			},
		})
		return
	}
	if !platform.SupportsDirect() {
		c.AbortWithStatusJSON(http.StatusForbidden, webapi.ManagementErrorResponse{
			Error: webapi.ManagementErrorDetail{
				Code:    "forbidden",
				Message: "direct node management is disabled for this platform",
			},
		})
		return
	}
	platformCtx := &nodePlatformContext{Config: platform}
	c.Set(nodePlatformContextKey, platformCtx)
	serviceUser, err := ensurePlatformServiceUser(state, platformCtx.Config)
	if err != nil || serviceUser == nil || serviceUser.Id <= 0 {
		c.AbortWithStatusJSON(http.StatusInternalServerError, webapi.ManagementErrorResponse{
			Error: webapi.ManagementErrorDetail{
				Code:    "platform_service_user_unavailable",
				Message: "platform service user is unavailable",
			},
		})
		return
	}
	platformCtx.ServiceUserID = serviceUser.Id
	actor, err := platformActorFromLookup(platformCtx.Config, serviceUser.Id, func() ([]int, error) {
		return platformOwnedClientIDs(state, serviceUser.Id)
	}, nodePlatformLookup(c))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, webapi.ManagementErrorResponseForStatus(http.StatusInternalServerError, err))
		return
	}
	setActor(c, actor)
	metadata := currentRequestMetadata(c)
	metadata.Source = "node-api"
	setRequestMetadata(c, metadata)
	c.Next()
}

func ensurePlatformServiceUser(state *State, platform servercfg.ManagementPlatformConfig) (*file.User, error) {
	if state == nil {
		return nil, errors.New("node state is unavailable")
	}
	return state.ManagementPlatforms().EnsureServiceUser(platform)
}

func nodeTokenFromRequest(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if value := strings.TrimSpace(c.GetHeader("X-Node-Token")); value != "" {
		return value
	}
	if value := strings.TrimSpace(c.GetHeader("Authorization")); value != "" {
		if token, ok := webservice.ParseBearerAuthorizationHeader(value); ok && !webservice.IsStandaloneToken(token) {
			return token
		}
	}
	for _, key := range []string{"token", "node_token"} {
		if value := nodeRequestBodyValue(c, key); value != "" {
			return value
		}
	}
	return ""
}

func nodeRequestValue(c *gin.Context, key string) string {
	if c == nil {
		return ""
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if value, ok := framework.RequestParam(c, key); ok {
		return strings.TrimSpace(value)
	}
	if value := strings.TrimSpace(c.Query(key)); value != "" {
		return value
	}
	return ""
}

func nodeRequestBodyValue(c *gin.Context, key string) string {
	if c == nil {
		return ""
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if value, ok := framework.RequestParam(c, key); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func handle(fn webapi.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		fn(requestAPIContext(c))
	}
}

func subgroup(group *gin.RouterGroup, prefix string, middlewares ...gin.HandlerFunc) *gin.RouterGroup {
	child := group.Group(prefix)
	if len(middlewares) > 0 {
		child.Use(middlewares...)
	}
	return child
}

func joinBase(base, suffix string) string {
	base = servercfg.NormalizeBaseURL(base)
	if base == "" {
		return suffix
	}
	return base + suffix
}

func standaloneCORSMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := (*servercfg.Snapshot)(nil)
		if state != nil {
			cfg = state.CurrentConfig()
		}
		if cfg == nil || !standaloneCORSRouteAllowed(c.Request.URL.Path, cfg.Web.BaseURL) {
			c.Next()
			return
		}

		origin := strings.TrimSpace(c.GetHeader("Origin"))
		if origin == "" {
			c.Next()
			return
		}
		if !cfg.StandaloneAllowsOrigin(origin) {
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Next()
			return
		}

		headers := c.Writer.Header()
		allowOrigin := "*"
		if cfg.StandaloneAllowCredentials() || !cfg.StandaloneAllowsAnyOrigin() {
			allowOrigin = origin
			appendVaryHeader(headers, "Origin")
		}
		headers.Set("Access-Control-Allow-Origin", allowOrigin)
		headers.Set("Access-Control-Allow-Methods", standaloneCORSAllowedMethods)
		headers.Set("Access-Control-Allow-Headers", standaloneCORSAllowedHeaders)
		headers.Set("Access-Control-Expose-Headers", standaloneCORSExposedHeaders)
		appendVaryHeader(headers, "Access-Control-Request-Method")
		appendVaryHeader(headers, "Access-Control-Request-Headers")
		if cfg.StandaloneAllowCredentials() {
			headers.Set("Access-Control-Allow-Credentials", "true")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func standaloneCORSRouteAllowed(path, baseURL string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	switch path {
	case joinBase(baseURL, "/captcha/new"):
		return true
	}
	authBase := joinBase(baseURL, "/api/auth")
	if path == authBase || strings.HasPrefix(path, authBase+"/") {
		return true
	}
	accessBase := joinBase(baseURL, "/api/access")
	if path == accessBase || strings.HasPrefix(path, accessBase+"/") {
		return true
	}
	captchaBase := joinBase(baseURL, "/captcha")
	if path == captchaBase || strings.HasPrefix(path, captchaBase+"/") {
		return true
	}
	nodeAPIBase := joinBase(baseURL, "/api")
	return path == nodeAPIBase || strings.HasPrefix(path, nodeAPIBase+"/")
}

func appendVaryHeader(headers http.Header, value string) {
	if headers == nil {
		return
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	current := headers.Values("Vary")
	for _, item := range current {
		for _, existing := range strings.Split(item, ",") {
			if strings.EqualFold(strings.TrimSpace(existing), value) {
				return
			}
		}
	}
	headers.Add("Vary", value)
}

func sessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := framework.EnsureSession(c); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			c.Abort()
			return
		}
		c.Next()
	}
}

func apiInputMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		contentType := strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Type")))
		if !strings.HasPrefix(contentType, "application/json") || c.Request.Body == nil {
			c.Next()
			return
		}

		rawBody, err := io.ReadAll(c.Request.Body)
		if err != nil {
			if strings.Contains(err.Error(), "http: request body too large") {
				abortRequestEntityTooLarge(c)
				return
			}
			c.AbortWithStatusJSON(http.StatusBadRequest, webapi.ManagementErrorResponse{
				Error: webapi.ManagementErrorDetail{
					Code:    "invalid_json_body",
					Message: "invalid json body",
				},
			})
			return
		}
		framework.SetRequestRawBody(c, rawBody)
		c.Request.Body = io.NopCloser(bytes.NewReader(rawBody))
		if len(bytes.TrimSpace(rawBody)) == 0 {
			c.Next()
			return
		}

		var payload interface{}
		decoder := json.NewDecoder(bytes.NewReader(rawBody))
		decoder.UseNumber()
		if err := decoder.Decode(&payload); err != nil {
			if err == io.EOF {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusBadRequest, webapi.ManagementErrorResponse{
				Error: webapi.ManagementErrorDetail{
					Code:    "invalid_json_body",
					Message: "invalid json body",
				},
			})
			return
		}
		if objectPayload, ok := payload.(map[string]interface{}); ok {
			for key, value := range objectPayload {
				framework.SetRequestParam(c, key, webapi.StringifyRequestValue(value))
			}
		}
		c.Next()
	}
}

func managementNoStoreMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c != nil && c.Writer != nil {
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
		}
		c.Next()
	}
}

func abortRequestEntityTooLarge(c *gin.Context) {
	if c == nil {
		return
	}
	if isFormalManagementAPIRequest(c.Request.URL.Path) {
		c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, webapi.ManagementErrorResponse{
			Error: webapi.ManagementErrorDetail{
				Code:    "payload_too_large",
				Message: "payload too large",
			},
		})
		return
	}
	c.AbortWithStatus(http.StatusRequestEntityTooLarge)
}

func requestContextMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		runRequestIdentityMiddleware(c, state, "")
	}
}

func runRequestIdentityMiddleware(c *gin.Context, state *State, metadataSource string) {
	if c == nil {
		return
	}
	if state != nil && state.App != nil {
		attachRequestMetadata(c, state.App)
		if source := strings.TrimSpace(metadataSource); source != "" {
			metadata := currentRequestMetadata(c)
			metadata.Source = source
			setRequestMetadata(c, metadata)
		}
	}
	if authenticateRequest(c, state) {
		return
	}
	if state != nil {
		ensureAutoAdminSession(c, state)
		syncRequestSessionActor(c, state)
	}
	if c.IsAborted() {
		return
	}
	c.Next()
}

func ensureAutoAdminSession(c *gin.Context, state *State) {
	if hasRequestIdentity(c) {
		return
	}
	if sessionIdentityFromSession(c, state.PermissionResolver()) != nil {
		return
	}
	identity, ok := webservice.AutoAdminIdentity(state.CurrentConfig())
	if !ok {
		return
	}
	apiCtx := requestAPIContext(c)
	webapi.ApplySessionIdentityWithResolver(apiCtx, identity, state.PermissionResolver())
	state.System().RegisterManagementAccess(resolvedManagementClientIP(apiCtx, state))
}

func syncRequestSessionActor(c *gin.Context, state *State) {
	if c == nil || state == nil {
		return
	}
	apiCtx := requestAPIContext(c)
	if hasRequestIdentity(c) {
		resolved := currentResolvedRequestIdentity(c, state)
		if resolved == nil {
			setActor(c, webapi.AnonymousActor())
			return
		}
		setActor(c, resolved.actor)
		return
	}
	identity := sessionIdentityFromSession(c, state.PermissionResolver())
	if identity == nil || !identity.Authenticated {
		setActor(c, webapi.AnonymousActor())
		return
	}
	resolved, err := refreshSessionActorIdentity(state, identity, common.TimeNow())
	if err != nil {
		if errors.Is(err, webservice.ErrUnauthenticated) {
			webapi.ClearSessionIdentity(apiCtx)
			markSessionInvalidated(c)
			setActor(c, webapi.AnonymousActor())
			return
		}
		setActor(c, webapi.AnonymousActor())
		abortRequestAuthError(c, err)
		return
	}
	if resolved == nil {
		setActor(c, webapi.AnonymousActor())
		return
	}
	registerManagementAccessForResolvedActor(c, state, resolved)
	refreshedRaw, err := webservice.MarshalSessionIdentityWithResolver(resolved.identity, state.PermissionResolver())
	if err != nil {
		setActor(c, resolved.actor)
		return
	}
	currentRaw, _ := framework.SessionValue(c, webservice.SessionIdentityKey).(string)
	if strings.TrimSpace(currentRaw) != refreshedRaw {
		webapi.ApplySessionIdentityWithResolver(apiCtx, resolved.identity, state.PermissionResolver())
		return
	}
	setActor(c, resolved.actor)
}

func permissionMiddleware(state *State, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := state.Authorization().RequirePermission(currentPrincipal(c), permission); err != nil {
			abortAccessError(c, state, err)
			return
		}
		c.Next()
	}
}

func protectedActionAccessMiddleware(state *State, spec webapi.ActionSpec) gin.HandlerFunc {
	return func(c *gin.Context) {
		result, err := webservice.ResolveProtectedActionAccess(state.Authorization(), webservice.ProtectedActionAccessInput{
			Principal:         currentPrincipal(c),
			Permission:        spec.Permission,
			ClientScope:       spec.ClientScope,
			Ownership:         string(spec.Ownership),
			RequestedClientID: requestedClientID(c),
			ResourceID:        requestID(c),
		})
		if err != nil {
			abortAccessError(c, state, err)
			return
		}
		if result.ResolvedClientID > 0 {
			framework.SetRequestData(c, "client_id", result.ResolvedClientID)
			framework.SetRequestParam(c, "client_id", strconv.Itoa(result.ResolvedClientID))
		}
		c.Next()
	}
}

func clientScopeMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		resolvedClientID, err := state.Authorization().ResolveClient(currentPrincipal(c), requestedClientID(c))
		if err != nil {
			abortAccessError(c, state, err)
			return
		}
		if resolvedClientID > 0 {
			framework.SetRequestData(c, "client_id", resolvedClientID)
			framework.SetRequestParam(c, "client_id", strconv.Itoa(resolvedClientID))
		}
		c.Next()
	}
}

func requestID(c *gin.Context) int {
	id, _ := requestInt(c, "id")
	return id
}

func clientOwnershipMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := requestInt(c, "id")
		if !ok {
			c.Next()
			return
		}
		if err := state.Authorization().RequireClient(currentPrincipal(c), id); err != nil {
			abortAccessError(c, state, err)
			return
		}
		c.Next()
	}
}

func tunnelOwnershipMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := requestInt(c, "id")
		if !ok {
			c.Next()
			return
		}
		if err := state.Authorization().RequireTunnel(currentPrincipal(c), id); err != nil {
			abortAccessError(c, state, err)
			return
		}
		c.Next()
	}
}

func hostOwnershipMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := requestInt(c, "id")
		if !ok {
			c.Next()
			return
		}
		if err := state.Authorization().RequireHost(currentPrincipal(c), id); err != nil {
			abortAccessError(c, state, err)
			return
		}
		c.Next()
	}
}

func requestInt(c *gin.Context, key string) (int, bool) {
	if raw, ok := framework.RequestParam(c, key); ok && raw != "" {
		value, err := strconv.Atoi(raw)
		if err == nil {
			return value, true
		}
		return 0, false
	}
	if raw := strings.TrimSpace(c.Param(key)); raw != "" {
		value, err := strconv.Atoi(raw)
		if err == nil {
			return value, true
		}
		return 0, false
	}
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return 0, false
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return value, true
}

func requestedClientID(c *gin.Context) int {
	raw := ""
	if requestValue, ok := framework.RequestParam(c, "client_id"); ok {
		raw = strings.TrimSpace(requestValue)
	}
	if raw == "" {
		raw = strings.TrimSpace(c.Query("client_id"))
	}
	if raw == "" {
		return 0
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return value
}

func abortUnauthorized(c *gin.Context) {
	abortManagementStatus(c, http.StatusUnauthorized, "unauthorized", "unauthorized")
}

func abortForbidden(c *gin.Context) {
	abortManagementStatus(c, http.StatusForbidden, "forbidden", "forbidden")
}

func abortManagementStatus(c *gin.Context, status int, code, message string) {
	if c == nil {
		return
	}
	if isFormalManagementAPIRequest(c.Request.URL.Path) {
		c.AbortWithStatusJSON(status, webapi.ManagementErrorResponse{
			Error: webapi.ManagementErrorDetail{
				Code:    strings.TrimSpace(code),
				Message: strings.TrimSpace(message),
			},
		})
		return
	}
	c.AbortWithStatus(status)
}

func abortAccessError(c *gin.Context, state *State, err error) {
	switch {
	case errors.Is(err, webservice.ErrUnauthenticated):
		abortUnauthorized(c)
	case errors.Is(err, webservice.ErrForbidden):
		abortForbidden(c)
	default:
		abortForbidden(c)
	}
}

func isFormalManagementAPIRequest(path string) bool {
	path = normalizeFormalManagementAPIPath(path)
	switch {
	case path == "/api":
		return true
	case path == "/api/ws", path == "/api/batch", path == "/api/traffic":
		return true
	case path == "/api/users", strings.HasPrefix(path, "/api/users/"):
		return true
	case path == "/api/clients", strings.HasPrefix(path, "/api/clients/"):
		return true
	case path == "/api/tunnels", strings.HasPrefix(path, "/api/tunnels/"):
		return true
	case path == "/api/hosts", strings.HasPrefix(path, "/api/hosts/"):
		return true
	case strings.HasPrefix(path, "/api/system/"):
		return true
	case strings.HasPrefix(path, "/api/settings/"):
		return true
	case strings.HasPrefix(path, "/api/security/"):
		return true
	case strings.HasPrefix(path, "/api/tools/"):
		return true
	case strings.HasPrefix(path, "/api/callbacks/"):
		return true
	case path == "/api/auth", strings.HasPrefix(path, "/api/auth/"):
		return true
	case path == "/api/access", strings.HasPrefix(path, "/api/access/"):
		return true
	case path == "/api/webhooks", strings.HasPrefix(path, "/api/webhooks/"):
		return true
	case path == "/api/realtime/subscriptions", strings.HasPrefix(path, "/api/realtime/subscriptions/"):
		return true
	}
	return false
}

func normalizeFormalManagementAPIPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if path == "/api" || strings.HasPrefix(path, "/api/") {
		return path
	}
	if index := strings.Index(path, "/api"); index > 0 {
		trimmed := path[index:]
		if trimmed == "/api" || strings.HasPrefix(trimmed, "/api/") {
			return trimmed
		}
	}
	return path
}

func currentPrincipal(c *gin.Context) webservice.Principal {
	return actorPrincipal(currentActor(c))
}

func actorPrincipal(actor *webapi.Actor) webservice.Principal {
	return webapi.PrincipalFromActor(actor)
}

func actorNodeScopeWithAuthz(authz webservice.AuthorizationService, actor *webapi.Actor) webservice.NodeAccessScope {
	return webservice.ResolveNodeAccessScopeWithAuthorization(authz, actorPrincipal(actor))
}
