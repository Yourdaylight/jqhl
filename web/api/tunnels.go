package api

import (
	"strconv"
	"strings"
	"time"

	"github.com/djylb/nps/lib/file"
	webservice "github.com/djylb/nps/web/service"
)

type nodeTunnelResourcePayload struct {
	ID                  int                        `json:"id"`
	Revision            int64                      `json:"revision"`
	UpdatedAt           int64                      `json:"updated_at"`
	ClientID            int                        `json:"client_id,omitempty"`
	Client              *nodeClientResourcePayload `json:"client,omitempty"`
	Port                int                        `json:"port"`
	ServerIP            string                     `json:"server_ip,omitempty"`
	Mode                string                     `json:"mode,omitempty"`
	Status              bool                       `json:"status"`
	RunStatus           bool                       `json:"run_status"`
	Remark              string                     `json:"remark,omitempty"`
	TargetType          string                     `json:"target_type,omitempty"`
	Target              string                     `json:"target,omitempty"`
	LocalProxy          bool                       `json:"local_proxy"`
	Password            string                     `json:"password,omitempty"`
	LocalPath           string                     `json:"local_path,omitempty"`
	StripPre            string                     `json:"strip_pre,omitempty"`
	ExpireAt            int64                      `json:"expire_at"`
	FlowLimitTotalBytes int64                      `json:"flow_limit_total_bytes"`
	RateLimitTotalBps   int                        `json:"rate_limit_total_bps"`
	MaxConnections      int                        `json:"max_connections"`
	NowConn             int                        `json:"now_conn"`
	NowRateInBps        int64                      `json:"now_rate_in_bps"`
	NowRateOutBps       int64                      `json:"now_rate_out_bps"`
	NowRateTotalBps     int64                      `json:"now_rate_total_bps"`
	ServiceInBytes      int64                      `json:"service_in_bytes"`
	ServiceOutBytes     int64                      `json:"service_out_bytes"`
	ServiceTotalBytes   int64                      `json:"service_total_bytes"`
	IsHTTP              bool                       `json:"is_http"`
	EnableHTTP          bool                       `json:"enable_http"`
	EnableSocks5        bool                       `json:"enable_socks5"`
	ReadOnly            bool                       `json:"read_only"`
	EntryACLMode        int                        `json:"entry_acl_mode"`
	EntryACLRules       string                     `json:"entry_acl_rules,omitempty"`
	DestACLMode         int                        `json:"dest_acl_mode"`
	DestACLRules        string                     `json:"dest_acl_rules,omitempty"`
	ProxyProtocol       int                        `json:"proxy_protocol"`
	Auth                string                     `json:"auth,omitempty"`
}

func (a *App) NodeTunnels(c Context) {
	access := a.nodeActorAccessFromContext(c)
	offset := requestIntValue(c, "offset")
	limit := requestIntValue(c, "limit")
	items, total, err := a.listNodeTunnels(c, access)
	if err != nil {
		respondNodeResourceData(c, nodeResourceListPayload{}, err)
		return
	}
	offset, limit, returned, hasMore := nodeListPagination(offset, limit, len(items), total)
	respondNodeResourceData(c, nodeResourceListPayload{
		ConfigEpoch: a.runtimeIdentity().ConfigEpoch(),
		GeneratedAt: time.Now().Unix(),
		Offset:      offset,
		Limit:       limit,
		Returned:    returned,
		Total:       total,
		HasMore:     hasMore,
		Items:       items,
	}, nil)
}

func (a *App) NodeTunnel(c Context) {
	access := a.nodeActorAccessFromContext(c)
	tunnel, err := a.Services.Index.GetTunnel(requestIntValue(c, "id"))
	if err == nil {
		switch {
		case tunnel == nil:
			err = webservice.ErrTunnelNotFound
		case !access.scope.AllowsClient(tunnel.Client):
			err = webservice.ErrForbidden
		default:
			tunnel = a.sanitizeNodeTunnel(access.actor, access.scope, tunnel)
		}
	}
	respondNodeResourceData(c, nodeResourceItemPayload{
		ConfigEpoch: a.runtimeIdentity().ConfigEpoch(),
		GeneratedAt: time.Now().Unix(),
		Item:        a.nodeTunnelResource(tunnel),
	}, err)
}

func (a *App) listNodeTunnels(c Context, access nodeActorAccess) ([]nodeTunnelResourcePayload, int, error) {
	visibility, ok, err := access.visibility(a)
	if err != nil {
		return nil, 0, err
	}
	if !ok {
		return nil, 0, nil
	}
	rows, total := a.Services.Index.ListTunnels(nodeListQueryFromContext(c).tunnelsInput(visibility))
	items := a.sanitizeNodeTunnels(access.actor, access.scope, rows)
	return items, adjustedNodeListTotal(total, len(rows), len(items)), nil
}

func (a *App) sanitizeNodeTunnels(actor *Actor, scope webservice.NodeAccessScope, tunnels []*file.Tunnel) []nodeTunnelResourcePayload {
	if len(tunnels) == 0 {
		return nil
	}
	items := make([]nodeTunnelResourcePayload, 0, len(tunnels))
	for _, tunnel := range tunnels {
		if tunnel == nil {
			continue
		}
		items = append(items, a.nodeTunnelResource(a.sanitizeNodeTunnel(actor, scope, tunnel)))
	}
	return items
}

func (a *App) nodeTunnelResource(tunnel *file.Tunnel) nodeTunnelResourcePayload {
	payload := nodeTunnelResourcePayload{}
	if tunnel == nil {
		return payload
	}
	payload.ID = tunnel.Id
	payload.Revision = tunnel.Revision
	payload.UpdatedAt = tunnel.UpdatedAt
	if tunnel.Client != nil {
		payload.ClientID = tunnel.Client.Id
		clientPayload := a.embeddedNodeClientResource(tunnel.Client)
		payload.Client = &clientPayload
	}
	payload.Port = tunnel.Port
	payload.ServerIP = tunnel.ServerIp
	payload.Mode = tunnel.Mode
	payload.Status = tunnel.Status
	payload.RunStatus = tunnel.RunStatus
	payload.Remark = tunnel.Remark
	payload.TargetType = tunnel.TargetType
	payload.Password = tunnel.Password
	payload.LocalPath = tunnel.LocalPath
	payload.StripPre = tunnel.StripPre
	payload.ExpireAt = tunnel.EffectiveExpireAt()
	payload.FlowLimitTotalBytes = tunnel.EffectiveFlowLimitBytes()
	payload.RateLimitTotalBps = webservice.ManagementRateLimitToBps(tunnel.RateLimit)
	payload.MaxConnections = tunnel.MaxConn
	payload.NowConn = int(tunnel.NowConn)
	payload.IsHTTP = tunnel.IsHttp
	payload.EnableHTTP = tunnel.HttpProxy
	payload.EnableSocks5 = tunnel.Socks5Proxy
	payload.ReadOnly = tunnel.ReadOnly
	payload.EntryACLMode = tunnel.EntryAclMode
	payload.EntryACLRules = tunnel.EntryAclRules
	payload.DestACLMode = tunnel.DestAclMode
	payload.DestACLRules = tunnel.DestAclRules
	if tunnel.Target != nil {
		payload.Target = tunnel.Target.TargetStr
		payload.ProxyProtocol = tunnel.Target.ProxyProtocol
		payload.LocalProxy = tunnel.Target.LocalProxy
	}
	if tunnel.UserAuth != nil {
		payload.Auth = tunnel.UserAuth.Content
	}
	payload.ServiceInBytes, payload.ServiceOutBytes, payload.ServiceTotalBytes = tunnel.ServiceTrafficTotals()
	payload.NowRateInBps, payload.NowRateOutBps, payload.NowRateTotalBps = tunnel.ServiceRateTotals()
	return payload
}

func (a *App) sanitizeNodeTunnel(actor *Actor, scope webservice.NodeAccessScope, tunnel *file.Tunnel) *file.Tunnel {
	if tunnel == nil {
		return nil
	}
	tunnel = webservice.CloneTunnelSnapshot(tunnel)
	if tunnel.Client != nil {
		tunnel.Client = sanitizeNodeClient(scope, tunnel.Client)
	}
	if !a.nodeActorAllows(actor, webservice.PermissionTunnelsUpdate) {
		tunnel.Password = ""
		if tunnel.UserAuth != nil {
			tunnel.UserAuth.Content = ""
			tunnel.UserAuth.AccountMap = nil
		}
	}
	return tunnel
}

func (a *App) finishNodeTunnelMutation(c Context, action, eventName string, id int, tunnel *file.Tunnel, overrides map[string]interface{}) {
	// Event emission is now handled exclusively by the service layer (web/service/resources.go).
	// a.emitNodeResourceMutationEvent(c, eventName, "tunnel", action, nodeResourceMutationFields(id, tunnelEventFields(tunnel), overrides))
	a.respondCompletedNodeMutation(c, "tunnel", action, id, a.nodeTunnelResource(tunnel))
}

func (a *App) NodeCreateTunnel(c Context) {
	access := a.nodeActorAccessFromContext(c)
	var body nodeTunnelWriteRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	clientID, err := access.authorize(a, c, webservice.ProtectedActionAccessInput{
		Permission:        webservice.PermissionTunnelsCreate,
		ClientScope:       true,
		RequestedClientID: body.ClientID,
	})
	if err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	if clientID > 0 {
		c.SetParam("client_id", strconv.Itoa(clientID))
	}
	effectiveClientID := body.ClientID
	if clientID > 0 {
		effectiveClientID = clientID
	}
	if effectiveClientID <= 0 {
		respondMissingRequestField(c, "client_id")
		return
	}
	result, err := a.Services.Index.AddTunnel(webservice.BuildAddTunnelInput(webservice.IndexMutationContext{
		Principal:       access.principal,
		Authz:           a.authorization(),
		AllowLocalProxy: a.currentConfig().Feature.AllowLocalProxy,
		AllowUserLocal:  a.currentConfig().Feature.AllowUserLocal,
	}, webservice.AddTunnelRequest{
		TunnelWriteRequest: webservice.TunnelWriteRequest{
			ClientID:       effectiveClientID,
			Port:           body.Port,
			ServerIP:       body.ServerIP,
			Mode:           body.Mode,
			TargetType:     body.TargetType,
			Target:         body.Target,
			ProxyProtocol:  body.ProxyProtocol,
			LocalProxy:     body.LocalProxy,
			Auth:           body.Auth,
			Remark:         body.Remark,
			Password:       body.Password,
			LocalPath:      body.LocalPath,
			StripPre:       body.StripPre,
			EnableHTTP:     body.EnableHTTP,
			EnableSocks5:   body.EnableSocks5,
			EntryACLMode:   body.EntryACLMode,
			EntryACLRules:  body.EntryACLRules,
			DestACLMode:    body.DestACLMode,
			DestACLRules:   body.DestACLRules,
			FlowLimit:      body.FlowLimitTotalBytes,
			TimeLimit:      body.ExpireAt,
			RateLimit:      webservice.ManagementRateLimitFromBps(body.RateLimitTotalBps),
			MaxConnections: body.MaxConnections,
		},
	}))
	if err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	a.finishNodeTunnelMutation(c, "create", "tunnel.created", result.ID, a.sanitizeNodeTunnel(access.actor, access.scope, result.Tunnel), map[string]interface{}{"client_id": result.ClientID, "mode": result.Mode})
}

func (a *App) NodeUpdateTunnel(c Context) {
	access := a.nodeActorAccessFromContext(c)
	id := requestIntValue(c, "id")
	var body nodeTunnelWriteRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	if _, err := access.authorize(a, c, webservice.ProtectedActionAccessInput{
		Permission: webservice.PermissionTunnelsUpdate,
		Ownership:  "tunnel",
		ResourceID: id,
	}); err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	if body.ClientID > 0 {
		if err := authorizeRequestedNodeClientWithAccess(a, c, access, body.ClientID); err != nil {
			respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
			return
		}
	}
	result, err := a.Services.Index.EditTunnel(webservice.BuildEditTunnelInput(webservice.IndexMutationContext{
		Principal:       access.principal,
		Authz:           a.authorization(),
		AllowLocalProxy: a.currentConfig().Feature.AllowLocalProxy,
		AllowUserLocal:  a.currentConfig().Feature.AllowUserLocal,
	}, webservice.EditTunnelRequest{
		ID:               id,
		ExpectedRevision: body.ExpectedRevision,
		TunnelWriteRequest: webservice.TunnelWriteRequest{
			ClientID:       body.ClientID,
			Port:           body.Port,
			ServerIP:       body.ServerIP,
			Mode:           body.Mode,
			TargetType:     body.TargetType,
			Target:         body.Target,
			ProxyProtocol:  body.ProxyProtocol,
			LocalProxy:     body.LocalProxy,
			Auth:           body.Auth,
			Remark:         body.Remark,
			Password:       body.Password,
			LocalPath:      body.LocalPath,
			StripPre:       body.StripPre,
			EnableHTTP:     body.EnableHTTP,
			EnableSocks5:   body.EnableSocks5,
			EntryACLMode:   body.EntryACLMode,
			EntryACLRules:  body.EntryACLRules,
			DestACLMode:    body.DestACLMode,
			DestACLRules:   body.DestACLRules,
			FlowLimit:      body.FlowLimitTotalBytes,
			TimeLimit:      body.ExpireAt,
			RateLimit:      webservice.ManagementRateLimitFromBps(body.RateLimitTotalBps),
			MaxConnections: body.MaxConnections,
		},
		ResetFlow: body.ResetFlow,
	}))
	if err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	a.finishNodeTunnelMutation(c, "update", "tunnel.updated", result.ID, a.sanitizeNodeTunnel(access.actor, access.scope, result.Tunnel), map[string]interface{}{"client_id": result.ClientID})
}

func (a *App) NodeDeleteTunnel(c Context) {
	access := a.nodeActorAccessFromContext(c)
	id := requestIntValue(c, "id")
	if _, err := access.authorize(a, c, webservice.ProtectedActionAccessInput{
		Permission: webservice.PermissionTunnelsDelete,
		Ownership:  "tunnel",
		ResourceID: id,
	}); err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	result, err := a.Services.Index.DeleteTunnel(id)
	if err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	a.finishNodeTunnelMutation(c, "delete", "tunnel.deleted", result.ID, a.sanitizeNodeTunnel(access.actor, access.scope, result.Tunnel), nil)
}

func (a *App) NodeStartTunnel(c Context) { a.nodeTunnelStateChange(c, "start") }
func (a *App) NodeStopTunnel(c Context)  { a.nodeTunnelStateChange(c, "stop") }
func (a *App) NodeClearTunnel(c Context) { a.nodeTunnelStateChange(c, "clear") }

func (a *App) nodeTunnelStateChange(c Context, action string) {
	access := a.nodeActorAccessFromContext(c)
	id := requestIntValue(c, "id")
	var body nodeModeActionRequest
	if !decodeOptionalCanonicalJSONObject(c, &body) {
		return
	}
	if _, err := access.authorize(a, c, webservice.ProtectedActionAccessInput{
		Permission: webservice.PermissionTunnelsControl,
		Ownership:  "tunnel",
		ResourceID: id,
	}); err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	mode := strings.TrimSpace(body.Mode)
	if action == "clear" && mode == "" {
		respondMissingRequestField(c, "mode")
		return
	}
	var (
		err    error
		result webservice.TunnelMutation
	)
	switch action {
	case "start":
		result, err = a.Services.Index.StartTunnel(id, mode)
	case "stop":
		result, err = a.Services.Index.StopTunnel(id, mode)
	default:
		result, err = a.Services.Index.ClearTunnel(id, mode)
	}
	if err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	tunnel := a.sanitizeNodeTunnel(access.actor, access.scope, result.Tunnel)
	fields := map[string]interface{}{}
	if mode != "" {
		fields["mode"] = mode
	}
	a.finishNodeTunnelMutation(c, action, nodeResourceStateEventName("tunnel", action), result.ID, tunnel, fields)
}
