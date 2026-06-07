package service

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/server"
)

type IndexService interface {
	DashboardData(force bool) map[string]interface{}
	ListTunnels(TunnelListInput) ([]*file.Tunnel, int)
	AddTunnel(AddTunnelInput) (TunnelMutation, error)
	GetTunnel(id int) (*file.Tunnel, error)
	EditTunnel(EditTunnelInput) (TunnelMutation, error)
	StopTunnel(id int, mode string) (TunnelMutation, error)
	DeleteTunnel(id int) (TunnelMutation, error)
	StartTunnel(id int, mode string) (TunnelMutation, error)
	ClearTunnel(id int, mode string) (TunnelMutation, error)
	ListHosts(HostListInput) ([]*file.Host, int)
	GetHost(id int) (*file.Host, error)
	DeleteHost(id int) (HostMutation, error)
	StartHost(id int, mode string) (HostMutation, error)
	StopHost(id int, mode string) (HostMutation, error)
	ClearHost(id int, mode string) (HostMutation, error)
	AddHost(AddHostInput) (HostMutation, error)
	EditHost(EditHostInput) (HostMutation, error)
}

type DefaultIndexService struct {
	Repo       IndexRepository
	Runtime    IndexRuntime
	Backend    Backend
	QuotaStore QuotaStore
}

type QuotaStore interface {
	GetUser(int) (*file.User, error)
	OwnedResourceCountsByUserID(int) ownedUserResourceCounts
}

type DefaultQuotaStore struct{}

type ownedUserResourceCounts struct {
	Clients int
	Tunnels int
	Hosts   int
}

func (DefaultQuotaStore) GetUser(id int) (*file.User, error) {
	if file.GlobalStore == nil {
		return nil, ErrStoreNotInitialized
	}
	return file.GlobalStore.GetUser(id)
}

func (DefaultQuotaStore) OwnedResourceCountsByUserID(id int) ownedUserResourceCounts {
	clientCount, tunnelCount, hostCount := OwnedResourceCountsByUser(DefaultBackend().repo(), id)
	return ownedUserResourceCounts{
		Clients: clientCount,
		Tunnels: tunnelCount,
		Hosts:   hostCount,
	}
}

func ChangeTunnelStatus(id int, name, action string) error {
	_, err := changeTunnelStatusWithRepo(DefaultBackend().repo(), DefaultBackend().runtime(), id, name, action)
	return err
}

func ChangeHostStatus(id int, name, action string) error {
	_, err := changeHostStatusWithRepo(DefaultBackend().repo(), id, name, action)
	return err
}

func ClientOwnsTunnel(clientID, tunnelID int) bool {
	return DefaultBackend().repo().ClientOwnsTunnel(clientID, tunnelID)
}

func ClientOwnsHost(clientID, hostID int) bool {
	return DefaultBackend().repo().ClientOwnsHost(clientID, hostID)
}

type TunnelListInput struct {
	Offset     int
	Limit      int
	Type       string
	ClientID   int
	Search     string
	Sort       string
	Order      string
	Visibility ClientVisibility
}

type HostListInput struct {
	Offset     int
	Limit      int
	ClientID   int
	Search     string
	Sort       string
	Order      string
	Visibility ClientVisibility
}

type TunnelMutation struct {
	ID       int
	ClientID int
	Mode     string
	Tunnel   *file.Tunnel
}

type HostMutation struct {
	ID       int
	ClientID int
	Host     *file.Host
}

type AddTunnelInput struct {
	IsAdmin        bool
	AllowUserLocal bool
	ClientID       int
	Port           int
	ServerIP       string
	Mode           string
	TargetType     string
	Target         string
	ProxyProtocol  int
	LocalProxy     bool
	Auth           string
	Remark         string
	Password       string
	LocalPath      string
	StripPre       string
	EnableHTTP     bool
	EnableSocks5   bool
	EntryACLMode   int
	EntryACLRules  string
	DestACLMode    int
	DestACLRules   string
	FlowLimit      int64
	TimeLimit      string
	RateLimit      int
	MaxConnections int
}

type EditTunnelInput struct {
	ID               int
	ExpectedRevision int64
	IsAdmin          bool
	AllowUserLocal   bool
	ClientID         int
	Port             int
	ServerIP         string
	Mode             string
	TargetType       string
	Target           string
	ProxyProtocol    int
	LocalProxy       bool
	Auth             string
	Remark           string
	Password         string
	LocalPath        string
	StripPre         string
	EnableHTTP       bool
	EnableSocks5     bool
	EntryACLMode     int
	EntryACLRules    string
	DestACLMode      int
	DestACLRules     string
	FlowLimit        int64
	TimeLimit        string
	RateLimit        int
	MaxConnections   int
	ResetFlow        bool
}

type AddHostInput struct {
	IsAdmin        bool
	AllowUserLocal bool
	ClientID       int
	Host           string
	Target         string
	ProxyProtocol  int
	LocalProxy     bool
	Auth           string
	Header         string
	RespHeader     string
	HostChange     string
	Remark         string
	Location       string
	PathRewrite    string
	RedirectURL    string
	FlowLimit      int64
	TimeLimit      string
	RateLimit      int
	MaxConnections int
	EntryACLMode   int
	EntryACLRules  string
	Scheme         string
	HTTPSJustProxy bool
	TLSOffload     bool
	AutoSSL        bool
	KeyFile        string
	CertFile       string
	AutoHTTPS      bool
	AutoCORS       bool
	CompatMode     bool
	TargetIsHTTPS  bool
}

type EditHostInput struct {
	ID                      int
	ExpectedRevision        int64
	IsAdmin                 bool
	AllowUserLocal          bool
	ClientID                int
	Host                    string
	Target                  string
	ProxyProtocol           int
	LocalProxy              bool
	Auth                    string
	Header                  string
	RespHeader              string
	HostChange              string
	Remark                  string
	Location                string
	PathRewrite             string
	RedirectURL             string
	FlowLimit               int64
	TimeLimit               string
	RateLimit               int
	MaxConnections          int
	ResetFlow               bool
	EntryACLMode            int
	EntryACLRules           string
	Scheme                  string
	HTTPSJustProxy          bool
	TLSOffload              bool
	AutoSSL                 bool
	KeyFile                 string
	CertFile                string
	AutoHTTPS               bool
	AutoCORS                bool
	CompatMode              bool
	TargetIsHTTPS           bool
	SyncCertToMatchingHosts bool
	SyncHostIDs             []int
}

type IndexMutationContext struct {
	Principal       Principal
	Authz           AuthorizationService
	AllowLocalProxy bool
	AllowUserLocal  bool
}

type TunnelWriteRequest struct {
	ClientID       int
	Port           int
	ServerIP       string
	Mode           string
	TargetType     string
	Target         string
	ProxyProtocol  int
	LocalProxy     bool
	Auth           string
	Remark         string
	Password       string
	LocalPath      string
	StripPre       string
	EnableHTTP     bool
	EnableSocks5   bool
	EntryACLMode   int
	EntryACLRules  string
	DestACLMode    int
	DestACLRules   string
	FlowLimit      int64
	TimeLimit      string
	RateLimit      int
	MaxConnections int
}

type AddTunnelRequest struct {
	TunnelWriteRequest
}

type EditTunnelRequest struct {
	ID               int
	ExpectedRevision int64
	TunnelWriteRequest
	ResetFlow bool
}

type HostWriteRequest struct {
	ClientID       int
	Host           string
	Target         string
	ProxyProtocol  int
	LocalProxy     bool
	Auth           string
	Header         string
	RespHeader     string
	HostChange     string
	Remark         string
	Location       string
	PathRewrite    string
	RedirectURL    string
	FlowLimit      int64
	TimeLimit      string
	RateLimit      int
	MaxConnections int
	EntryACLMode   int
	EntryACLRules  string
	Scheme         string
	HTTPSJustProxy bool
	TLSOffload     bool
	AutoSSL        bool
	KeyFile        string
	CertFile       string
	AutoHTTPS      bool
	AutoCORS       bool
	CompatMode     bool
	TargetIsHTTPS  bool
}

type AddHostRequest struct {
	HostWriteRequest
}

type EditHostRequest struct {
	ID               int
	ExpectedRevision int64
	HostWriteRequest
	ResetFlow               bool
	SyncCertToMatchingHosts bool
	SyncHostIDs             []int
}

func BuildAddTunnelInput(ctx IndexMutationContext, request AddTunnelRequest) AddTunnelInput {
	policy := resolveIndexMutationPolicy(ctx)
	return AddTunnelInput{
		IsAdmin:        policy.isAdmin,
		AllowUserLocal: policy.allowUserLocal,
		ClientID:       request.ClientID,
		Port:           request.Port,
		ServerIP:       request.ServerIP,
		Mode:           request.Mode,
		TargetType:     request.TargetType,
		Target:         request.Target,
		ProxyProtocol:  request.ProxyProtocol,
		LocalProxy:     request.LocalProxy,
		Auth:           request.Auth,
		Remark:         request.Remark,
		Password:       request.Password,
		LocalPath:      request.LocalPath,
		StripPre:       request.StripPre,
		EnableHTTP:     request.EnableHTTP,
		EnableSocks5:   request.EnableSocks5,
		EntryACLMode:   request.EntryACLMode,
		EntryACLRules:  request.EntryACLRules,
		DestACLMode:    request.DestACLMode,
		DestACLRules:   request.DestACLRules,
		FlowLimit:      request.FlowLimit,
		TimeLimit:      request.TimeLimit,
		RateLimit:      request.RateLimit,
		MaxConnections: request.MaxConnections,
	}
}

func BuildEditTunnelInput(ctx IndexMutationContext, request EditTunnelRequest) EditTunnelInput {
	policy := resolveIndexMutationPolicy(ctx)
	return EditTunnelInput{
		ID:               request.ID,
		ExpectedRevision: request.ExpectedRevision,
		IsAdmin:          policy.isAdmin,
		AllowUserLocal:   policy.allowUserLocal,
		ClientID:         request.ClientID,
		Port:             request.Port,
		ServerIP:         request.ServerIP,
		Mode:             request.Mode,
		TargetType:       request.TargetType,
		Target:           request.Target,
		ProxyProtocol:    request.ProxyProtocol,
		LocalProxy:       request.LocalProxy,
		Auth:             request.Auth,
		Remark:           request.Remark,
		Password:         request.Password,
		LocalPath:        request.LocalPath,
		StripPre:         request.StripPre,
		EnableHTTP:       request.EnableHTTP,
		EnableSocks5:     request.EnableSocks5,
		EntryACLMode:     request.EntryACLMode,
		EntryACLRules:    request.EntryACLRules,
		DestACLMode:      request.DestACLMode,
		DestACLRules:     request.DestACLRules,
		FlowLimit:        request.FlowLimit,
		TimeLimit:        request.TimeLimit,
		RateLimit:        request.RateLimit,
		MaxConnections:   request.MaxConnections,
		ResetFlow:        request.ResetFlow,
	}
}

func BuildAddHostInput(ctx IndexMutationContext, request AddHostRequest) AddHostInput {
	policy := resolveIndexMutationPolicy(ctx)
	return AddHostInput{
		IsAdmin:        policy.isAdmin,
		AllowUserLocal: policy.allowUserLocal,
		ClientID:       request.ClientID,
		Host:           request.Host,
		Target:         request.Target,
		ProxyProtocol:  request.ProxyProtocol,
		LocalProxy:     request.LocalProxy,
		Auth:           request.Auth,
		Header:         request.Header,
		RespHeader:     request.RespHeader,
		HostChange:     request.HostChange,
		Remark:         request.Remark,
		Location:       request.Location,
		PathRewrite:    request.PathRewrite,
		RedirectURL:    request.RedirectURL,
		FlowLimit:      request.FlowLimit,
		TimeLimit:      request.TimeLimit,
		RateLimit:      request.RateLimit,
		MaxConnections: request.MaxConnections,
		EntryACLMode:   request.EntryACLMode,
		EntryACLRules:  request.EntryACLRules,
		Scheme:         request.Scheme,
		HTTPSJustProxy: request.HTTPSJustProxy,
		TLSOffload:     request.TLSOffload,
		AutoSSL:        request.AutoSSL,
		KeyFile:        request.KeyFile,
		CertFile:       request.CertFile,
		AutoHTTPS:      request.AutoHTTPS,
		AutoCORS:       request.AutoCORS,
		CompatMode:     request.CompatMode,
		TargetIsHTTPS:  request.TargetIsHTTPS,
	}
}

func BuildEditHostInput(ctx IndexMutationContext, request EditHostRequest) EditHostInput {
	policy := resolveIndexMutationPolicy(ctx)
	return EditHostInput{
		ID:                      request.ID,
		ExpectedRevision:        request.ExpectedRevision,
		IsAdmin:                 policy.isAdmin,
		AllowUserLocal:          policy.allowUserLocal,
		ClientID:                request.ClientID,
		Host:                    request.Host,
		Target:                  request.Target,
		ProxyProtocol:           request.ProxyProtocol,
		LocalProxy:              request.LocalProxy,
		Auth:                    request.Auth,
		Header:                  request.Header,
		RespHeader:              request.RespHeader,
		HostChange:              request.HostChange,
		Remark:                  request.Remark,
		Location:                request.Location,
		PathRewrite:             request.PathRewrite,
		RedirectURL:             request.RedirectURL,
		FlowLimit:               request.FlowLimit,
		TimeLimit:               request.TimeLimit,
		RateLimit:               request.RateLimit,
		MaxConnections:          request.MaxConnections,
		ResetFlow:               request.ResetFlow,
		EntryACLMode:            request.EntryACLMode,
		EntryACLRules:           request.EntryACLRules,
		Scheme:                  request.Scheme,
		HTTPSJustProxy:          request.HTTPSJustProxy,
		TLSOffload:              request.TLSOffload,
		AutoSSL:                 request.AutoSSL,
		KeyFile:                 request.KeyFile,
		CertFile:                request.CertFile,
		AutoHTTPS:               request.AutoHTTPS,
		AutoCORS:                request.AutoCORS,
		CompatMode:              request.CompatMode,
		TargetIsHTTPS:           request.TargetIsHTTPS,
		SyncCertToMatchingHosts: request.SyncCertToMatchingHosts,
		SyncHostIDs:             append([]int(nil), request.SyncHostIDs...),
	}
}

type indexMutationPolicy struct {
	isAdmin        bool
	allowUserLocal bool
}

func resolveIndexMutationPolicy(ctx IndexMutationContext) indexMutationPolicy {
	principal := authorizationOrDefault(ctx.Authz).NormalizePrincipal(ctx.Principal)
	isAdmin := principal.Authenticated && permissionSetAllows(principal.Permissions, PermissionManagementAdmin)
	return indexMutationPolicy{
		isAdmin:        isAdmin,
		allowUserLocal: ctx.AllowLocalProxy && (ctx.AllowUserLocal || isAdmin),
	}
}

func (s DefaultIndexService) DashboardData(force bool) map[string]interface{} {
	return s.runtime().DashboardData(force)
}

func (s DefaultIndexService) ListTunnels(input TunnelListInput) ([]*file.Tunnel, int) {
	if !hasVisibilityScope(input.Visibility) || input.Visibility.IsAdmin {
		rows, count := s.runtime().ListTunnels(input.Offset, input.Limit, input.Type, input.ClientID, input.Search, input.Sort, input.Order)
		return cloneTunnelSnapshotList(rows), count
	}
	scope := visibleClientScope(input.Visibility)
	if len(scope.ids) == 0 {
		return nil, 0
	}
	if input.ClientID > 0 {
		if !scope.has(input.ClientID) {
			return nil, 0
		}
		rows, count := s.runtime().ListTunnels(input.Offset, input.Limit, input.Type, input.ClientID, input.Search, input.Sort, input.Order)
		return cloneTunnelSnapshotList(rows), count
	}
	if len(scope.ids) == 1 {
		rows, count := s.runtime().ListTunnels(input.Offset, input.Limit, input.Type, scope.firstID(), input.Search, input.Sort, input.Order)
		return cloneTunnelSnapshotList(rows), count
	}
	rows, count := s.runtime().ListVisibleTunnels(input.Offset, input.Limit, input.Type, scope.ids, input.Search, input.Sort, input.Order)
	return cloneTunnelSnapshotList(rows), count
}

func hasVisibilityScope(visibility ClientVisibility) bool {
	return visibility.IsAdmin || visibility.PrimaryClientID > 0 || len(visibility.ClientIDs) > 0
}

func (s DefaultIndexService) ListHosts(input HostListInput) ([]*file.Host, int) {
	if !hasVisibilityScope(input.Visibility) || input.Visibility.IsAdmin {
		rows, count := s.runtime().ListHosts(input.Offset, input.Limit, input.ClientID, input.Search, input.Sort, input.Order)
		return cloneHostSnapshotList(rows), count
	}
	scope := visibleClientScope(input.Visibility)
	if len(scope.ids) == 0 {
		return nil, 0
	}
	if input.ClientID > 0 {
		if !scope.has(input.ClientID) {
			return nil, 0
		}
		rows, count := s.runtime().ListHosts(input.Offset, input.Limit, input.ClientID, input.Search, input.Sort, input.Order)
		return cloneHostSnapshotList(rows), count
	}
	if len(scope.ids) == 1 {
		rows, count := s.runtime().ListHosts(input.Offset, input.Limit, scope.firstID(), input.Search, input.Sort, input.Order)
		return cloneHostSnapshotList(rows), count
	}
	rows, count := s.runtime().ListVisibleHosts(input.Offset, input.Limit, scope.ids, input.Search, input.Sort, input.Order)
	return cloneHostSnapshotList(rows), count
}

func (s DefaultIndexService) AddTunnel(input AddTunnelInput) (TunnelMutation, error) {
	id := s.repo().NextTunnelID()
	entryACLMode, entryACLRules := normalizeEntryACLInput(input.EntryACLMode, input.EntryACLRules)
	tunnel := &file.Tunnel{
		Port:       input.Port,
		ServerIp:   input.ServerIP,
		Mode:       input.Mode,
		TargetType: input.TargetType,
		Target: &file.Target{
			TargetStr:     sanitizeBridgeTarget(input.Target, input.IsAdmin, ""),
			ProxyProtocol: input.ProxyProtocol,
			LocalProxy:    localProxyEnabled(input.ClientID, input.LocalProxy, input.AllowUserLocal),
		},
		UserAuth:      file.NewMultiAccount(input.Auth),
		Id:            id,
		Status:        true,
		Remark:        input.Remark,
		Password:      input.Password,
		LocalPath:     input.LocalPath,
		StripPre:      input.StripPre,
		HttpProxy:     input.EnableHTTP,
		Socks5Proxy:   input.EnableSocks5,
		EntryAclMode:  entryACLMode,
		EntryAclRules: entryACLRules,
		Flow: &file.Flow{
			FlowLimit: input.FlowLimit,
			TimeLimit: common.GetTimeNoErrByStr(input.TimeLimit),
		},
		RateLimit: input.RateLimit,
		MaxConn:   input.MaxConnections,
	}
	tunnel.DestAclMode, tunnel.DestAclRules = normalizeDestinationACLInput(input.DestACLMode, input.DestACLRules)
	tunnel.TouchMeta()

	if _, err := s.resolveTunnelPort(tunnel); err != nil {
		return TunnelMutation{}, err
	}

	client, err := s.resolveClient(input.ClientID)
	if err != nil {
		return TunnelMutation{}, err
	}
	tunnel.Client = client
	if err := s.ensureUserTunnelQuota(client, 0); err != nil {
		return TunnelMutation{}, err
	}
	if err := s.ensureClientResourceQuota(tunnel.Client, 0); err != nil {
		return TunnelMutation{}, err
	}

	if err := s.repo().CreateTunnel(tunnel); err != nil {
		return TunnelMutation{}, err
	}
	if err := s.runtime().AddTunnel(tunnel); err != nil {
		normalizedErr := normalizeRuntimeError(err)
		if rollbackErr := s.repo().DeleteTunnelRecord(tunnel.Id); rollbackErr != nil {
			return TunnelMutation{}, errors.Join(normalizedErr, rollbackErr)
		}
		return TunnelMutation{}, normalizedErr
	}

	emitTunnelEvent("tunnel.created", "create", tunnel)
	return newRuntimeTunnelMutationResult(s.runtime(), tunnel), nil
}

func (s DefaultIndexService) GetTunnel(id int) (*file.Tunnel, error) {
	repo := s.repo()
	tunnel, err := repo.GetTunnel(id)
	if err != nil {
		return nil, mapTunnelNotFound(err)
	}
	if tunnel == nil {
		return nil, ErrTunnelNotFound
	}
	cloned := ensureDetachedTunnelSnapshot(repo, tunnel)
	if cloned != nil {
		cloned.RunStatus = s.runtime().TunnelRunning(id)
	}
	return cloned, nil
}

func (s DefaultIndexService) EditTunnel(input EditTunnelInput) (TunnelMutation, error) {
	repo := s.repo()
	tunnel, err := repo.GetTunnel(input.ID)
	if err != nil {
		return TunnelMutation{}, mapTunnelNotFound(err)
	}
	if tunnel == nil {
		return TunnelMutation{}, ErrTunnelNotFound
	}
	working := ensureDetachedTunnelMutation(repo, tunnel)
	previousClientID := 0
	previousUserID := 0
	if tunnel.Client != nil {
		previousClientID = tunnel.Client.Id
		previousUserID = tunnel.Client.OwnerID()
	}
	effectiveClientID := input.ClientID
	if effectiveClientID <= 0 && tunnel.Client != nil {
		effectiveClientID = tunnel.Client.Id
	}

	client, err := s.resolveClient(effectiveClientID)
	if err != nil {
		return TunnelMutation{}, err
	}
	working.Client = client
	if err := s.ensureUserTunnelQuota(client, previousUserID); err != nil {
		return TunnelMutation{}, err
	}
	if err := s.ensureClientResourceQuota(client, previousClientID); err != nil {
		return TunnelMutation{}, err
	}

	desiredMode := input.Mode
	if desiredMode == "" {
		desiredMode = working.Mode
	}
	probe := &file.Tunnel{
		Port:        input.Port,
		Mode:        desiredMode,
		HttpProxy:   input.EnableHTTP,
		Socks5Proxy: input.EnableSocks5,
	}
	if probe.Port <= 0 {
		probe.Port = working.Port
	}
	if probe.Port != working.Port || probe.Mode != working.Mode || probe.Socks5Proxy != working.Socks5Proxy {
		if _, err := s.resolveTunnelPort(probe); err != nil {
			return TunnelMutation{}, err
		}
	}

	targetFallback := ""
	if working.Target != nil {
		targetFallback = working.Target.TargetStr
	}

	working.Port = probe.Port
	working.ServerIp = input.ServerIP
	working.Mode = desiredMode
	working.TargetType = input.TargetType
	working.Target = &file.Target{
		TargetStr:     sanitizeBridgeTarget(input.Target, input.IsAdmin, targetFallback),
		ProxyProtocol: input.ProxyProtocol,
		LocalProxy:    localProxyEnabled(effectiveClientID, input.LocalProxy, input.AllowUserLocal),
	}
	working.UserAuth = file.NewMultiAccount(input.Auth)
	working.Password = input.Password
	working.LocalPath = input.LocalPath
	working.StripPre = input.StripPre
	working.HttpProxy = input.EnableHTTP
	working.Socks5Proxy = input.EnableSocks5
	working.EntryAclMode, working.EntryAclRules = normalizeEntryACLInput(input.EntryACLMode, input.EntryACLRules)
	working.DestAclMode, working.DestAclRules = normalizeDestinationACLInput(input.DestACLMode, input.DestACLRules)
	working.Remark = input.Remark
	working.Flow.FlowLimit = input.FlowLimit
	working.Flow.TimeLimit = common.GetTimeNoErrByStr(input.TimeLimit)
	working.RateLimit = input.RateLimit
	working.MaxConn = input.MaxConnections
	if input.ResetFlow {
		working.Flow.ExportFlow = 0
		working.Flow.InletFlow = 0
	}
	working.TouchMeta()
	working.ExpectedRevision = input.ExpectedRevision

	if err := repo.SaveTunnel(working); err != nil {
		if errors.Is(err, file.ErrRevisionConflict) {
			return TunnelMutation{}, ErrRevisionConflict
		}
		return TunnelMutation{}, mapTunnelNotFound(err)
	}
	if err := s.runtime().StopTunnel(working.Id); err != nil && !isTaskNotRunning(err) {
		return TunnelMutation{}, mapTunnelNotFound(err)
	}
	if err := s.runtime().StartTunnel(working.Id); err != nil {
		return TunnelMutation{}, mapTunnelNotFound(normalizeRuntimeError(err))
	}

	emitTunnelEvent("tunnel.updated", "update", working)
	return newRuntimeTunnelMutationResult(s.runtime(), working), nil
}

func (s DefaultIndexService) StopTunnel(id int, mode string) (TunnelMutation, error) {
	if mode != "" {
		return changeTunnelStatusWithRepo(s.repo(), s.runtime(), id, mode, "stop")
	}
	repo := s.repo()
	tunnel, err := repo.GetTunnel(id)
	if err != nil {
		return TunnelMutation{}, mapTunnelNotFound(err)
	}
	if tunnel == nil {
		return TunnelMutation{}, ErrTunnelNotFound
	}
	if err := s.runtime().StopTunnel(id); err != nil && !isTaskNotRunning(err) {
		if errors.Is(err, file.ErrTaskNotFound) {
			return TunnelMutation{}, ErrTunnelNotFound
		}
		return TunnelMutation{}, err
	}
	emitTunnelEvent("tunnel.stopped", "stop", tunnel)
	return newRuntimeTunnelMutationResult(s.runtime(), tunnel), nil
}

func (s DefaultIndexService) DeleteTunnel(id int) (TunnelMutation, error) {
	repo := s.repo()
	var deleted *file.Tunnel
	if tunnel, err := repo.GetTunnel(id); err == nil && tunnel != nil {
		deleted = ensureDetachedTunnelMutation(repo, tunnel)
	}
	if err := s.runtime().DeleteTunnel(id); err != nil {
		if !isTaskNotRunning(err) {
			return TunnelMutation{}, err
		}
	}
	if err := repo.DeleteTunnelRecord(id); err != nil {
		if errors.Is(err, file.ErrTaskNotFound) {
			return TunnelMutation{}, ErrTunnelNotFound
		}
		return TunnelMutation{}, err
	}
	if deleted == nil {
		return TunnelMutation{ID: id}, nil
	}
	deleted.NowConn = 0
	emitTunnelEvent("tunnel.deleted", "delete", deleted)
	return newRuntimeTunnelMutationResult(s.runtime(), deleted), nil
}

func (s DefaultIndexService) StartTunnel(id int, mode string) (TunnelMutation, error) {
	if mode != "" {
		return changeTunnelStatusWithRepo(s.repo(), s.runtime(), id, mode, "start")
	}
	repo := s.repo()
	tunnel, err := repo.GetTunnel(id)
	if err != nil {
		return TunnelMutation{}, mapTunnelNotFound(err)
	}
	if tunnel == nil {
		return TunnelMutation{}, ErrTunnelNotFound
	}
	if err := normalizeRuntimeError(s.runtime().StartTunnel(id)); err != nil {
		if errors.Is(err, file.ErrTaskNotFound) {
			return TunnelMutation{}, ErrTunnelNotFound
		}
		return TunnelMutation{}, err
	}
	emitTunnelEvent("tunnel.started", "start", tunnel)
	return newRuntimeTunnelMutationResult(s.runtime(), tunnel), nil
}

func (s DefaultIndexService) ClearTunnel(id int, mode string) (TunnelMutation, error) {
	if strings.TrimSpace(mode) == "" {
		return TunnelMutation{}, ErrModeRequired
	}
	return changeTunnelStatusWithRepo(s.repo(), s.runtime(), id, mode, "clear")
}

func changeTunnelStatusWithRepo(repo IndexRepository, runtime IndexRuntime, id int, name, action string) (TunnelMutation, error) {
	tunnel, err := repo.GetTunnel(id)
	if err != nil {
		return TunnelMutation{}, mapTunnelNotFound(err)
	}
	if tunnel == nil {
		return TunnelMutation{}, ErrTunnelNotFound
	}
	working := ensureDetachedTunnelMutation(repo, tunnel)

	switch strings.TrimSpace(name) {
	case "http":
		if err := applyBoolAction(&working.HttpProxy, action); err != nil {
			return TunnelMutation{}, err
		}
	case "socks5":
		if err := applyBoolAction(&working.Socks5Proxy, action); err != nil {
			return TunnelMutation{}, err
		}
	case "flow":
		if normalizeAction(action) != "clear" {
			return TunnelMutation{}, fmt.Errorf("unsupported action %q for %s", action, name)
		}
		working.ResetServiceTraffic()
	case "flow_limit":
		if normalizeAction(action) != "clear" {
			return TunnelMutation{}, fmt.Errorf("unsupported action %q for %s", action, name)
		}
		working.SetFlowLimitBytes(0)
	case "time_limit":
		if normalizeAction(action) != "clear" {
			return TunnelMutation{}, fmt.Errorf("unsupported action %q for %s", action, name)
		}
		working.SetExpireAt(0)
	default:
		return TunnelMutation{}, fmt.Errorf("unknown name: %q", name)
	}

	working.TouchMeta()
	if err := repo.SaveTunnel(working); err != nil {
		return TunnelMutation{}, mapTunnelNotFound(err)
	}
	emitTunnelEvent("tunnel.updated", "update", working)
	return newRuntimeTunnelMutationResult(runtime, working), nil
}

func cloneTunnelSnapshotList(tunnels []*file.Tunnel) []*file.Tunnel {
	if len(tunnels) == 0 {
		return nil
	}
	cloned := make([]*file.Tunnel, 0, len(tunnels))
	for _, tunnel := range tunnels {
		cloned = append(cloned, cloneTunnelSnapshot(tunnel))
	}
	return cloned
}

func (s DefaultIndexService) GetHost(id int) (*file.Host, error) {
	repo := s.repo()
	host, err := repo.GetHost(id)
	if err != nil {
		return nil, mapHostNotFound(err)
	}
	if host == nil {
		return nil, ErrHostNotFound
	}
	return ensureDetachedHostSnapshot(repo, host), nil
}

func cloneHostSnapshotList(hosts []*file.Host) []*file.Host {
	if len(hosts) == 0 {
		return nil
	}
	cloned := make([]*file.Host, 0, len(hosts))
	for _, host := range hosts {
		cloned = append(cloned, cloneHostSnapshot(host))
	}
	return cloned
}

func (s DefaultIndexService) DeleteHost(id int) (HostMutation, error) {
	repo := s.repo()
	var deleted *file.Host
	if host, err := repo.GetHost(id); err == nil && host != nil {
		deleted = ensureDetachedHostMutation(repo, host)
	}
	if err := repo.DeleteHostRecord(id); err != nil {
		if errors.Is(err, file.ErrHostNotFound) {
			return HostMutation{}, ErrHostNotFound
		}
		return HostMutation{}, err
	}
	s.runtime().RemoveHostCache(id)
	if deleted == nil {
		return HostMutation{ID: id}, nil
	}
	deleted.NowConn = 0
	return newHostMutationResult(deleted), nil
}

func (s DefaultIndexService) StartHost(id int, mode string) (HostMutation, error) {
	if mode != "" {
		mutation, err := changeHostStatusWithRepo(s.repo(), id, mode, "start")
		if err != nil {
			return HostMutation{}, err
		}
		s.runtime().RemoveHostCache(id)
		return mutation, nil
	}
	return s.setHostClosedState(id, false)
}

func (s DefaultIndexService) StopHost(id int, mode string) (HostMutation, error) {
	if mode != "" {
		mutation, err := changeHostStatusWithRepo(s.repo(), id, mode, "stop")
		if err != nil {
			return HostMutation{}, err
		}
		s.runtime().RemoveHostCache(id)
		return mutation, nil
	}
	return s.setHostClosedState(id, true)
}

func (s DefaultIndexService) setHostClosedState(id int, closed bool) (HostMutation, error) {
	repo := s.repo()
	host, err := repo.GetHost(id)
	if err != nil {
		return HostMutation{}, mapHostNotFound(err)
	}
	if host == nil {
		return HostMutation{}, ErrHostNotFound
	}
	working := ensureDetachedHostMutation(repo, host)
	working.IsClose = closed
	working.TouchMeta()
	if err := repo.SaveHost(working, ""); err != nil {
		return HostMutation{}, mapHostNotFound(err)
	}
	s.runtime().RemoveHostCache(id)
	return newHostMutationResult(working), nil
}

func (s DefaultIndexService) ClearHost(id int, mode string) (HostMutation, error) {
	if strings.TrimSpace(mode) == "" {
		return HostMutation{}, ErrModeRequired
	}
	mutation, err := changeHostStatusWithRepo(s.repo(), id, mode, "clear")
	if err != nil {
		return HostMutation{}, err
	}
	s.runtime().RemoveHostCache(id)
	return mutation, nil
}

func changeHostStatusWithRepo(repo IndexRepository, id int, name, action string) (HostMutation, error) {
	host, err := repo.GetHost(id)
	if err != nil {
		return HostMutation{}, mapHostNotFound(err)
	}
	if host == nil {
		return HostMutation{}, ErrHostNotFound
	}
	working := ensureDetachedHostMutation(repo, host)

	switch strings.TrimSpace(name) {
	case "flow":
		if normalizeAction(action) != "clear" {
			return HostMutation{}, fmt.Errorf("unsupported action %q for %s", action, name)
		}
		working.ResetServiceTraffic()
	case "flow_limit":
		if normalizeAction(action) != "clear" {
			return HostMutation{}, fmt.Errorf("unsupported action %q for %s", action, name)
		}
		working.SetFlowLimitBytes(0)
	case "time_limit":
		if normalizeAction(action) != "clear" {
			return HostMutation{}, fmt.Errorf("unsupported action %q for %s", action, name)
		}
		working.SetExpireAt(0)
	case "auto_ssl":
		if err := applyBoolAction(&working.AutoSSL, action); err != nil {
			return HostMutation{}, err
		}
	case "https_just_proxy":
		if err := applyBoolAction(&working.HttpsJustProxy, action); err != nil {
			return HostMutation{}, err
		}
	case "tls_offload":
		if err := applyBoolAction(&working.TlsOffload, action); err != nil {
			return HostMutation{}, err
		}
	case "auto_https":
		if err := applyBoolAction(&working.AutoHttps, action); err != nil {
			return HostMutation{}, err
		}
	case "auto_cors":
		if err := applyBoolAction(&working.AutoCORS, action); err != nil {
			return HostMutation{}, err
		}
	case "compat_mode":
		if err := applyBoolAction(&working.CompatMode, action); err != nil {
			return HostMutation{}, err
		}
	case "target_is_https":
		if err := applyBoolAction(&working.TargetIsHttps, action); err != nil {
			return HostMutation{}, err
		}
	default:
		return HostMutation{}, fmt.Errorf("unknown name: %q", name)
	}

	working.CertType = common.GetCertType(working.CertFile)
	working.CertHash = crypt.FNV1a64(working.CertType, working.CertFile, working.KeyFile)
	working.TouchMeta()
	if err := repo.SaveHost(working, ""); err != nil {
		return HostMutation{}, mapHostNotFound(err)
	}
	return newHostMutationResult(working), nil
}

func (s DefaultIndexService) AddHost(input AddHostInput) (HostMutation, error) {
	id := s.repo().NextHostID()
	entryACLMode, entryACLRules := normalizeEntryACLInput(input.EntryACLMode, input.EntryACLRules)
	host := &file.Host{
		Id:   id,
		Host: input.Host,
		Target: &file.Target{
			TargetStr:     sanitizeBridgeTarget(input.Target, input.IsAdmin, ""),
			ProxyProtocol: input.ProxyProtocol,
			LocalProxy:    localProxyEnabled(input.ClientID, input.LocalProxy, input.AllowUserLocal),
		},
		UserAuth:         file.NewMultiAccount(input.Auth),
		HeaderChange:     input.Header,
		RespHeaderChange: input.RespHeader,
		HostChange:       input.HostChange,
		Remark:           input.Remark,
		Location:         input.Location,
		PathRewrite:      input.PathRewrite,
		RedirectURL:      input.RedirectURL,
		EntryAclMode:     entryACLMode,
		EntryAclRules:    entryACLRules,
		Flow: &file.Flow{
			FlowLimit: input.FlowLimit,
			TimeLimit: common.GetTimeNoErrByStr(input.TimeLimit),
		},
		RateLimit:      input.RateLimit,
		MaxConn:        input.MaxConnections,
		Scheme:         normalizeScheme(input.Scheme),
		HttpsJustProxy: input.HTTPSJustProxy,
		TlsOffload:     input.TLSOffload,
		AutoSSL:        input.AutoSSL,
		KeyFile:        input.KeyFile,
		CertFile:       input.CertFile,
		AutoHttps:      input.AutoHTTPS,
		AutoCORS:       input.AutoCORS,
		CompatMode:     input.CompatMode,
		TargetIsHttps:  input.TargetIsHTTPS,
	}
	host.TouchMeta()

	client, err := s.resolveClient(input.ClientID)
	if err != nil {
		return HostMutation{}, err
	}
	host.Client = client
	if err := s.ensureUserHostQuota(client, 0); err != nil {
		return HostMutation{}, err
	}
	if err := s.ensureClientResourceQuota(host.Client, 0); err != nil {
		return HostMutation{}, err
	}

	if err := s.repo().CreateHost(host); err != nil {
		if isHostExistsError(err) {
			return HostMutation{}, ErrHostExists
		}
		return HostMutation{}, err
	}

	return newHostMutationResult(host), nil
}

func (s DefaultIndexService) EditHost(input EditHostInput) (HostMutation, error) {
	repo := s.repo()
	host, err := repo.GetHost(input.ID)
	if err != nil {
		return HostMutation{}, mapHostNotFound(err)
	}
	if host == nil {
		return HostMutation{}, ErrHostNotFound
	}
	working := ensureDetachedHostMutation(repo, host)
	previousClientID := 0
	previousUserID := 0
	if host.Client != nil {
		previousClientID = host.Client.Id
		previousUserID = host.Client.OwnerID()
	}
	effectiveClientID := input.ClientID
	if effectiveClientID <= 0 && host.Client != nil {
		effectiveClientID = host.Client.Id
	}

	oldHost := working.Host
	scheme := normalizeScheme(input.Scheme)
	if working.Host != input.Host || working.Location != input.Location || working.Scheme != scheme {
		tmpHost := &file.Host{Id: working.Id, Host: input.Host, Location: input.Location, Scheme: scheme}
		if repo.HostExists(tmpHost) {
			return HostMutation{}, ErrHostExists
		}
	}

	client, err := s.resolveClient(effectiveClientID)
	if err != nil {
		return HostMutation{}, err
	}
	working.Client = client
	if err := s.ensureUserHostQuota(client, previousUserID); err != nil {
		return HostMutation{}, err
	}
	if err := s.ensureClientResourceQuota(client, previousClientID); err != nil {
		return HostMutation{}, err
	}

	targetFallback := ""
	if working.Target != nil {
		targetFallback = working.Target.TargetStr
	}

	working.Host = input.Host
	working.Target = &file.Target{
		TargetStr:     sanitizeBridgeTarget(input.Target, input.IsAdmin, targetFallback),
		ProxyProtocol: input.ProxyProtocol,
		LocalProxy:    localProxyEnabled(effectiveClientID, input.LocalProxy, input.AllowUserLocal),
	}
	working.UserAuth = file.NewMultiAccount(input.Auth)
	working.HeaderChange = input.Header
	working.RespHeaderChange = input.RespHeader
	working.HostChange = input.HostChange
	working.Remark = input.Remark
	working.Location = input.Location
	working.PathRewrite = input.PathRewrite
	working.RedirectURL = input.RedirectURL
	working.EntryAclMode, working.EntryAclRules = normalizeEntryACLInput(input.EntryACLMode, input.EntryACLRules)
	working.Scheme = scheme
	working.HttpsJustProxy = input.HTTPSJustProxy
	working.TlsOffload = input.TLSOffload
	working.AutoSSL = input.AutoSSL
	working.KeyFile = input.KeyFile
	working.CertFile = input.CertFile
	working.Flow.FlowLimit = input.FlowLimit
	working.Flow.TimeLimit = common.GetTimeNoErrByStr(input.TimeLimit)
	working.RateLimit = input.RateLimit
	working.MaxConn = input.MaxConnections
	if input.ResetFlow {
		working.Flow.ExportFlow = 0
		working.Flow.InletFlow = 0
	}
	working.AutoHttps = input.AutoHTTPS
	working.AutoCORS = input.AutoCORS
	working.CompatMode = input.CompatMode
	working.TargetIsHttps = input.TargetIsHTTPS

	working.CertType = common.GetCertType(working.CertFile)
	working.CertHash = crypt.FNV1a64(working.CertType, working.CertFile, working.KeyFile)
	working.TouchMeta()
	working.ExpectedRevision = input.ExpectedRevision
	if err := repo.SaveHost(working, oldHost); err != nil {
		if errors.Is(err, file.ErrRevisionConflict) {
			return HostMutation{}, ErrRevisionConflict
		}
		return HostMutation{}, mapHostNotFound(err)
	}
	s.runtime().RemoveHostCache(input.ID)
	if err := s.syncCertToMatchingHosts(input, working); err != nil {
		return HostMutation{}, err
	}

	return newHostMutationResult(working), nil
}

func syncHostIDSet(ids []int) map[int]struct{} {
	if len(ids) == 0 {
		return nil
	}
	allowed := make(map[int]struct{}, len(ids))
	for _, id := range ids {
		if id > 0 {
			allowed[id] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func newTunnelMutationResult(tunnel *file.Tunnel) TunnelMutation {
	if tunnel == nil {
		return TunnelMutation{}
	}
	result := TunnelMutation{
		ID:     tunnel.Id,
		Mode:   tunnel.Mode,
		Tunnel: cloneTunnelSnapshot(tunnel),
	}
	if tunnel.Client != nil {
		result.ClientID = tunnel.Client.Id
	}
	return result
}

func newRuntimeTunnelMutationResult(runtime IndexRuntime, tunnel *file.Tunnel) TunnelMutation {
	result := newTunnelMutationResult(tunnel)
	if result.Tunnel == nil || runtime == nil {
		return result
	}
	result.Tunnel.RunStatus = runtime.TunnelRunning(result.ID)
	return result
}

func newHostMutationResult(host *file.Host) HostMutation {
	if host == nil {
		return HostMutation{}
	}
	result := HostMutation{
		ID:   host.Id,
		Host: cloneHostSnapshot(host),
	}
	if host.Client != nil {
		result.ClientID = host.Client.Id
	}
	return result
}

func sortedSyncHostIDs(allowed map[int]struct{}) []int {
	if len(allowed) == 0 {
		return nil
	}
	ids := make([]int, 0, len(allowed))
	for id := range allowed {
		if id > 0 {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	return ids
}

func normalizeCertSyncHost(value string) string {
	return strings.TrimSpace(strings.ToLower(common.GetIpByAddr(value)))
}

func certDomainCoversHostRule(domainPattern, hostRule string) bool {
	domainPattern = normalizeCertSyncHost(domainPattern)
	hostRule = normalizeCertSyncHost(hostRule)
	if domainPattern == "" || hostRule == "" {
		return false
	}
	if domainPattern == hostRule {
		return true
	}
	if strings.HasPrefix(hostRule, "*.") {
		return false
	}
	if !strings.HasPrefix(domainPattern, "*.") {
		return false
	}
	suffix := domainPattern[1:]
	if !strings.HasSuffix(hostRule, suffix) {
		return false
	}
	prefix := strings.TrimSuffix(hostRule, suffix)
	return prefix != "" && !strings.Contains(prefix, ".") && !strings.Contains(prefix, "*")
}

func certDomainsCoverHostRule(domains []string, hostRule string) bool {
	for _, domain := range domains {
		if certDomainCoversHostRule(domain, hostRule) {
			return true
		}
	}
	return false
}

func hostEligibleForCertSync(host *file.Host) bool {
	if host == nil {
		return false
	}
	if host.Scheme == "http" || host.HttpsJustProxy {
		return false
	}
	return normalizeCertSyncHost(host.Host) != ""
}

func (s DefaultIndexService) syncCertToMatchingHosts(input EditHostInput, current *file.Host) error {
	if !input.SyncCertToMatchingHosts || current == nil {
		return nil
	}
	if strings.TrimSpace(current.CertFile) == "" || strings.TrimSpace(current.KeyFile) == "" {
		return nil
	}

	allowed := syncHostIDSet(input.SyncHostIDs)
	if len(allowed) == 0 {
		return nil
	}
	domains, err := common.LoadCertDomains(current.CertFile, current.KeyFile)
	if err != nil || len(domains) == 0 {
		return nil
	}

	for _, hostID := range sortedSyncHostIDs(allowed) {
		if hostID == current.Id {
			continue
		}
		candidate, err := s.repo().GetHost(hostID)
		switch {
		case err == nil:
		case errors.Is(err, file.ErrHostNotFound):
			continue
		default:
			return err
		}
		if candidate == nil || !hostEligibleForCertSync(candidate) || !certDomainsCoverHostRule(domains, candidate.Host) {
			continue
		}

		working := ensureDetachedHostMutation(s.repo(), candidate)
		working.CertFile = current.CertFile
		working.KeyFile = current.KeyFile
		working.CertType = current.CertType
		working.CertHash = current.CertHash
		working.TouchMeta()
		if err := s.repo().SaveHost(working, ""); err != nil {
			if errors.Is(err, file.ErrHostNotFound) {
				continue
			}
			return err
		}
		s.runtime().RemoveHostCache(working.Id)
	}
	return nil
}

func sanitizeBridgeTarget(target string, isAdmin bool, fallback string) string {
	normalized := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(target, "\r\n", "\n")))
	if !isAdmin && strings.Contains(normalized, "bridge://") {
		return fallback
	}
	return normalized
}

func normalizeScheme(scheme string) string {
	switch strings.TrimSpace(strings.ToLower(scheme)) {
	case "http", "https":
		return strings.TrimSpace(strings.ToLower(scheme))
	default:
		return "all"
	}
}

func localProxyEnabled(clientID int, requested bool, allowLocal bool) bool {
	return (clientID > 0 && requested && allowLocal) || clientID <= 0
}

func normalizeRuntimeError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "the port open error") {
		return ErrPortUnavailable
	}
	return err
}

func isTaskNotRunning(err error) bool {
	return err != nil && strings.Contains(err.Error(), "task is not running")
}

func normalizeAction(action string) string {
	return strings.ToLower(strings.TrimSpace(action))
}

func applyBoolAction(dst *bool, action string) error {
	switch normalizeAction(action) {
	case "start", "true", "on":
		*dst = true
	case "stop", "false", "off":
		*dst = false
	case "clear", "turn", "switch":
		*dst = !*dst
	default:
		return fmt.Errorf("unknown action: %q", action)
	}
	return nil
}

func isHostExistsError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "host has exist")
}

func mapTunnelNotFound(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, file.ErrTaskNotFound) {
		return ErrTunnelNotFound
	}
	return err
}

func mapHostNotFound(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, file.ErrHostNotFound) {
		return ErrHostNotFound
	}
	return err
}

func (s DefaultIndexService) repo() IndexRepository {
	if !isNilServiceValue(s.Repo) {
		return s.Repo
	}
	if !isNilServiceValue(s.Backend.Repository) {
		return s.Backend.Repository
	}
	return DefaultBackend().Repository
}

func (s DefaultIndexService) runtime() IndexRuntime {
	if !isNilServiceValue(s.Runtime) {
		return s.Runtime
	}
	if !isNilServiceValue(s.Backend.Runtime) {
		return s.Backend.Runtime
	}
	return DefaultBackend().Runtime
}

func (s DefaultIndexService) resolveClient(clientID int) (*file.Client, error) {
	client, err := s.repo().GetClient(clientID)
	if err != nil {
		return nil, mapClientServiceError(err)
	}
	if client == nil {
		return nil, ErrClientNotFound
	}
	return client, nil
}

func (s DefaultIndexService) resolveTunnelPort(tunnel *file.Tunnel) (int, error) {
	if tunnel.Port <= 0 {
		tunnel.Port = s.runtime().GenerateTunnelPort(tunnel)
	}
	if !s.runtime().TunnelPortAvailable(tunnel) {
		return 0, ErrPortUnavailable
	}
	return tunnel.Port, nil
}

func (s DefaultIndexService) ensureClientResourceQuota(client *file.Client, previousClientID int) error {
	if client == nil || client.Id <= 0 || client.MaxTunnelNum <= 0 || client.Id == previousClientID {
		return nil
	}
	if s.clientResourceCountUpTo(client.Id, client.MaxTunnelNum) >= client.MaxTunnelNum {
		return ErrClientResourceLimitExceeded
	}
	return nil
}

func (s DefaultIndexService) clientResourceCount(clientID int) int {
	return countResourcesByClient(s.repo(), clientID)
}

func (s DefaultIndexService) clientResourceCountUpTo(clientID, stopAfter int) int {
	return countResourcesByClientUpTo(s.repo(), clientID, stopAfter)
}

func (s DefaultIndexService) ensureUserTunnelQuota(client *file.Client, previousUserID int) error {
	return s.ensureUserOwnedResourceQuota(
		client,
		previousUserID,
		func(user *file.User) int { return user.MaxTunnels },
		func(counts ownedUserResourceCounts) int { return counts.Tunnels },
		ErrTunnelLimitExceeded,
	)
}

func (s DefaultIndexService) ensureUserHostQuota(client *file.Client, previousUserID int) error {
	return s.ensureUserOwnedResourceQuota(
		client,
		previousUserID,
		func(user *file.User) int { return user.MaxHosts },
		func(counts ownedUserResourceCounts) int { return counts.Hosts },
		ErrHostLimitExceeded,
	)
}

func (s DefaultIndexService) ensureUserOwnedResourceQuota(client *file.Client, previousUserID int, limit func(*file.User) int, currentCount func(ownedUserResourceCounts) int, exceeded error) error {
	if limit == nil || currentCount == nil || exceeded == nil {
		return nil
	}
	ownerID := 0
	if client != nil {
		ownerID = client.OwnerID()
	}
	if ownerID <= 0 || ownerID == previousUserID {
		return nil
	}
	quota := s.quotaStore()
	user, err := resolveClientOwnerUser(quota, client)
	if err != nil {
		return mapUserServiceError(err)
	}
	if user == nil {
		return ErrUserNotFound
	}
	resourceLimit := limit(user)
	if resourceLimit <= 0 {
		return nil
	}
	if currentCount(quota.OwnedResourceCountsByUserID(user.Id)) >= resourceLimit {
		return exceeded
	}
	return nil
}

func (s DefaultIndexService) quotaStore() QuotaStore {
	if !isNilServiceValue(s.QuotaStore) {
		return s.QuotaStore
	}
	return DefaultQuotaStore{}
}

func emitTunnelEvent(eventName, action string, tunnel *file.Tunnel) {
	hook := server.ManagementEventHook
	if hook == nil || tunnel == nil {
		return
	}
	targetAddr := ""
	if tunnel.Target != nil {
		tunnel.Target.RLock()
		targetAddr = tunnel.Target.TargetStr
		tunnel.Target.RUnlock()
	}
	fields := map[string]interface{}{
		"id":          tunnel.Id,
		"port":        tunnel.Port,
		"mode":        tunnel.Mode,
		"status":      tunnel.Status,
		"run_status":  tunnel.RunStatus,
		"remark":      tunnel.Remark,
		"target":      targetAddr,
		"target_type": tunnel.TargetType,
		"now_conn":    tunnel.NowConn,
		"max_conn":    tunnel.MaxConn,
		"expire_at":   tunnel.ExpireAt,
		"rate_limit":  tunnel.RateLimit,
	}
	if tunnel.Client != nil {
		fields["client_id"] = tunnel.Client.Id
	}
	if tunnel.Flow != nil {
		tunnel.Flow.RLock()
		fields["flow_in"] = tunnel.Flow.InletFlow
		fields["flow_out"] = tunnel.Flow.ExportFlow
		fields["flow_limit"] = tunnel.Flow.FlowLimit
		tunnel.Flow.RUnlock()
	}
	if tunnel.ServiceTraffic != nil {
		in, out, _ := tunnel.ServiceTraffic.Snapshot()
		fields["service_traffic_in"] = in
		fields["service_traffic_out"] = out
	}
	hook(eventName, "tunnel", action, fields)
}
