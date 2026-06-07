package server

import (
	"math"
	"sort"
	"strings"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/file"
)

func SortClientList(list []*file.Client, sortField, order string) {
	asc := sortOrderAscending(order)
	switch sortField {
	case "Addr":
		sortClientListByOrdered(list, asc, func(client *file.Client) string { return client.Addr })
	case "LocalAddr":
		sortClientListByOrdered(list, asc, func(client *file.Client) string { return client.LocalAddr })
	case "Remark":
		sortClientListByOrdered(list, asc, func(client *file.Client) string { return client.Remark })
	case "VerifyKey":
		sortClientListByOrdered(list, asc, func(client *file.Client) string { return client.VerifyKey })
	case "TotalFlow":
		sortClientListByOrdered(list, asc, clientTotalFlow)
	case "FlowRemain":
		sortClientListByOrdered(list, asc, func(client *file.Client) int64 { return clientFlowRemain(client, asc) })
	case "NowConn":
		sortClientListByOrdered(list, asc, func(client *file.Client) int32 { return client.NowConn })
	case "Version":
		sortClientListByOrdered(list, asc, func(client *file.Client) string { return client.Version })
	case "Mode":
		sortClientListByOrdered(list, asc, func(client *file.Client) string { return client.Mode })
	case "NowRate", "Rate.NowRate":
		sortClientListByOrdered(list, asc, clientRateNow)
	case "Flow.FlowLimit", "FlowLimit":
		sortClientListByUnlimited(list, asc, func(client *file.Client) int64 { return client.EffectiveFlowLimitBytes() })
	case "Flow.TimeLimit", "ExpireAt", "TimeRemain":
		sortClientListByUnlimited(list, asc, func(client *file.Client) int64 { return client.EffectiveExpireAt() })
	case "Status":
		sortClientListByBool(list, asc, func(client *file.Client) bool { return client.Status })
	case "IsConnect":
		sortClientListByBool(list, asc, func(client *file.Client) bool { return client.IsConnect })
	default:
		sortClientListByOrdered(list, asc, func(client *file.Client) int { return client.Id })
	}
}

func sortClientListByOrdered[T orderedListValue](list []*file.Client, asc bool, value func(*file.Client) T) {
	sortStableBy(list, func(left, right *file.Client) bool {
		leftValue := value(left)
		rightValue := value(right)
		if leftValue == rightValue {
			return left.Id < right.Id
		}
		return orderedSortLess(asc, leftValue, rightValue)
	})
}

func sortClientListByBool(list []*file.Client, asc bool, value func(*file.Client) bool) {
	sortStableBy(list, func(left, right *file.Client) bool {
		leftValue := value(left)
		rightValue := value(right)
		if leftValue == rightValue {
			return left.Id < right.Id
		}
		return boolSortLess(asc, leftValue, rightValue)
	})
}

func sortClientListByUnlimited(list []*file.Client, asc bool, value func(*file.Client) int64) {
	sortStableBy(list, func(left, right *file.Client) bool {
		leftValue := value(left)
		rightValue := value(right)
		if leftValue == rightValue {
			return left.Id < right.Id
		}
		return unlimitedInt64SortLess(asc, leftValue, rightValue)
	})
}

// GetClientList get client list
func GetClientList(start, length int, search, sortField, order string, clientId int) (list []*file.Client, cnt int) {
	searchID := common.GetIntNoErrByStr(search)
	if clientId > 0 {
		runtimeFlow.RefreshClient(clientId)
		client, err := file.GetDb().GetClient(clientId)
		if err != nil || client == nil || client.NoDisplay || !matchesClientListSearch(client, search, searchID) {
			return nil, 0
		}
		snapshot := snapshotClientForList(client)
		if snapshot == nil {
			return nil, 0
		}
		return []*file.Client{snapshot}, 1
	}
	runtimeFlow.RefreshClients()
	allList := make([]*file.Client, 0)
	file.GetDb().RangeClients(func(client *file.Client) bool {
		if client.NoDisplay {
			return true
		}
		if !matchesClientListSearch(client, search, searchID) {
			return true
		}
		if snapshot := snapshotClientForList(client); snapshot != nil {
			allList = append(allList, snapshot)
		}
		return true
	})

	SortClientList(allList, sortField, order)
	cnt = len(allList)
	return paginateClientList(allList, start, length), cnt
}

func matchesClientListSearch(client *file.Client, search string, searchID int) bool {
	if search == "" {
		return true
	}
	if client == nil {
		return false
	}
	return client.Id == searchID ||
		common.ContainsFold(client.VerifyKey, search) ||
		common.ContainsFold(client.Remark, search)
}

func paginateClientList(allList []*file.Client, start, length int) []*file.Client {
	if start < 0 {
		start = 0
	}
	if start >= len(allList) {
		return nil
	}
	if length <= 0 || start+length > len(allList) {
		length = len(allList) - start
	}
	return allList[start : start+length]
}

func GetHostList(start, length, clientId int, search, sortField, order string) (list []*file.Host, cnt int) {
	searchID := common.GetIntNoErrByStr(search)
	if clientId > 0 {
		runtimeFlow.RefreshClient(clientId)
		list = collectHostSnapshotsByClientSet(map[int]struct{}{clientId: {}}, search, searchID)
		sortHostList(list, sortField, order)
		cnt = len(list)
		return paginateHostList(list, start, length), cnt
	}
	list = collectAllHostSnapshots(search, searchID)
	sortHostList(list, sortField, order)
	cnt = len(list)
	return paginateHostList(list, start, length), cnt
}

func collectAllHostSnapshots(search string, searchID int) []*file.Host {
	list := make([]*file.Host, 0)
	runtimeFlow.RefreshClients()
	file.GetDb().RangeHosts(func(v *file.Host) bool {
		if !matchesHostListSearch(v, search, searchID) {
			return true
		}
		if snapshot := snapshotHostForList(v); snapshot != nil {
			list = append(list, snapshot)
		}
		return true
	})
	return list
}

func GetHostListByClientIDs(start, length int, clientIDs []int, search, sortField, order string) (list []*file.Host, cnt int) {
	visible := visibleClientSet(clientIDs)
	if len(visible) == 0 {
		return nil, 0
	}
	runtimeFlow.RefreshClientSet(visible)
	searchID := common.GetIntNoErrByStr(search)
	list = collectHostSnapshotsByClientSet(visible, search, searchID)
	cnt = len(list)
	sortHostList(list, sortField, order)
	return paginateHostList(list, start, length), cnt
}

func collectHostSnapshotsByClientSet(clientSet map[int]struct{}, search string, searchID int) []*file.Host {
	if len(clientSet) == 0 {
		return nil
	}
	list := make([]*file.Host, 0)
	for clientID := range clientSet {
		file.GetDb().RangeHostsByClientID(clientID, func(host *file.Host) bool {
			if !matchesHostListSearch(host, search, searchID) {
				return true
			}
			if snapshot := snapshotHostForList(host); snapshot != nil {
				list = append(list, snapshot)
			}
			return true
		})
	}
	return list
}

func matchesHostListSearch(host *file.Host, search string, searchID int) bool {
	if search == "" {
		return true
	}
	if host == nil {
		return false
	}
	return host.Id == searchID ||
		common.ContainsFold(host.Host, search) ||
		common.ContainsFold(host.Remark, search) ||
		common.ContainsFold(hostClientVerifyKey(host), search)
}

func paginateHostList(allList []*file.Host, start, length int) []*file.Host {
	if start < 0 {
		start = 0
	}
	if start >= len(allList) {
		return nil
	}
	if length <= 0 || start+length > len(allList) {
		length = len(allList) - start
	}
	return allList[start : start+length]
}

func sortHostList(list []*file.Host, sortField, order string) {
	asc := sortOrderAscending(order)
	switch sortField {
	case "Id":
		sortHostListByOrdered(list, asc, func(host *file.Host) int { return host.Id })

	case "Client.Id":
		sortHostListByOrdered(list, asc, hostClientID)

	case "Remark":
		sortHostListByOrdered(list, asc, func(host *file.Host) string { return host.Remark })

	case "Client.VerifyKey":
		sortHostListByOrdered(list, asc, hostClientVerifyKey)

	case "Host":
		sortHostListByOrdered(list, asc, func(host *file.Host) string { return host.Host })

	case "Scheme":
		sortHostListByOrdered(list, asc, func(host *file.Host) string { return host.Scheme })

	case "TargetIsHttps":
		sortHostListByBool(list, asc, func(host *file.Host) bool { return host.TargetIsHttps })

	case "Target.TargetStr":
		sortHostListByOrdered(list, asc, hostTargetStr)

	case "Location":
		sortHostListByOrdered(list, asc, func(host *file.Host) string { return host.Location })

	case "PathRewrite":
		sortHostListByOrdered(list, asc, func(host *file.Host) string { return host.PathRewrite })

	case "CertType":
		sortHostListByOrdered(list, asc, func(host *file.Host) string { return host.CertType })

	case "AutoSSL":
		sortHostListByBool(list, asc, func(host *file.Host) bool { return host.AutoSSL })

	case "AutoHttps":
		sortHostListByBool(list, asc, func(host *file.Host) bool { return host.AutoHttps })

	case "AutoCORS":
		sortHostListByBool(list, asc, func(host *file.Host) bool { return host.AutoCORS })

	case "CompatMode":
		sortHostListByBool(list, asc, func(host *file.Host) bool { return host.CompatMode })

	case "HttpsJustProxy":
		sortHostListByBool(list, asc, func(host *file.Host) bool { return host.HttpsJustProxy })

	case "TlsOffload":
		sortHostListByBool(list, asc, func(host *file.Host) bool { return host.TlsOffload })

	case "NowConn":
		sortHostListByOrdered(list, asc, func(host *file.Host) int32 { return host.NowConn })

	case "InletFlow":
		sortHostListByOrdered(list, asc, hostInletFlow)

	case "ExportFlow":
		sortHostListByOrdered(list, asc, hostExportFlow)

	case "TotalFlow":
		sortHostListByOrdered(list, asc, hostTotalFlow)

	case "NowRate", "Rate.NowRate":
		sortHostListByOrdered(list, asc, hostRateNow)

	case "FlowRemain":
		sortHostListByOrdered(list, asc, func(host *file.Host) int64 { return hostFlowRemain(host, asc) })

	case "Flow.FlowLimit", "FlowLimit":
		sortHostListByUnlimited(list, asc, func(host *file.Host) int64 { return host.EffectiveFlowLimitBytes() })

	case "Flow.TimeLimit", "ExpireAt", "TimeRemain":
		sortHostListByUnlimited(list, asc, func(host *file.Host) int64 { return host.EffectiveExpireAt() })

	case "IsClose":
		sortHostListByBool(list, asc, func(host *file.Host) bool { return host.IsClose })

	case "Client.IsConnect":
		sortHostListByBool(list, asc, hostClientConnected)

	default:
		sortHostListByOrdered(list, asc, func(host *file.Host) int { return host.Id })
	}
}

func sortHostListByOrdered[T orderedListValue](list []*file.Host, asc bool, value func(*file.Host) T) {
	sortStableBy(list, func(left, right *file.Host) bool {
		leftValue := value(left)
		rightValue := value(right)
		if leftValue == rightValue {
			return left.Id < right.Id
		}
		return orderedSortLess(asc, leftValue, rightValue)
	})
}

func sortHostListByBool(list []*file.Host, asc bool, value func(*file.Host) bool) {
	sortStableBy(list, func(left, right *file.Host) bool {
		leftValue := value(left)
		rightValue := value(right)
		if leftValue == rightValue {
			return left.Id < right.Id
		}
		return boolSortLess(asc, leftValue, rightValue)
	})
}

func sortHostListByUnlimited(list []*file.Host, asc bool, value func(*file.Host) int64) {
	sortStableBy(list, func(left, right *file.Host) bool {
		leftValue := value(left)
		rightValue := value(right)
		if leftValue == rightValue {
			return left.Id < right.Id
		}
		return unlimitedInt64SortLess(asc, leftValue, rightValue)
	})
}

func hostInletFlow(host *file.Host) int64 {
	if host == nil {
		return 0
	}
	in, _, _ := host.ServiceTrafficTotals()
	return in
}

func hostExportFlow(host *file.Host) int64 {
	if host == nil {
		return 0
	}
	_, out, _ := host.ServiceTrafficTotals()
	return out
}

func hostTotalFlow(host *file.Host) int64 {
	if host == nil {
		return 0
	}
	_, _, total := host.ServiceTrafficTotals()
	return total
}

func hostRateNow(host *file.Host) int64 {
	if host == nil {
		return 0
	}
	_, _, total := host.ServiceRateTotals()
	return total
}

func hostFlowRemain(host *file.Host, asc bool) int64 {
	if host == nil {
		return 0
	}
	limit := host.EffectiveFlowLimitBytes()
	if limit == 0 {
		if asc {
			return math.MaxInt64
		}
		return math.MinInt64
	}
	return limit - hostTotalFlow(host)
}

func clientTotalFlow(current *file.Client) int64 {
	if current == nil {
		return 0
	}
	_, _, total := current.TotalTrafficTotals()
	return total
}

func clientFlowRemain(current *file.Client, asc bool) int64 {
	if current == nil {
		return 0
	}
	limit := current.EffectiveFlowLimitBytes()
	if limit == 0 {
		if asc {
			return math.MaxInt64
		}
		return math.MinInt64
	}
	return limit - clientTotalFlow(current)
}

func clientRateNow(current *file.Client) int64 {
	if current == nil {
		return 0
	}
	_, _, total := current.TotalRateTotals()
	return total
}

func hostClientID(host *file.Host) int {
	if host == nil || host.Client == nil {
		return 0
	}
	return host.Client.Id
}

func hostClientVerifyKey(host *file.Host) string {
	if host == nil || host.Client == nil {
		return ""
	}
	return host.Client.VerifyKey
}

func hostClientConnected(host *file.Host) bool {
	if host == nil || host.Client == nil {
		return false
	}
	return host.Client.IsConnect
}

func hostTargetStr(host *file.Host) string {
	if host == nil || host.Target == nil {
		return ""
	}
	return host.Target.TargetStr
}

func lessUnlimitedInt64(left, right int64) bool {
	return (left != 0 && right == 0) || (left != 0 && right != 0 && left < right)
}

func snapshotClientForList(client *file.Client) *file.Client {
	if client == nil {
		return nil
	}
	owner := snapshotOwnerUserForList(client.OwnerUser())
	cloned := &file.Client{
		Cnf:              cloneClientConfigForList(client.Cnf),
		Id:               client.Id,
		UserId:           client.UserId,
		OwnerUserID:      client.OwnerUserID,
		ManagerUserIDs:   append([]int(nil), client.ManagerUserIDs...),
		SourceType:       client.SourceType,
		SourcePlatformID: client.SourcePlatformID,
		SourceActorID:    client.SourceActorID,
		Revision:         client.Revision,
		UpdatedAt:        client.UpdatedAt,
		VerifyKey:        client.VerifyKey,
		Mode:             client.Mode,
		Addr:             client.Addr,
		LocalAddr:        client.LocalAddr,
		Remark:           client.Remark,
		Status:           client.Status,
		IsConnect:        client.IsConnect,
		ExpireAt:         client.ExpireAt,
		FlowLimit:        client.FlowLimit,
		RateLimit:        client.RateLimit,
		Flow:             cloneFlowForList(client.Flow),
		ExportFlow:       client.ExportFlow,
		InletFlow:        client.InletFlow,
		Rate:             client.Rate.Clone(),
		BridgeTraffic:    cloneTrafficStatsForList(client.BridgeTraffic),
		ServiceTraffic:   cloneTrafficStatsForList(client.ServiceTraffic),
		BridgeMeter:      client.BridgeMeter.Clone(),
		ServiceMeter:     client.ServiceMeter.Clone(),
		TotalMeter:       client.TotalMeter.Clone(),
		NoStore:          client.NoStore,
		NoDisplay:        client.NoDisplay,
		MaxConn:          client.MaxConn,
		NowConn:          client.NowConn,
		ConfigConnAllow:  client.ConfigConnAllow,
		MaxTunnelNum:     client.MaxTunnelNum,
		Version:          client.Version,
		EntryAclMode:     client.EntryAclMode,
		EntryAclRules:    client.EntryAclRules,
		CreateTime:       client.CreateTime,
		LastOnlineTime:   client.LastOnlineTime,
	}
	cloned.BindOwnerUser(owner)
	return cloned
}

func snapshotOwnerUserForList(user *file.User) *file.User {
	if user == nil {
		return nil
	}
	return &file.User{
		Id:                 user.Id,
		Username:           user.Username,
		Kind:               user.Kind,
		ExternalPlatformID: user.ExternalPlatformID,
		Hidden:             user.Hidden,
		Status:             user.Status,
		ExpireAt:           user.ExpireAt,
		FlowLimit:          user.FlowLimit,
		TotalFlow:          cloneFlowForList(user.TotalFlow),
		TotalTraffic:       cloneTrafficStatsForList(user.TotalTraffic),
		MaxClients:         user.MaxClients,
		MaxTunnels:         user.MaxTunnels,
		MaxHosts:           user.MaxHosts,
		MaxConnections:     user.MaxConnections,
		RateLimit:          user.RateLimit,
		EntryAclMode:       user.EntryAclMode,
		EntryAclRules:      user.EntryAclRules,
		DestAclMode:        user.DestAclMode,
		DestAclRules:       user.DestAclRules,
		Revision:           user.Revision,
		UpdatedAt:          user.UpdatedAt,
		NowConn:            user.NowConn,
		Rate:               user.Rate.Clone(),
		TotalMeter:         user.TotalMeter.Clone(),
	}
}

func snapshotTunnelForList(tunnel *file.Tunnel) *file.Tunnel {
	if tunnel == nil {
		return nil
	}
	cloned := &file.Tunnel{
		Id:             tunnel.Id,
		Revision:       tunnel.Revision,
		UpdatedAt:      tunnel.UpdatedAt,
		Port:           tunnel.Port,
		ServerIp:       tunnel.ServerIp,
		Mode:           tunnel.Mode,
		Status:         tunnel.Status,
		RunStatus:      runtimeTasks.Contains(tunnel.Id),
		Client:         snapshotClientForList(tunnel.Client),
		Ports:          tunnel.Ports,
		ExpireAt:       tunnel.ExpireAt,
		FlowLimit:      tunnel.FlowLimit,
		RateLimit:      tunnel.RateLimit,
		Flow:           cloneFlowForList(tunnel.Flow),
		Rate:           tunnel.Rate.Clone(),
		ServiceTraffic: cloneTrafficStatsForList(tunnel.ServiceTraffic),
		ServiceMeter:   tunnel.ServiceMeter.Clone(),
		NowConn:        tunnel.NowConn,
		MaxConn:        tunnel.MaxConn,
		Password:       tunnel.Password,
		Remark:         tunnel.Remark,
		TargetAddr:     tunnel.TargetAddr,
		TargetType:     tunnel.TargetType,
		EntryAclMode:   tunnel.EntryAclMode,
		EntryAclRules:  tunnel.EntryAclRules,
		DestAclMode:    tunnel.DestAclMode,
		DestAclRules:   tunnel.DestAclRules,
		DestAclSet:     tunnel.DestAclSet,
		NoStore:        tunnel.NoStore,
		IsHttp:         tunnel.IsHttp,
		HttpProxy:      tunnel.HttpProxy,
		Socks5Proxy:    tunnel.Socks5Proxy,
		LocalPath:      tunnel.LocalPath,
		StripPre:       tunnel.StripPre,
		ReadOnly:       tunnel.ReadOnly,
		Target:         cloneTargetForList(tunnel.Target),
		UserAuth:       cloneMultiAccountForList(tunnel.UserAuth),
		MultiAccount:   cloneMultiAccountForList(tunnel.MultiAccount),
	}
	copyHealthForList(&cloned.Health, &tunnel.Health)
	return cloned
}

func snapshotHostForList(host *file.Host) *file.Host {
	if host == nil {
		return nil
	}
	cloned := &file.Host{
		Id:               host.Id,
		Revision:         host.Revision,
		UpdatedAt:        host.UpdatedAt,
		Host:             host.Host,
		HeaderChange:     host.HeaderChange,
		RespHeaderChange: host.RespHeaderChange,
		HostChange:       host.HostChange,
		Location:         host.Location,
		PathRewrite:      host.PathRewrite,
		Remark:           host.Remark,
		Scheme:           host.Scheme,
		RedirectURL:      host.RedirectURL,
		HttpsJustProxy:   host.HttpsJustProxy,
		TlsOffload:       host.TlsOffload,
		AutoSSL:          host.AutoSSL,
		CertType:         host.CertType,
		CertHash:         host.CertHash,
		CertFile:         host.CertFile,
		KeyFile:          host.KeyFile,
		NoStore:          host.NoStore,
		IsClose:          host.IsClose,
		AutoHttps:        host.AutoHttps,
		AutoCORS:         host.AutoCORS,
		CompatMode:       host.CompatMode,
		ExpireAt:         host.ExpireAt,
		FlowLimit:        host.FlowLimit,
		RateLimit:        host.RateLimit,
		Flow:             cloneFlowForList(host.Flow),
		Rate:             host.Rate.Clone(),
		ServiceTraffic:   cloneTrafficStatsForList(host.ServiceTraffic),
		ServiceMeter:     host.ServiceMeter.Clone(),
		MaxConn:          host.MaxConn,
		NowConn:          host.NowConn,
		Client:           snapshotClientForList(host.Client),
		EntryAclMode:     host.EntryAclMode,
		EntryAclRules:    host.EntryAclRules,
		TargetIsHttps:    host.TargetIsHttps,
		Target:           cloneTargetForList(host.Target),
		UserAuth:         cloneMultiAccountForList(host.UserAuth),
		MultiAccount:     cloneMultiAccountForList(host.MultiAccount),
	}
	copyHealthForList(&cloned.Health, &host.Health)
	return cloned
}

func cloneClientConfigForList(cfg *file.Config) *file.Config {
	if cfg == nil {
		return nil
	}
	return &file.Config{
		U:        cfg.U,
		P:        cfg.P,
		Compress: cfg.Compress,
		Crypt:    cfg.Crypt,
	}
}

func cloneFlowForList(flow *file.Flow) *file.Flow {
	if flow == nil {
		return nil
	}
	flow.RLock()
	defer flow.RUnlock()
	return &file.Flow{
		ExportFlow: flow.ExportFlow,
		InletFlow:  flow.InletFlow,
		FlowLimit:  flow.FlowLimit,
		TimeLimit:  flow.TimeLimit,
	}
}

func cloneTrafficStatsForList(stats *file.TrafficStats) *file.TrafficStats {
	if stats == nil {
		return nil
	}
	in, out, _ := stats.Snapshot()
	return &file.TrafficStats{
		InletBytes:  in,
		ExportBytes: out,
	}
}

func cloneTargetForList(target *file.Target) *file.Target {
	if target == nil {
		return nil
	}
	target.RLock()
	defer target.RUnlock()
	return &file.Target{
		TargetStr:     target.TargetStr,
		TargetArr:     append([]string(nil), target.TargetArr...),
		LocalProxy:    target.LocalProxy,
		ProxyProtocol: target.ProxyProtocol,
	}
}

func cloneMultiAccountForList(account *file.MultiAccount) *file.MultiAccount {
	return file.CloneMultiAccountSnapshot(account)
}

func copyHealthForList(dst *file.Health, src *file.Health) {
	if dst == nil {
		return
	}
	*dst = file.Health{}
	if src == nil {
		return
	}
	src.RLock()
	defer src.RUnlock()
	dst.HealthCheckTimeout = src.HealthCheckTimeout
	dst.HealthMaxFail = src.HealthMaxFail
	dst.HealthCheckInterval = src.HealthCheckInterval
	dst.HealthNextTime = src.HealthNextTime
	dst.HttpHealthUrl = src.HttpHealthUrl
	dst.HealthRemoveArr = append([]string(nil), src.HealthRemoveArr...)
	dst.HealthCheckType = src.HealthCheckType
	dst.HealthCheckTarget = src.HealthCheckTarget
	if len(src.HealthMap) > 0 {
		dst.HealthMap = make(map[string]int, len(src.HealthMap))
		for key, value := range src.HealthMap {
			dst.HealthMap[key] = value
		}
	}
}

func GetTunnel(start, length int, typeVal string, clientId int, search string, sortField string, order string) ([]*file.Tunnel, int) {
	searchID := common.GetIntNoErrByStr(search)
	if clientId > 0 {
		runtimeFlow.RefreshClient(clientId)
		allList := collectTunnelSnapshotsByClientSet(map[int]struct{}{clientId: {}}, typeVal, search, searchID)
		sortTunnelList(allList, sortField, order)
		return paginateTunnelList(allList, start, length), len(allList)
	}
	allList := collectAllTunnelSnapshots(typeVal, search, searchID)
	sortTunnelList(allList, sortField, order)
	return paginateTunnelList(allList, start, length), len(allList)
}

func collectAllTunnelSnapshots(typeVal, search string, searchID int) []*file.Tunnel {
	allList := make([]*file.Tunnel, 0)
	runtimeFlow.RefreshClients()
	file.GetDb().RangeTasks(func(v *file.Tunnel) bool {
		if typeVal != "" && v.Mode != typeVal {
			return true
		}
		if !matchesTunnelListSearch(v, search, searchID) {
			return true
		}
		if snapshot := snapshotTunnelForList(v); snapshot != nil {
			allList = append(allList, snapshot)
		}
		return true
	})
	return allList
}

func GetTunnelByClientIDs(start, length int, typeVal string, clientIDs []int, search string, sortField string, order string) ([]*file.Tunnel, int) {
	visible := visibleClientSet(clientIDs)
	if len(visible) == 0 {
		return nil, 0
	}
	runtimeFlow.RefreshClientSet(visible)
	searchID := common.GetIntNoErrByStr(search)
	allList := collectTunnelSnapshotsByClientSet(visible, typeVal, search, searchID)
	sortTunnelList(allList, sortField, order)
	return paginateTunnelList(allList, start, length), len(allList)
}

func collectTunnelSnapshotsByClientSet(clientSet map[int]struct{}, typeVal, search string, searchID int) []*file.Tunnel {
	if len(clientSet) == 0 {
		return nil
	}
	allList := make([]*file.Tunnel, 0)
	for clientID := range clientSet {
		file.GetDb().RangeTunnelsByClientID(clientID, func(tunnel *file.Tunnel) bool {
			if typeVal != "" && tunnel.Mode != typeVal {
				return true
			}
			if !matchesTunnelListSearch(tunnel, search, searchID) {
				return true
			}
			if snapshot := snapshotTunnelForList(tunnel); snapshot != nil {
				allList = append(allList, snapshot)
			}
			return true
		})
	}
	return allList
}

func visibleClientSet(clientIDs []int) map[int]struct{} {
	visible := make(map[int]struct{}, len(clientIDs))
	for _, clientID := range clientIDs {
		if clientID > 0 {
			visible[clientID] = struct{}{}
		}
	}
	return visible
}

type orderedListValue interface {
	~int | ~int32 | ~int64 | ~string
}

func sortStableBy[T any](list []T, less func(left, right T) bool) {
	if len(list) < 2 || less == nil {
		return
	}
	sort.SliceStable(list, func(i, j int) bool {
		return less(list[i], list[j])
	})
}

func sortOrderAscending(order string) bool {
	order = strings.TrimSpace(order)
	return order == "" || strings.EqualFold(order, "asc")
}

func orderedSortLess[T orderedListValue](asc bool, left, right T) bool {
	if asc {
		return left < right
	}
	return left > right
}

func boolSortLess(asc bool, left, right bool) bool {
	if asc {
		return left && !right
	}
	return !left && right
}

func unlimitedInt64SortLess(asc bool, left, right int64) bool {
	if asc {
		return lessUnlimitedInt64(left, right)
	}
	return left > right
}

func sortTunnelList(allList []*file.Tunnel, sortField string, order string) {
	asc := sortOrderAscending(order)
	switch sortField {
	case "Id":
		sortTunnelListByOrdered(allList, asc, func(tunnel *file.Tunnel) int { return tunnel.Id })
	case "Client.Id":
		sortTunnelListByOrdered(allList, asc, tunnelClientID)
	case "Remark":
		sortTunnelListByOrdered(allList, asc, func(tunnel *file.Tunnel) string { return tunnel.Remark })
	case "Client.VerifyKey":
		sortTunnelListByOrdered(allList, asc, tunnelClientVerifyKey)
	case "Target.TargetStr":
		sortTunnelListByOrdered(allList, asc, tunnelTargetStr)
	case "Port":
		sortTunnelListByOrdered(allList, asc, func(tunnel *file.Tunnel) int { return tunnel.Port })
	case "Mode":
		sortTunnelListByOrdered(allList, asc, func(tunnel *file.Tunnel) string { return tunnel.Mode })
	case "TargetType":
		sortTunnelListByOrdered(allList, asc, func(tunnel *file.Tunnel) string { return tunnel.TargetType })
	case "Password":
		sortTunnelListByOrdered(allList, asc, func(tunnel *file.Tunnel) string { return tunnel.Password })
	case "HttpProxy":
		sortTunnelListByBool(allList, asc, func(tunnel *file.Tunnel) bool { return tunnel.HttpProxy })
	case "Socks5Proxy":
		sortTunnelListByBool(allList, asc, func(tunnel *file.Tunnel) bool { return tunnel.Socks5Proxy })
	case "NowConn":
		sortTunnelListByOrdered(allList, asc, func(tunnel *file.Tunnel) int32 { return tunnel.NowConn })
	case "InletFlow":
		sortTunnelListByOrdered(allList, asc, tunnelInletFlow)
	case "ExportFlow":
		sortTunnelListByOrdered(allList, asc, tunnelExportFlow)
	case "TotalFlow":
		sortTunnelListByOrdered(allList, asc, tunnelTotalFlow)
	case "NowRate", "Rate.NowRate":
		sortTunnelListByOrdered(allList, asc, tunnelRateNow)
	case "FlowRemain":
		sortTunnelListByOrdered(allList, asc, func(tunnel *file.Tunnel) int64 { return tunnelFlowRemain(tunnel, asc) })
	case "Flow.FlowLimit", "FlowLimit":
		sortTunnelListByUnlimited(allList, asc, func(tunnel *file.Tunnel) int64 { return tunnel.EffectiveFlowLimitBytes() })
	case "Flow.TimeLimit", "ExpireAt", "TimeRemain":
		sortTunnelListByUnlimited(allList, asc, func(tunnel *file.Tunnel) int64 { return tunnel.EffectiveExpireAt() })
	case "Status":
		sortTunnelListByBool(allList, asc, func(tunnel *file.Tunnel) bool { return tunnel.Status })
	case "RunStatus":
		sortTunnelListByBool(allList, asc, func(tunnel *file.Tunnel) bool { return tunnel.RunStatus })
	case "Client.IsConnect":
		sortTunnelListByBool(allList, asc, tunnelClientConnected)
	default:
		sortTunnelListByOrdered(allList, asc, func(tunnel *file.Tunnel) int { return tunnel.Id })
	}
}

func sortTunnelListByOrdered[T orderedListValue](allList []*file.Tunnel, asc bool, value func(*file.Tunnel) T) {
	sortStableBy(allList, func(left, right *file.Tunnel) bool {
		leftValue := value(left)
		rightValue := value(right)
		if leftValue == rightValue {
			return left.Id < right.Id
		}
		return orderedSortLess(asc, leftValue, rightValue)
	})
}

func sortTunnelListByBool(allList []*file.Tunnel, asc bool, value func(*file.Tunnel) bool) {
	sortStableBy(allList, func(left, right *file.Tunnel) bool {
		leftValue := value(left)
		rightValue := value(right)
		if leftValue == rightValue {
			return left.Id < right.Id
		}
		return boolSortLess(asc, leftValue, rightValue)
	})
}

func sortTunnelListByUnlimited(allList []*file.Tunnel, asc bool, value func(*file.Tunnel) int64) {
	sortStableBy(allList, func(left, right *file.Tunnel) bool {
		leftValue := value(left)
		rightValue := value(right)
		if leftValue == rightValue {
			return left.Id < right.Id
		}
		return unlimitedInt64SortLess(asc, leftValue, rightValue)
	})
}

func paginateTunnelList(allList []*file.Tunnel, start, length int) []*file.Tunnel {
	if start < 0 {
		start = 0
	}
	if start >= len(allList) {
		return nil
	}
	if length <= 0 || start+length > len(allList) {
		length = len(allList) - start
	}
	return allList[start : start+length]
}

func matchesTunnelListSearch(tunnel *file.Tunnel, search string, searchID int) bool {
	if search == "" {
		return true
	}
	if tunnel == nil {
		return false
	}
	return tunnel.Id == searchID ||
		tunnel.Port == searchID ||
		common.ContainsFold(tunnelClientVerifyKey(tunnel), search) ||
		common.ContainsFold(tunnel.Password, search) ||
		common.ContainsFold(tunnel.Remark, search) ||
		common.ContainsFold(tunnelTargetStr(tunnel), search)
}

func tunnelInletFlow(tunnel *file.Tunnel) int64 {
	if tunnel == nil {
		return 0
	}
	in, _, _ := tunnel.ServiceTrafficTotals()
	return in
}

func tunnelExportFlow(tunnel *file.Tunnel) int64 {
	if tunnel == nil {
		return 0
	}
	_, out, _ := tunnel.ServiceTrafficTotals()
	return out
}

func tunnelTotalFlow(tunnel *file.Tunnel) int64 {
	if tunnel == nil {
		return 0
	}
	_, _, total := tunnel.ServiceTrafficTotals()
	return total
}

func tunnelRateNow(tunnel *file.Tunnel) int64 {
	if tunnel == nil {
		return 0
	}
	_, _, total := tunnel.ServiceRateTotals()
	return total
}

func tunnelFlowRemain(tunnel *file.Tunnel, asc bool) int64 {
	if tunnel == nil {
		return 0
	}
	limit := tunnel.EffectiveFlowLimitBytes()
	if limit == 0 {
		if asc {
			return math.MaxInt64
		}
		return math.MinInt64
	}
	return limit - tunnelTotalFlow(tunnel)
}

func tunnelClientID(tunnel *file.Tunnel) int {
	if tunnel == nil || tunnel.Client == nil {
		return 0
	}
	return tunnel.Client.Id
}

func tunnelClientVerifyKey(tunnel *file.Tunnel) string {
	if tunnel == nil || tunnel.Client == nil {
		return ""
	}
	return tunnel.Client.VerifyKey
}

func tunnelClientConnected(tunnel *file.Tunnel) bool {
	if tunnel == nil || tunnel.Client == nil {
		return false
	}
	return tunnel.Client.IsConnect
}

func tunnelTargetStr(tunnel *file.Tunnel) string {
	if tunnel == nil || tunnel.Target == nil {
		return ""
	}
	return tunnel.Target.TargetStr
}
