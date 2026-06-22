package routers

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/gin-gonic/gin"
)

// registerLegacyCompatRoutes registers the legacy form-encoded endpoints that
// nps_enhanced control plane SDK (v0.33.x) still uses to probe nodes and read
// tunnel runtime state.  NPS v0.35.0 replaced these with the new REST API under
// /api, so without these shims the control plane sees every v0.35.0 node as
// offline and every tunnel as abnormal.
func registerLegacyCompatRoutes(engine *gin.Engine, state *State) {
	if engine == nil || state == nil || !legacyCompatEnabled(state) {
		return
	}
	engine.POST("/auth/gettime", legacyAuthGetTime(state))
	engine.POST("/api/system/discovery", legacySystemDiscovery(state))
	engine.POST("/index/gettunnel", legacyIndexGetTunnel(state))
}

// legacyCompatEnabled returns true when this NPS instance is configured as a
// managed data-plane node (it has one or more management platforms).  The
// legacy form-encoded endpoints are only needed for the nps_enhanced control
// plane to poll such nodes; a pure management server should keep them disabled.
func legacyCompatEnabled(state *State) bool {
	cfg := state.CurrentConfig()
	if cfg == nil {
		return false
	}
	return len(cfg.Runtime.ManagementPlatforms) > 0
}

// legacyAuthKey validates the legacy auth_key = md5(auth_secret + timestamp).
func legacyAuthKey(secret, timestamp, authKey string) bool {
	if secret == "" || timestamp == "" || authKey == "" {
		return false
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	// Allow a ±5 minute clock skew, matching the old SDK tolerance.
	if ts < time.Now().Unix()-300 || ts > time.Now().Unix()+300 {
		return false
	}
	hash := md5.Sum([]byte(secret + timestamp))
	expected := fmt.Sprintf("%x", hash)
	return expected == authKey
}

func legacyResponse(c *gin.Context, status int, msg string, data interface{}) {
	c.JSON(http.StatusOK, gin.H{
		"status": status,
		"msg":    msg,
		"data":   data,
	})
}

func legacyAuthGetTime(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		secret := state.CurrentConfig().Auth.Key
		timestamp := c.PostForm("timestamp")
		authKey := c.PostForm("auth_key")

		if !legacyAuthKey(secret, timestamp, authKey) {
			legacyResponse(c, 0, "auth fail", nil)
			return
		}

		now := time.Now().Unix()
		legacyResponse(c, 1, "success", gin.H{
			"server_time": now,
			"time":        now,
		})
	}
}

// legacySystemDiscovery handles the health probe used by control plane v0.34.0
// for nodes that are not in push/reverse-WS mode.  It accepts the legacy
// auth_key+timestamp form auth and returns a discovery payload that the control
// plane can use to mark the node online.
func legacySystemDiscovery(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		secret := state.CurrentConfig().Auth.Key
		timestamp := c.PostForm("timestamp")
		authKey := c.PostForm("auth_key")

		if !legacyAuthKey(secret, timestamp, authKey) {
			legacyResponse(c, 0, "auth fail", nil)
			return
		}

		now := time.Now().Unix()
		cfg := state.CurrentConfig()
		legacyResponse(c, 1, "success", gin.H{
			"server_time": now,
			"serverTime":  now,
			"time":        now,
			"timestamp":   now,
			"app": gin.H{
				"name":    "nps",
				"version": "0.35.0",
				"year":    time.Now().Year(),
			},
			"routes": gin.H{
				"discovery": "/api/system/discovery",
				"health":    "/api/system/health",
			},
			"web_base_url": cfg.Web.BaseURL,
		})
	}
}

func legacyIndexGetTunnel(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		secret := state.CurrentConfig().Auth.Key
		timestamp := c.PostForm("timestamp")
		authKey := c.PostForm("auth_key")

		if !legacyAuthKey(secret, timestamp, authKey) {
			legacyResponse(c, 0, "auth fail", nil)
			return
		}

		clientID, _ := strconv.Atoi(c.PostForm("client_id"))
		tunnelType := c.PostForm("type")
		search := c.PostForm("search")

		db := file.GetDb()
		rows := make([]map[string]interface{}, 0)

		appendTunnel := func(t *file.Tunnel) {
			// Filter by type if requested.
			if tunnelType != "" && t.Mode != tunnelType {
				return
			}
			// Very basic search filter on remark/target.
			if search != "" {
				matched := false
				if containsFold(t.Remark, search) {
					matched = true
				}
				if t.Target != nil && containsFold(t.Target.TargetStr, search) {
					matched = true
				}
				if !matched {
					return
				}
			}

			clientMap := map[string]interface{}{}
			if t.Client != nil {
				clientMap = map[string]interface{}{
					"Id":        t.Client.Id,
					"VerifyKey": t.Client.VerifyKey,
					"Remark":    t.Client.Remark,
					"Addr":      t.Client.Addr,
					"Status":    t.Client.Status,
					"IsConnect": t.Client.IsConnect,
					"Version":   t.Client.Version,
				}
			}

			flowMap := map[string]interface{}{}
			if t.Flow != nil {
				t.Flow.RLock()
				flowMap = map[string]interface{}{
					"InletFlow":  t.Flow.InletFlow,
					"ExportFlow": t.Flow.ExportFlow,
					"FlowLimit":  t.Flow.FlowLimit,
				}
				t.Flow.RUnlock()
			}

			rows = append(rows, map[string]interface{}{
				"Id":        t.Id,
				"Port":      t.Port,
				"Mode":      t.Mode,
				"Status":    t.Status,
				"RunStatus": t.RunStatus,
				"Remark":    t.Remark,
				"Target":    t.TargetAddr,
				"Client":    clientMap,
				"Flow":      flowMap,
				"NowConn":   int(t.NowConn),
			})
		}

		if clientID > 0 {
			db.RangeTunnelsByClientID(clientID, func(t *file.Tunnel) bool {
				if t != nil {
					appendTunnel(t)
				}
				return true
			})
		} else {
			db.RangeTasks(func(t *file.Tunnel) bool {
				if t != nil {
					appendTunnel(t)
				}
				return true
			})
		}

		logs.Trace("legacy /index/gettunnel returned %d tunnels", len(rows))
		legacyResponse(c, 1, "success", gin.H{
			"rows":  rows,
			"total": len(rows),
		})
	}
}

func containsFold(s, substr string) bool {
	return len(substr) == 0 || (len(s) > 0 && containsLower(s, substr))
}

func containsLower(s, substr string) bool {
	// Simple case-insensitive substring search; good enough for the legacy shim.
	ls, lsub := lower(s), lower(substr)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return true
		}
	}
	return false
}

func lower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
