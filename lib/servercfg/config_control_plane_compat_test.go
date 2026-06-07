package servercfg

import (
	"strings"
	"testing"
)

// TestControlPlaneFlatConfigParsing verifies that the flat INI format
// produced by nps_enhanced/renderPushModeConfig is correctly parsed.
func TestControlPlaneFlatConfigParsing(t *testing.T) {
	resetTestState(t)

	// This is the exact format produced by nps_enhanced renderPushModeConfig
	// (flat keys in the default section, no [common] block).
	path := writeConfig(t, "nps.conf", strings.Join([]string{
		"platform_ids=nps-enhanced-42",
		"platform_tokens=test-platform-token-abc",
		"platform_scopes=full",
		"platform_connect_modes=reverse",
		"platform_reverse_ws_urls=ws://ctrl.example.com:18081/node/ws",
		"platform_reverse_enabled=true",
		"platform_reverse_heartbeat_seconds=30",
		"platform_callback_urls=https://ctrl.example.com:18081/node/callback",
		"platform_callback_enabled=true",
		"platform_callback_signing_keys=test-signing-key-xyz",
		"# Legacy native keys (ignored by data-plane)",
		"run_mode=node",
		"platform_url=https://ctrl.example.com:18081",
		"platform_token=test-platform-token-abc",
		"callback_signing_key=test-signing-key-xyz",
		"traffic_report=true",
	}, "\n")+"\n")

	if err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	cfg := Current()
	if cfg == nil {
		t.Fatal("Current() returned nil")
	}

	platforms := cfg.Runtime.ManagementPlatforms
	if len(platforms) != 1 {
		t.Fatalf("expected 1 management platform, got %d", len(platforms))
	}

	p := platforms[0]
	if p.PlatformID != "nps-enhanced-42" {
		t.Errorf("PlatformID = %q, want nps-enhanced-42", p.PlatformID)
	}
	if p.Token != "test-platform-token-abc" {
		t.Errorf("Token = %q, want test-platform-token-abc", p.Token)
	}
	if p.ControlScope != "full" {
		t.Errorf("ControlScope = %q, want full", p.ControlScope)
	}
	if p.ConnectMode != "reverse" {
		t.Errorf("ConnectMode = %q, want reverse", p.ConnectMode)
	}
	if p.ReverseWSURL != "ws://ctrl.example.com:18081/node/ws" {
		t.Errorf("ReverseWSURL = %q, want ws://ctrl.example.com:18081/node/ws", p.ReverseWSURL)
	}
	if !p.ReverseEnabled {
		t.Error("ReverseEnabled = false, want true")
	}
	if p.ReverseHeartbeatSeconds != 30 {
		t.Errorf("ReverseHeartbeatSeconds = %d, want 30", p.ReverseHeartbeatSeconds)
	}
	if p.CallbackURL != "https://ctrl.example.com:18081/node/callback" {
		t.Errorf("CallbackURL = %q, want https://ctrl.example.com:18081/node/callback", p.CallbackURL)
	}
	if !p.CallbackEnabled {
		t.Error("CallbackEnabled = false, want true")
	}
	if p.CallbackSigningKey != "test-signing-key-xyz" {
		t.Errorf("CallbackSigningKey = %q, want test-signing-key-xyz", p.CallbackSigningKey)
	}
}

// TestControlPlaneMergedConfigParsing verifies that a merged config
// (push block inserted at top, before [common]) is correctly parsed.
func TestControlPlaneMergedConfigParsing(t *testing.T) {
	resetTestState(t)

	path := writeConfig(t, "nps.conf", strings.Join([]string{
		"# --- nps-enhanced push mode config START ---",
		"platform_ids=nps-enhanced-1",
		"platform_tokens=tok-1",
		"platform_scopes=full",
		"platform_connect_modes=reverse",
		"platform_reverse_ws_urls=ws://ctrl.example.com:18081/node/ws",
		"platform_reverse_enabled=true",
		"platform_reverse_heartbeat_seconds=30",
		"platform_callback_urls=https://ctrl.example.com:18081/node/callback",
		"platform_callback_enabled=true",
		"platform_callback_signing_keys=key-1",
		"# --- nps-enhanced push mode config END ---",
		"",
		"[common]",
		"web_port=8080",
		"run_mode=server",
	}, "\n")+"\n")

	if err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	cfg := Current()
	platforms := cfg.Runtime.ManagementPlatforms
	if len(platforms) != 1 {
		t.Fatalf("expected 1 platform, got %d", len(platforms))
	}
	if platforms[0].PlatformID != "nps-enhanced-1" {
		t.Errorf("PlatformID = %q, want nps-enhanced-1", platforms[0].PlatformID)
	}
	if platforms[0].ConnectMode != "reverse" {
		t.Errorf("ConnectMode = %q, want reverse", platforms[0].ConnectMode)
	}
}

// TestCommonSectionPlatformKeysIgnored verifies that platform keys inside
// [common] are NOT visible to the data-plane parser (they become
// common_platform_ids after flattening). This confirms why mergePushConfig
// must place push keys in the default section (before any [section]).
func TestCommonSectionPlatformKeysIgnored(t *testing.T) {
	resetTestState(t)

	path := writeConfig(t, "nps.conf", strings.Join([]string{
		"[common]",
		"platform_ids=old-master",
		"platform_tokens=old-tok",
		"platform_connect_modes=reverse",
		"platform_reverse_ws_urls=ws://old.example/ws",
		"platform_reverse_enabled=true",
	}, "\n")+"\n")

	if err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	cfg := Current()
	platforms := cfg.Runtime.ManagementPlatforms
	if len(platforms) != 0 {
		t.Fatalf("expected 0 platforms (keys inside [common] are invisible), got %d", len(platforms))
	}
}
