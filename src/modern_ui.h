// simplewall Personal Edition
// Modern WebView2 UI bridge header (C & C++ compatible)

#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _MODERN_APP_SNAPSHOT
{
	ULONG_PTR app_hash;
	WCHAR name[260];
	WCHAR path[520];
	WCHAR signature[260];
	WCHAR wake_trigger[520];
	LONG64 timestamp;
	LONG64 timer_remaining;
	INT category; // 0=app, 1=uwp, 2=service, 3=system
	BOOLEAN is_enabled;
	BOOLEAN is_blocked;
	BOOLEAN is_silent;
	BOOLEAN is_system;
	BOOLEAN exists;
	BOOLEAN is_ask_on_use;
	BOOLEAN is_allow_until_closed;
} MODERN_APP_SNAPSHOT;

typedef struct _MODERN_STATE_SNAPSHOT
{
	INT mode; // 0=off, 1=strict, 2=safe_pause
	LONG64 safepause_remaining;
	BOOLEAN is_applying;
	BOOLEAN is_dark_theme;
	BOOLEAN notifications;
	BOOLEAN sound;
	BOOLEAN block_inbound;
	BOOLEAN stealth_mode;
	BOOLEAN allow_loopback;
	BOOLEAN allow_ipv6;
} MODERN_STATE_SNAPSHOT;

// Implemented in modern_ui.cpp
BOOLEAN _modern_ui_init (
	_In_ HWND hwnd
);

VOID _modern_ui_resize (
	_In_ HWND hwnd,
	_In_ LPCRECT rect
);

VOID _modern_ui_destroy (
	VOID
);

BOOLEAN _modern_ui_isactive (
	VOID
);

VOID _modern_ui_notify_change (
	VOID
);

VOID _modern_ui_handle_refresh (
	_In_ HWND hwnd
);

VOID _modern_ui_handle_async_json (
	_In_ HWND hwnd,
	_In_ LPARAM lparam
);

VOID _modern_ui_apply_titlebar_theme (
	_In_ HWND hwnd
);

VOID _modern_ui_push_activity_raw (
	_In_ ULONG_PTR app_hash,
	_In_opt_ LPCWSTR app_name,
	_In_opt_ LPCWSTR path,
	_In_opt_ LPCWSTR remote_addr,
	_In_ UINT16 remote_port,
	_In_opt_ LPCWSTR protocol,
	_In_opt_ LPCWSTR direction,
	_In_ BOOLEAN is_allow,
	_In_ LONG64 timestamp,
	_In_opt_ LPCWSTR reason,
	_In_ BOOLEAN is_harmless
);

// Implemented in modern_ui_bridge.c
VOID _modern_bridge_get_state (
	_Out_ MODERN_STATE_SNAPSHOT *out_state
);

BOOLEAN _modern_bridge_get_apps (
	_Outptr_result_buffer_ (*out_count) MODERN_APP_SNAPSHOT **out_apps,
	_Out_ SIZE_T *out_count
);

VOID _modern_bridge_free_apps (
	_In_opt_ MODERN_APP_SNAPSHOT *apps
);

VOID _modern_bridge_set_mode (
	_In_ HWND hwnd,
	_In_ INT mode,
	_In_ LONG64 duration_seconds
);

VOID _modern_bridge_allow_app (
	_In_ HWND hwnd,
	_In_ ULONG_PTR app_hash,
	_In_ LONG64 duration_seconds,
	_In_ BOOLEAN until_closed
);

VOID _modern_bridge_block_app (
	_In_ HWND hwnd,
	_In_ ULONG_PTR app_hash,
	_In_ BOOLEAN ask_on_use
);

VOID _modern_bridge_set_wake_trigger (
	_In_ HWND hwnd,
	_In_ ULONG_PTR app_hash,
	_In_opt_ LPCWSTR trigger_path
);

VOID _modern_bridge_reblock_session_app (
	_In_ HWND hwnd,
	_In_ ULONG_PTR app_hash
);

BOOLEAN _modern_bridge_prompt_standby_app (
	_In_ HWND hwnd,
	_In_ ULONG_PTR app_hash,
	_In_opt_ LPCWSTR remote_addr,
	_In_ UINT16 remote_port,
	_In_opt_ LPCWSTR protocol,
	_In_opt_ LPCWSTR wake_source
);

VOID _modern_bridge_delete_apps (
	_In_ HWND hwnd,
	_In_reads_ (count) const ULONG_PTR *hashes,
	_In_ SIZE_T count
);

VOID _modern_bridge_add_app (
	_In_ HWND hwnd
);

VOID _modern_bridge_set_theme (
	_In_ HWND hwnd,
	_In_ BOOLEAN is_dark
);

VOID _modern_bridge_set_setting (
	_In_ HWND hwnd,
	_In_ LPCWSTR key,
	_In_ BOOLEAN value
);

VOID _modern_bridge_hide_legacy_controls (
	_In_ HWND hwnd
);

VOID _modern_bridge_request_exit (
	_In_ HWND hwnd
);

BOOLEAN _modern_alert_isready (
	VOID
);

BOOLEAN _modern_alert_enqueue (
	_In_ ULONG_PTR app_hash,
	_In_opt_ LPCWSTR name,
	_In_opt_ LPCWSTR path,
	_In_opt_ LPCWSTR signature,
	_In_opt_ LPCWSTR remote_addr,
	_In_ UINT16 remote_port,
	_In_opt_ LPCWSTR protocol,
	_In_ BOOLEAN can_reopen,
	_In_opt_ LPCWSTR wake_source,
	_In_ BOOLEAN is_ask_on_use
);

VOID _modern_ui_record_standby_block (
	_In_ ULONG_PTR app_hash,
	_In_opt_ LPCWSTR remote_addr,
	_In_ UINT16 remote_port,
	_In_opt_ LPCWSTR protocol
);

BOOLEAN _modern_ui_consume_standby_arm (
	_In_ ULONG_PTR app_hash
);

// decision_mode: 0=always_block, 1=allow (permanent or timed), 2=ask_on_use, 3=allow_until_closed
VOID _modern_bridge_notify_decision (
	_In_ HWND hwnd,
	_In_ ULONG_PTR app_hash,
	_In_ INT decision_mode,
	_In_ LONG64 duration_seconds,
	_In_ BOOLEAN reopen_app
);

typedef struct _MODERN_DIAG_INFO
{
	WCHAR profile_path[520];
	LONG64 profile_size;
	BOOLEAN profile_exists;
	BOOLEAN wfp_installed;
	INT protection_mode;
} MODERN_DIAG_INFO;

VOID _modern_bridge_get_diag (
	_Out_ MODERN_DIAG_INFO *out_diag
);

VOID _modern_ui_log_event (
	_In_ LPCWSTR level,
	_In_ LPCWSTR message
);

BOOLEAN _modern_ui_paint_bg (
	_In_ HWND hwnd,
	_In_ HDC hdc
);

VOID _modern_bridge_notify_dismiss (
	_In_ ULONG_PTR app_hash
);

#ifdef __cplusplus
}
#endif
