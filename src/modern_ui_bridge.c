// simplewall Personal Edition
// C-side bridge between simplewall WFP/profile engine and modern_ui.cpp

#include "global.h"

static VOID _modern_copy_wstr (
	_Out_writes_ (dest_cch) LPWSTR dest,
	_In_ SIZE_T dest_cch,
	_In_opt_ LPCWSTR src
)
{
	if (!dest || dest_cch == 0)
		return;

	dest[0] = UNICODE_NULL;

	if (!src || !src[0])
		return;

	wcsncpy_s (dest, dest_cch, src, _TRUNCATE);
}

VOID _modern_bridge_get_state (
	_Out_ MODERN_STATE_SNAPSHOT *out_state
)
{
	ENUM_PROTECTION_MODE mode;

	RtlZeroMemory (out_state, sizeof (*out_state));

	mode = _wfp_getprotectionmode ();

	out_state->mode = (INT)mode;
	out_state->safepause_remaining = _wfp_getsafepause_remaining ();
	out_state->is_applying = _wfp_isfiltersapplying ();
	out_state->is_dark_theme = _r_config_getboolean (L"ModernDarkTheme", TRUE);
	out_state->notifications = _r_config_getboolean (L"IsNotificationsEnabled", TRUE);
	out_state->sound = _r_config_getboolean (L"IsNotificationsSound", FALSE);
	out_state->block_inbound = _r_config_getboolean (L"BlockInboundConnections", TRUE);
	out_state->stealth_mode = _r_config_getboolean (L"UseStealthMode", TRUE);
	out_state->allow_loopback = _r_config_getboolean (L"AllowLoopbackConnections", TRUE);
	out_state->allow_ipv6 = _r_config_getboolean (L"AllowIPv6", TRUE);
}

BOOLEAN _modern_bridge_get_apps (
	_Outptr_result_buffer_ (*out_count) MODERN_APP_SNAPSHOT **out_apps,
	_Out_ SIZE_T *out_count
)
{
	MODERN_APP_SNAPSHOT *items = NULL;
	PITEM_APP ptr_app = NULL;
	PITEM_APP_INFO ptr_info;
	PR_STRING display_name;
	ULONG_PTR enum_key = 0;
	SIZE_T capacity = 0;
	SIZE_T count = 0;
	LONG64 now;

	*out_apps = NULL;
	*out_count = 0;

	if (!apps_table)
		return TRUE;

	now = _r_unixtime_now ();

	_r_queuedlock_acquireshared (&lock_apps);

	capacity = _r_obj_gethashtablesize (apps_table);

	if (capacity > 0)
	{
		items = (MODERN_APP_SNAPSHOT *)HeapAlloc (GetProcessHeap (), HEAP_ZERO_MEMORY, capacity * sizeof (MODERN_APP_SNAPSHOT));
	}

	if (items)
	{
		while (_r_obj_enumhashtablepointer (apps_table, &ptr_app, NULL, &enum_key))
		{
			MODERN_APP_SNAPSHOT *dst;
			LPCWSTR path_str;

			if (!ptr_app || count >= capacity)
				continue;

			dst = &items[count];

			dst->app_hash = ptr_app->app_hash;
			dst->timestamp = ptr_app->timestamp;
			dst->is_enabled = !!ptr_app->is_enabled;
			dst->is_blocked = _app_isappblocked (ptr_app);
			dst->is_silent = !!ptr_app->is_silent;
			dst->is_system = _app_isdisabledremoval (ptr_app->app_hash);
			if (ptr_app->type == DATA_APP_REGULAR && !dst->is_system)
			{
				dst->exists = (ptr_app->real_path && _r_fs_exists (&ptr_app->real_path->sr)) ? TRUE : FALSE;
			}
			else
			{
				dst->exists = _app_isappexists (ptr_app);
			}

			if (ptr_app->timer > now && _app_istimerset (ptr_app))
			{
				dst->timer_remaining = ptr_app->timer - now;
			}
			else
			{
				dst->timer_remaining = 0;
			}

			if (dst->is_system)
				dst->category = 3;
			else if (ptr_app->type == DATA_APP_UWP)
				dst->category = 1;
			else if (ptr_app->type == DATA_APP_SERVICE)
				dst->category = 2;
			else
				dst->category = 0;

			display_name = _app_getappdisplayname (ptr_app, TRUE);

			if (display_name)
			{
				_modern_copy_wstr (dst->name, RTL_NUMBER_OF (dst->name), display_name->buffer);
				_r_obj_dereference (display_name);
			}

			if (ptr_app->real_path && !_r_obj_isstringempty (ptr_app->real_path))
				path_str = ptr_app->real_path->buffer;
			else if (ptr_app->original_path && !_r_obj_isstringempty (ptr_app->original_path))
				path_str = ptr_app->original_path->buffer;
			else
				path_str = L"";

			_modern_copy_wstr (dst->path, RTL_NUMBER_OF (dst->path), path_str);

			ptr_info = _app_getappinfobyhash2 (ptr_app->app_hash);

			if (ptr_info)
			{
				if (ptr_info->signature_info && !_r_obj_isstringempty (ptr_info->signature_info))
					_modern_copy_wstr (dst->signature, RTL_NUMBER_OF (dst->signature), ptr_info->signature_info->buffer);

				_r_obj_dereference (ptr_info);
			}

			count += 1;
		}
	}

	_r_queuedlock_releaseshared (&lock_apps);

	*out_apps = items;
	*out_count = count;

	return TRUE;
}

VOID _modern_bridge_free_apps (
	_In_opt_ MODERN_APP_SNAPSHOT *apps
)
{
	if (apps)
		HeapFree (GetProcessHeap (), 0, apps);
}

VOID _modern_bridge_set_mode (
	_In_ HWND hwnd,
	_In_ INT mode,
	_In_ LONG64 duration_seconds
)
{
	WCHAR log_buf[160];
	LPCWSTR mode_name = (mode == 1) ? L"Strict Protection" : ((mode == 2) ? L"Safe Pause" : L"Off");

	if (mode == 2 && duration_seconds > 0)
		_r_str_printf (log_buf, RTL_NUMBER_OF (log_buf), L"Switched firewall mode to %s (%lld minutes)", mode_name, duration_seconds / 60);
	else
		_r_str_printf (log_buf, RTL_NUMBER_OF (log_buf), L"Switched firewall mode to %s", mode_name);

	_modern_ui_log_event (L"MODE", log_buf);

	_wfp_setprotectionmode (hwnd, (ENUM_PROTECTION_MODE)mode, duration_seconds);
	_modern_ui_notify_change ();
}

VOID _modern_bridge_allow_app (
	_In_ HWND hwnd,
	_In_ ULONG_PTR app_hash,
	_In_ LONG64 duration_seconds
)
{
	PITEM_APP ptr_app;
	PR_LIST rules;
	HANDLE hengine;

	ptr_app = _app_getappitem (app_hash);

	if (!ptr_app)
		return;

	ptr_app->is_enabled = TRUE;
	ptr_app->is_silent = FALSE;
	ptr_app->is_haveerrors = FALSE;

	if (duration_seconds > 0)
	{
		_app_timer_set (hwnd, ptr_app, duration_seconds);
	}
	else if (_app_istimerset (ptr_app))
	{
		_app_timer_remove (ptr_app);
		ptr_app->timer = 0;
	}

	if (_wfp_isfiltersinstalled ())
	{
		hengine = _wfp_getenginehandle ();
		rules = _r_obj_createlist (2, NULL);

		_r_obj_addlistitem (rules, ptr_app);
		_wfp_create3filters (hengine, rules, DBG_ARG, FALSE);

		_r_obj_dereference (rules);
	}

	_app_listview_updateitemby_param (hwnd, app_hash, TRUE);
	_app_profile_save (hwnd);

	{
		WCHAR log_buf[640];
		LPCWSTR p = (ptr_app->real_path && !_r_obj_isstringempty (ptr_app->real_path)) ? ptr_app->real_path->buffer : L"<unknown>";
		if (duration_seconds > 0)
			_r_str_printf (log_buf, RTL_NUMBER_OF (log_buf), L"Allowed temporarily (%lldm): %s", duration_seconds / 60, p);
		else
			_r_str_printf (log_buf, RTL_NUMBER_OF (log_buf), L"Allowed app: %s", p);
		_modern_ui_log_event (L"ALLOW", log_buf);
	}

	_r_obj_dereference (ptr_app);

	_modern_ui_notify_change ();
}

VOID _modern_bridge_block_app (
	_In_ HWND hwnd,
	_In_ ULONG_PTR app_hash
)
{
	PITEM_APP ptr_app;
	PR_LIST rules;
	HANDLE hengine;

	ptr_app = _app_getappitem (app_hash);

	if (!ptr_app)
		return;

	if (_app_istimerset (ptr_app))
		_app_timer_remove (ptr_app);

	ptr_app->timer = 0;
	ptr_app->is_enabled = FALSE;
	ptr_app->is_silent = TRUE;
	ptr_app->is_haveerrors = FALSE;

	if (_wfp_isfiltersinstalled ())
	{
		hengine = _wfp_getenginehandle ();
		rules = _r_obj_createlist (2, NULL);

		_r_obj_addlistitem (rules, ptr_app);
		_wfp_create3filters (hengine, rules, DBG_ARG, FALSE);

		_r_obj_dereference (rules);
	}

	_app_listview_updateitemby_param (hwnd, app_hash, TRUE);
	_app_profile_save (hwnd);

	{
		WCHAR log_buf[640];
		LPCWSTR p = (ptr_app->real_path && !_r_obj_isstringempty (ptr_app->real_path)) ? ptr_app->real_path->buffer : L"<unknown>";
		_r_str_printf (log_buf, RTL_NUMBER_OF (log_buf), L"Blocked app: %s", p);
		_modern_ui_log_event (L"BLOCK", log_buf);
	}

	_r_obj_dereference (ptr_app);

	_modern_ui_notify_change ();
}

VOID _modern_bridge_delete_apps (
	_In_ HWND hwnd,
	_In_reads_ (count) const ULONG_PTR *hashes,
	_In_ SIZE_T count
)
{
	PR_ARRAY guids;
	PITEM_APP ptr_app;
	HANDLE hengine;
	SIZE_T i;

	if (!hashes || count == 0)
		return;

	guids = _r_obj_createarray (sizeof (GUID), 16, NULL);

	for (i = 0; i < count; i++)
	{
		ULONG_PTR app_hash = hashes[i];

		if (!app_hash || _app_isdisabledremoval (app_hash))
			continue;

		ptr_app = _app_getappitem (app_hash);

		if (!ptr_app)
			continue;

		ptr_app->is_undeletable = FALSE;
		_app_deleteappitem (hwnd, ptr_app->type, app_hash);
		_app_timer_reset (NULL, ptr_app);
		_app_notify_freeobject (NULL, ptr_app);

		if (!_r_obj_isempty (ptr_app->guids))
			_r_obj_addarrayitems (guids, ptr_app->guids->items, ptr_app->guids->count);

		_r_obj_dereference (ptr_app);

		_r_queuedlock_acquireexclusive (&lock_apps);
		_app_freeapplication (hwnd, app_hash);
		_r_queuedlock_releaseexclusive (&lock_apps);
	}

	if (!_r_obj_isempty2 (guids) && _wfp_isfiltersinstalled ())
	{
		hengine = _wfp_getenginehandle ();
		_wfp_destroyfilters_array (hengine, guids, DBG_ARG);
	}

	_r_obj_dereference (guids);

	_app_profile_save (hwnd);
	_modern_ui_notify_change ();
}

VOID _modern_bridge_add_app (
	_In_ HWND hwnd
)
{
	SendMessageW (hwnd, WM_COMMAND, MAKEWPARAM (IDM_ADD_FILE, 0), 0);
	_modern_ui_notify_change ();
}

VOID _modern_bridge_set_theme (
	_In_ HWND hwnd,
	_In_ BOOLEAN is_dark
)
{
	_r_config_setboolean (L"ModernDarkTheme", is_dark);
	_modern_ui_apply_titlebar_theme (hwnd);
}

VOID _modern_bridge_set_setting (
	_In_ HWND hwnd,
	_In_ LPCWSTR key,
	_In_ BOOLEAN value
)
{
	BOOLEAN needs_wfp_reapply = FALSE;

	if (!key)
		return;

	_r_config_setboolean (key, value);

	if (wcscmp (key, L"BlockInboundConnections") == 0 ||
		wcscmp (key, L"UseStealthMode") == 0 ||
		wcscmp (key, L"AllowLoopbackConnections") == 0 ||
		wcscmp (key, L"AllowIPv6") == 0)
	{
		needs_wfp_reapply = TRUE;
	}

	if (needs_wfp_reapply && _wfp_isfiltersinstalled ())
	{
		HANDLE hengine = _wfp_getenginehandle ();
		_wfp_create2filters (hengine, DBG_ARG, FALSE);
	}

	_app_profile_save (hwnd);
	_modern_ui_notify_change ();
}

VOID _modern_bridge_hide_legacy_controls (
	_In_ HWND hwnd
)
{
	const INT legacy_ids[] = {
		IDC_TAB,
		IDC_APPS_PROFILE,
		IDC_APPS_SERVICE,
		IDC_APPS_UWP,
		IDC_RULES_BLOCKLIST,
		IDC_RULES_SYSTEM,
		IDC_RULES_CUSTOM,
		IDC_NETWORK,
		IDC_LOG,
		IDC_STATUSBAR,
	};
	HWND hctrl;

	if (config.hrebar && IsWindow (config.hrebar))
		ShowWindow (config.hrebar, SW_HIDE);

	for (SIZE_T i = 0; i < RTL_NUMBER_OF (legacy_ids); i++)
	{
		hctrl = GetDlgItem (hwnd, legacy_ids[i]);

		if (hctrl && IsWindow (hctrl))
			ShowWindow (hctrl, SW_HIDE);
	}

	// Remove the classic Win32 menu bar for a clean modern window
	SetMenu (hwnd, NULL);
}

VOID _modern_bridge_request_exit (
	_In_ HWND hwnd
)
{
	// Cleanly exit without confirmation prompt when installing an update
	_wfp_cancelsafepause_timer ();
	DestroyWindow (hwnd);
}

VOID _modern_bridge_push_activity (
	_In_ PITEM_LOG ptr_log,
	_In_opt_ PITEM_APP ptr_app
)
{
	PR_STRING app_name = NULL;
	LPCWSTR path_str = NULL;
	LPCWSTR remote_str = NULL;
	LPCWSTR proto_str = NULL;
	LPCWSTR dir_str = L"Out";
	LPCWSTR reason_str = NULL;
	BOOLEAN is_harmless = TRUE;

	if (!ptr_log)
		return;

	if (ptr_app)
	{
		app_name = _app_getappdisplayname (ptr_app, TRUE);

		if (ptr_app->real_path && !_r_obj_isstringempty (ptr_app->real_path))
			path_str = ptr_app->real_path->buffer;
	}

	if (!path_str && ptr_log->path && !_r_obj_isstringempty (ptr_log->path))
		path_str = ptr_log->path->buffer;

	if (ptr_log->remote_addr_str && !_r_obj_isstringempty (ptr_log->remote_addr_str))
		remote_str = ptr_log->remote_addr_str->buffer;

	if (ptr_log->protocol_str && !_r_obj_isstringempty (ptr_log->protocol_str))
		proto_str = ptr_log->protocol_str->buffer;

	if (ptr_log->direction == FWP_DIRECTION_INBOUND)
		dir_str = L"In";
	else if (ptr_log->direction == FWP_DIRECTION_OUTBOUND)
		dir_str = L"Out";

	if (!ptr_log->is_allow)
	{
		UINT16 rp = ptr_log->remote_port;
		UINT16 lp = ptr_log->local_port;
		BOOLEAN is_discovery = (rp == 5353 || lp == 5353 || rp == 1900 || lp == 1900 ||
			rp == 137 || lp == 137 || rp == 138 || lp == 138 || rp == 5355 || lp == 5355);
		BOOLEAN is_app_allowed = (ptr_app && ptr_app->is_enabled) ? TRUE : FALSE;

		if (ptr_log->is_blocklist)
		{
			reason_str = L"Tracker Blocked";
			is_harmless = TRUE;
		}
		else if (is_discovery)
		{
			reason_str = L"Local Discovery";
			is_harmless = TRUE;
		}
		else if (ptr_log->direction == FWP_DIRECTION_INBOUND)
		{
			reason_str = L"Incoming Blocked";
			is_harmless = TRUE;
		}
		else if (!is_app_allowed)
		{
			reason_str = L"App Not Allowed";
			is_harmless = FALSE;
		}
		else if (ptr_log->is_system)
		{
			reason_str = L"Firewall Protection";
			is_harmless = TRUE;
		}
		else
		{
			reason_str = (ptr_log->filter_name && !_r_obj_isstringempty (ptr_log->filter_name))
				? ptr_log->filter_name->buffer
				: L"Firewall Rule";
			is_harmless = FALSE;
		}
	}

	_modern_ui_push_activity_raw (
		ptr_log->app_hash,
		app_name ? app_name->buffer : NULL,
		path_str,
		remote_str,
		ptr_log->remote_port,
		proto_str,
		dir_str,
		ptr_log->is_allow,
		ptr_log->timestamp,
		reason_str,
		is_harmless
	);

	if (app_name)
		_r_obj_dereference (app_name);
}

BOOLEAN _modern_bridge_show_alert (
	_In_ HWND hwnd,
	_In_ PITEM_LOG ptr_log
)
{
	PITEM_APP ptr_app;
	PITEM_APP_INFO ptr_info;
	PR_STRING app_name = NULL;
	LPCWSTR path_str = NULL;
	LPCWSTR sig_str = NULL;
	LPCWSTR remote_str = NULL;
	LPCWSTR proto_str = NULL;
	BOOLEAN can_reopen = FALSE;
	BOOLEAN ok;

	UNREFERENCED_PARAMETER (hwnd);

	if (!ptr_log || !_modern_alert_isready ())
		return FALSE;

	ptr_app = _app_getappitem (ptr_log->app_hash);

	if (!ptr_app)
		return FALSE;

	app_name = _app_getappdisplayname (ptr_app, TRUE);

	if (ptr_app->real_path && !_r_obj_isstringempty (ptr_app->real_path))
		path_str = ptr_app->real_path->buffer;
	else if (ptr_log->path && !_r_obj_isstringempty (ptr_log->path))
		path_str = ptr_log->path->buffer;

	ptr_info = _app_getappinfobyhash2 (ptr_app->app_hash);

	if (ptr_info && ptr_info->signature_info && !_r_obj_isstringempty (ptr_info->signature_info))
		sig_str = ptr_info->signature_info->buffer;

	if (ptr_log->remote_addr_str && !_r_obj_isstringempty (ptr_log->remote_addr_str))
		remote_str = ptr_log->remote_addr_str->buffer;

	if (ptr_log->protocol_str && !_r_obj_isstringempty (ptr_log->protocol_str))
		proto_str = ptr_log->protocol_str->buffer;

	// Allow & Reopen is offered for regular installed non-system desktop .exe apps
	if (ptr_app->type == DATA_APP_REGULAR &&
		!_app_isdisabledremoval (ptr_app->app_hash) &&
		!_app_isappfromsystem (ptr_app->real_path, ptr_app->app_hash) &&
		_app_isappexists (ptr_app) &&
		path_str && path_str[0])
	{
		can_reopen = TRUE;
	}

	ok = _modern_alert_enqueue (
		ptr_app->app_hash,
		app_name ? app_name->buffer : NULL,
		path_str,
		sig_str,
		remote_str,
		ptr_log->remote_port,
		proto_str,
		can_reopen
	);

	if (ptr_info)
		_r_obj_dereference (ptr_info);

	if (app_name)
		_r_obj_dereference (app_name);

	_r_obj_dereference (ptr_app);

	return ok;
}

VOID _modern_bridge_notify_decision (
	_In_ HWND hwnd,
	_In_ ULONG_PTR app_hash,
	_In_ BOOLEAN is_allow,
	_In_ LONG64 duration_seconds,
	_In_ BOOLEAN reopen_app
)
{
	PITEM_APP ptr_app;
	PR_LIST rules;
	HANDLE hengine;
	WCHAR reopen_path[520] = {0};

	ptr_app = _app_getappitem (app_hash);

	if (!ptr_app)
		return;

	if (ptr_app->notification)
		_r_obj_clearreference (&ptr_app->notification);

	ptr_app->last_notify = _r_unixtime_now ();

	if (is_allow)
	{
		ptr_app->is_enabled = TRUE;
		ptr_app->is_silent = FALSE;
		ptr_app->is_haveerrors = FALSE;

		if (duration_seconds > 0)
		{
			_app_timer_set (hwnd, ptr_app, duration_seconds);
		}
		else if (_app_istimerset (ptr_app))
		{
			_app_timer_remove (ptr_app);
			ptr_app->timer = 0;
		}

		if (reopen_app && ptr_app->real_path && !_r_obj_isstringempty (ptr_app->real_path))
			_modern_copy_wstr (reopen_path, RTL_NUMBER_OF (reopen_path), ptr_app->real_path->buffer);
	}
	else
	{
		if (_app_istimerset (ptr_app))
			_app_timer_remove (ptr_app);

		ptr_app->timer = 0;
		ptr_app->is_enabled = FALSE;
		ptr_app->is_silent = TRUE;
		ptr_app->is_haveerrors = FALSE;
	}

	if (_wfp_isfiltersinstalled ())
	{
		hengine = _wfp_getenginehandle ();
		rules = _r_obj_createlist (2, NULL);

		_r_obj_addlistitem (rules, ptr_app);
		_wfp_create3filters (hengine, rules, DBG_ARG, FALSE);

		_r_obj_dereference (rules);
	}

	_app_listview_updateitemby_param (hwnd, app_hash, TRUE);
	_app_profile_save (hwnd);

	{
		WCHAR log_buf[640];
		LPCWSTR p = (ptr_app->real_path && !_r_obj_isstringempty (ptr_app->real_path)) ? ptr_app->real_path->buffer : L"<unknown>";
		_r_str_printf (log_buf, RTL_NUMBER_OF (log_buf), L"Alert decision (%s): %s", is_allow ? (reopen_app ? L"Allow & Reopen" : L"Allow") : L"Block", p);
		_modern_ui_log_event (is_allow ? L"ALLOW" : L"BLOCK", log_buf);
	}

	_r_obj_dereference (ptr_app);

	// Optional safe reopen for regular desktop apps
	if (reopen_path[0])
	{
		ShellExecuteW (NULL, L"open", reopen_path, NULL, NULL, SW_SHOWNORMAL);
	}

	_modern_ui_notify_change ();
}

VOID _modern_bridge_get_diag (
	_Out_ MODERN_DIAG_INFO *out_diag
)
{
	WIN32_FILE_ATTRIBUTE_DATA fad;

	RtlZeroMemory (out_diag, sizeof (*out_diag));

	out_diag->wfp_installed = _wfp_isfiltersinstalled ();
	out_diag->protection_mode = (INT)_wfp_getprotectionmode ();

	if (profile_info.profile_path && !_r_obj_isstringempty (profile_info.profile_path))
	{
		_modern_copy_wstr (out_diag->profile_path, RTL_NUMBER_OF (out_diag->profile_path), profile_info.profile_path->buffer);

		if (GetFileAttributesExW (profile_info.profile_path->buffer, GetFileExInfoStandard, &fad))
		{
			LARGE_INTEGER li;
			li.HighPart = (LONG)fad.nFileSizeHigh;
			li.LowPart = fad.nFileSizeLow;
			out_diag->profile_exists = TRUE;
			out_diag->profile_size = li.QuadPart;
		}
	}
}

VOID _modern_bridge_notify_dismiss (
	_In_ ULONG_PTR app_hash
)
{
	PITEM_APP ptr_app;

	ptr_app = _app_getappitem (app_hash);

	if (!ptr_app)
		return;

	if (ptr_app->notification)
		_r_obj_clearreference (&ptr_app->notification);

	ptr_app->last_notify = _r_unixtime_now ();

	_r_obj_dereference (ptr_app);
}
