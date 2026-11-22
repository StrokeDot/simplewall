// simplewall Personal Edition
// Modern Edge WebView2 UI host, icon/metadata inspector, live process scanner, and GitHub Fork Updater

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>
#include <shellapi.h>
#include <dwmapi.h>
#include <tlhelp32.h>
#include <wincodec.h>
#include <winhttp.h>
#include <winver.h>

#pragma warning(push)
#pragma warning(disable: 4996)
#include <WebView2.h>
#pragma warning(pop)

#include <atomic>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <deque>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "app.h"
#include "resource.h"
#include "modern_ui.h"

#pragma comment(lib, "WebView2LoaderStatic.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

#ifndef WM_MODERN_UI_REFRESH
#define WM_MODERN_UI_REFRESH (WM_APP + 23)
#endif

#ifndef WM_MODERN_UI_ASYNC_JSON
#define WM_MODERN_UI_ASYNC_JSON (WM_APP + 24)
#endif

#ifndef WM_MODERN_UI_EXIT_FOR_UPDATE
#define WM_MODERN_UI_EXIT_FOR_UPDATE (WM_APP + 25)
#endif

namespace
{
struct ActivityItem
{
	ULONG_PTR appHash = 0;
	std::wstring appName;
	std::wstring path;
	std::wstring remoteAddr;
	UINT16 remotePort = 0;
	std::wstring protocol;
	std::wstring direction;
	bool isAllow = false;
	LONG64 timestamp = 0;
};

struct FileMeta
{
	std::wstring company;
	std::wstring description;
	std::wstring productName;
	std::wstring fileVersion;
	std::wstring parentApp;
	std::wstring iconDataUrl;
};

struct AlertItem
{
	ULONG_PTR appHash = 0;
	std::wstring name;
	std::wstring path;
	std::wstring signature;
	std::wstring remoteAddr;
	UINT16 remotePort = 0;
	std::wstring protocol;
	bool canReopen = false;
};

HWND g_hwnd = nullptr;
ICoreWebView2Environment *g_env = nullptr;
ICoreWebView2Controller *g_controller = nullptr;
ICoreWebView2 *g_webview = nullptr;
EventRegistrationToken g_msgToken = {};
std::atomic<bool> g_active{false};
std::atomic<bool> g_initialized{false};
std::atomic<bool> g_refreshPending{false};

// Bottom-right animated alert popup
HWND g_alertHwnd = nullptr;
ICoreWebView2Controller *g_alertController = nullptr;
ICoreWebView2 *g_alertWebview = nullptr;
EventRegistrationToken g_alertMsgToken = {};
std::atomic<bool> g_alertReady{false};
std::atomic<bool> g_alertHtmlReady{false};
std::deque<AlertItem> g_alertQueue;

std::mutex g_activityMutex;
std::deque<ActivityItem> g_activity;
constexpr size_t kMaxActivity = 180;

std::mutex g_metaMutex;
std::unordered_map<std::wstring, FileMeta> g_metaCache;

// ---- String & JSON helpers ----

std::wstring ToLower (const std::wstring &s)
{
	std::wstring out = s;
	std::transform (out.begin (), out.end (), out.begin (), [] (wchar_t c) { return (wchar_t)towlower (c); });
	return out;
}

std::wstring Utf8ToWide (const std::string &utf8)
{
	if (utf8.empty ())
		return {};

	int len = MultiByteToWideChar (CP_UTF8, 0, utf8.data (), (int)utf8.size (), nullptr, 0);
	if (len <= 0)
		return {};

	std::wstring out ((size_t)len, L'\0');
	MultiByteToWideChar (CP_UTF8, 0, utf8.data (), (int)utf8.size (), out.data (), len);
	return out;
}

std::wstring JsonEscape (const std::wstring &s)
{
	std::wstring out;
	out.reserve (s.size () + 16);

	for (wchar_t c : s)
	{
		switch (c)
		{
			case L'"': out += L"\\\""; break;
			case L'\\': out += L"\\\\"; break;
			case L'\b': out += L"\\b"; break;
			case L'\f': out += L"\\f"; break;
			case L'\n': out += L"\\n"; break;
			case L'\r': out += L"\\r"; break;
			case L'\t': out += L"\\t"; break;
			default:
				if (c < 0x20)
				{
					wchar_t buf[8];
					swprintf_s (buf, L"\\u%04x", (unsigned int)c);
					out += buf;
				}
				else
				{
					out.push_back (c);
				}
				break;
		}
	}

	return out;
}

std::wstring Base64Encode (const BYTE *data, size_t len)
{
	static constexpr wchar_t kTable[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::wstring out;
	out.reserve (((len + 2) / 3) * 4);

	for (size_t i = 0; i < len; i += 3)
	{
		UINT32 n = ((UINT32)data[i]) << 16;
		if (i + 1 < len) n |= ((UINT32)data[i + 1]) << 8;
		if (i + 2 < len) n |= ((UINT32)data[i + 2]);

		out.push_back (kTable[(n >> 18) & 63]);
		out.push_back (kTable[(n >> 12) & 63]);
		out.push_back (i + 1 < len ? kTable[(n >> 6) & 63] : L'=');
		out.push_back (i + 2 < len ? kTable[n & 63] : L'=');
	}

	return out;
}

std::wstring Trim (const std::wstring &s)
{
	size_t a = 0;
	while (a < s.size () && iswspace (s[a])) ++a;
	size_t b = s.size ();
	while (b > a && iswspace (s[b - 1])) --b;
	return s.substr (a, b - a);
}

// Tiny JSON field extractors (UTF-16)
bool ExtractJsonString (const std::wstring &json, const std::wstring &key, std::wstring &out)
{
	std::wstring needle = L"\"" + key + L"\"";
	size_t pos = json.find (needle);
	if (pos == std::wstring::npos) return false;
	pos = json.find (L':', pos + needle.size ());
	if (pos == std::wstring::npos) return false;
	++pos;
	while (pos < json.size () && iswspace (json[pos])) ++pos;
	if (pos >= json.size () || json[pos] != L'"') return false;
	++pos;

	std::wstring res;
	while (pos < json.size ())
	{
		wchar_t c = json[pos++];
		if (c == L'"')
		{
			out = res;
			return true;
		}
		if (c == L'\\' && pos < json.size ())
		{
			wchar_t e = json[pos++];
			switch (e)
			{
				case L'"': res.push_back (L'"'); break;
				case L'\\': res.push_back (L'\\'); break;
				case L'/': res.push_back (L'/'); break;
				case L'n': res.push_back (L'\n'); break;
				case L'r': res.push_back (L'\r'); break;
				case L't': res.push_back (L'\t'); break;
				case L'u':
					if (pos + 4 <= json.size ())
					{
						unsigned int code = 0;
						swscanf_s (json.substr (pos, 4).c_str (), L"%x", &code);
						res.push_back ((wchar_t)code);
						pos += 4;
					}
					break;
				default: res.push_back (e); break;
			}
		}
		else
		{
			res.push_back (c);
		}
	}
	return false;
}

bool ExtractJsonInt64 (const std::wstring &json, const std::wstring &key, LONG64 &out)
{
	std::wstring needle = L"\"" + key + L"\"";
	size_t pos = json.find (needle);
	if (pos == std::wstring::npos) return false;
	pos = json.find (L':', pos + needle.size ());
	if (pos == std::wstring::npos) return false;
	++pos;
	while (pos < json.size () && iswspace (json[pos])) ++pos;
	if (pos >= json.size ()) return false;
	wchar_t *end = nullptr;
	out = wcstoll (json.c_str () + pos, &end, 10);
	return end != (json.c_str () + pos);
}

bool ExtractJsonBool (const std::wstring &json, const std::wstring &key, bool &out)
{
	std::wstring needle = L"\"" + key + L"\"";
	size_t pos = json.find (needle);
	if (pos == std::wstring::npos) return false;
	pos = json.find (L':', pos + needle.size ());
	if (pos == std::wstring::npos) return false;
	++pos;
	while (pos < json.size () && iswspace (json[pos])) ++pos;
	if (json.compare (pos, 4, L"true") == 0) { out = true; return true; }
	if (json.compare (pos, 5, L"false") == 0) { out = false; return true; }
	return false;
}

std::vector<ULONG_PTR> ExtractJsonHashArray (const std::wstring &json, const std::wstring &key)
{
	std::vector<ULONG_PTR> ids;
	std::wstring needle = L"\"" + key + L"\"";
	size_t pos = json.find (needle);
	if (pos == std::wstring::npos) return ids;
	pos = json.find (L'[', pos + needle.size ());
	if (pos == std::wstring::npos) return ids;
	size_t endPos = json.find (L']', pos);
	if (endPos == std::wstring::npos) return ids;

	size_t p = pos + 1;
	while (p < endPos)
	{
		size_t q1 = json.find (L'"', p);
		if (q1 == std::wstring::npos || q1 >= endPos) break;
		size_t q2 = json.find (L'"', q1 + 1);
		if (q2 == std::wstring::npos || q2 > endPos) break;
		std::wstring tok = json.substr (q1 + 1, q2 - q1 - 1);
		ULONG_PTR h = (ULONG_PTR)wcstoull (tok.c_str (), nullptr, 10);
		if (h != 0) ids.push_back (h);
		p = q2 + 1;
	}
	return ids;
}

// ---- Running process scanner ----

std::unordered_set<std::wstring> GetRunningProcessPaths ()
{
	std::unordered_set<std::wstring> running;
	HANDLE snap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return running;

	PROCESSENTRY32W pe = {};
	pe.dwSize = sizeof (pe);

	if (Process32FirstW (snap, &pe))
	{
		do
		{
			HANDLE hProc = OpenProcess (PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
			if (hProc)
			{
				WCHAR buf[1024];
				DWORD sz = (DWORD)std::size (buf);
				if (QueryFullProcessImageNameW (hProc, 0, buf, &sz))
				{
					running.insert (ToLower (std::wstring (buf, sz)));
				}
				CloseHandle (hProc);
			}
		} while (Process32NextW (snap, &pe));
	}

	CloseHandle (snap);
	return running;
}

// ---- Smart parent app / origin inference ----

std::wstring ExtractFileName (const std::wstring &path)
{
	size_t slash = path.find_last_of (L"\\/");
	if (slash == std::wstring::npos) return path;
	return path.substr (slash + 1);
}

std::wstring InferParentApp (const std::wstring &path)
{
	if (path.empty ()) return L"";
	std::wstring low = ToLower (path);

	if (low.find (L"\\windows\\system32\\") != std::wstring::npos ||
		low.find (L"\\windows\\syswow64\\") != std::wstring::npos)
		return L"Windows Operating System";

	if (low.find (L"\\windows\\") != std::wstring::npos)
		return L"Windows System Component";

	if (low.find (L"\\windowsapps\\") != std::wstring::npos)
		return L"Microsoft Store App";

	// Extract meaningful segments after Program Files / AppData / ProgramData
	const wchar_t *markers[] = {
		L"\\program files (x86)\\",
		L"\\program files\\",
		L"\\appdata\\local\\programs\\",
		L"\\appdata\\local\\",
		L"\\appdata\\roaming\\",
		L"\\programdata\\"
	};

	for (const wchar_t *m : markers)
	{
		size_t idx = low.find (m);
		if (idx != std::wstring::npos)
		{
			size_t start = idx + wcslen (m);
			size_t s1 = path.find (L'\\', start);
			if (s1 != std::wstring::npos)
			{
				std::wstring seg1 = path.substr (start, s1 - start);
				size_t s2 = path.find (L'\\', s1 + 1);
				if (s2 != std::wstring::npos)
				{
					std::wstring seg2 = path.substr (s1 + 1, s2 - s1 - 1);
					std::wstring seg2Low = ToLower (seg2);
					if (seg2Low != L"bin" && seg2Low != L"application" && seg2Low != L"app" && seg2Low != L"common")
						return seg1 + L" / " + seg2;
				}
				return seg1;
			}
		}
	}

	// Fallback to immediate parent folder name
	size_t lastSlash = path.find_last_of (L"\\/");
	if (lastSlash != std::wstring::npos && lastSlash > 2)
	{
		size_t prevSlash = path.find_last_of (L"\\/", lastSlash - 1);
		if (prevSlash != std::wstring::npos)
			return path.substr (prevSlash + 1, lastSlash - prevSlash - 1);
	}

	return L"";
}

// ---- Icon to base64 PNG via WIC ----

std::wstring EncodeHIconToDataUrl (HICON hIcon)
{
	if (!hIcon) return {};

	std::wstring result;
	IWICImagingFactory *factory = nullptr;
	IWICBitmap *wicBitmap = nullptr;
	IStream *stream = nullptr;
	IWICBitmapEncoder *encoder = nullptr;
	IWICBitmapFrameEncode *frame = nullptr;

	HRESULT hr = CoCreateInstance (CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS (&factory));
	if (SUCCEEDED (hr))
		hr = factory->CreateBitmapFromHICON (hIcon, &wicBitmap);
	if (SUCCEEDED (hr))
		hr = CreateStreamOnHGlobal (nullptr, TRUE, &stream);
	if (SUCCEEDED (hr))
		hr = factory->CreateEncoder (GUID_ContainerFormatPng, nullptr, &encoder);
	if (SUCCEEDED (hr))
		hr = encoder->Initialize (stream, WICBitmapEncoderNoCache);
	if (SUCCEEDED (hr))
		hr = encoder->CreateNewFrame (&frame, nullptr);
	if (SUCCEEDED (hr))
		hr = frame->Initialize (nullptr);
	if (SUCCEEDED (hr))
		hr = frame->WriteSource (wicBitmap, nullptr);
	if (SUCCEEDED (hr))
		hr = frame->Commit ();
	if (SUCCEEDED (hr))
		hr = encoder->Commit ();

	if (SUCCEEDED (hr))
	{
		HGLOBAL hMem = nullptr;
		if (SUCCEEDED (GetHGlobalFromStream (stream, &hMem)) && hMem)
		{
			SIZE_T sz = GlobalSize (hMem);
			const BYTE *ptr = (const BYTE *)GlobalLock (hMem);
			if (ptr && sz > 0)
			{
				result = L"data:image/png;base64," + Base64Encode (ptr, sz);
				GlobalUnlock (hMem);
			}
		}
	}

	if (frame) frame->Release ();
	if (encoder) encoder->Release ();
	if (stream) stream->Release ();
	if (wicBitmap) wicBitmap->Release ();
	if (factory) factory->Release ();

	return result;
}

std::wstring ExtractIconDataUrl (const std::wstring &path)
{
	if (path.empty ()) return {};

	SHFILEINFOW sfi = {};
	if (!SHGetFileInfoW (path.c_str (), 0, &sfi, sizeof (sfi), SHGFI_ICON | SHGFI_LARGEICON) || !sfi.hIcon)
		return {};

	std::wstring result = EncodeHIconToDataUrl (sfi.hIcon);
	DestroyIcon (sfi.hIcon);
	return result;
}

std::wstring GetMainAppIconDataUrl ()
{
	static std::wstring cached;
	static bool loaded = false;
	if (!loaded)
	{
		loaded = true;
		HICON hIcon = (HICON)LoadImageW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDI_MAIN), IMAGE_ICON, 64, 64, LR_DEFAULTCOLOR);
		if (hIcon)
		{
			cached = EncodeHIconToDataUrl (hIcon);
			DestroyIcon (hIcon);
		}
	}
	return cached;
}

// ---- Version info extractor ----

std::wstring QueryVerString (const std::vector<BYTE> &verData, const wchar_t *langCp, const wchar_t *field)
{
	WCHAR subBlock[128];
	swprintf_s (subBlock, L"\\StringFileInfo\\%s\\%s", langCp, field);
	LPWSTR val = nullptr;
	UINT valLen = 0;
	if (VerQueryValueW (verData.data (), subBlock, (LPVOID *)&val, &valLen) && val && valLen > 0)
		return Trim (std::wstring (val));
	return {};
}

FileMeta GetFileMeta (const std::wstring &path, bool exists)
{
	std::wstring key = ToLower (path);
	{
		std::lock_guard<std::mutex> lock (g_metaMutex);
		auto it = g_metaCache.find (key);
		if (it != g_metaCache.end ())
			return it->second;
	}

	FileMeta meta;
	meta.parentApp = InferParentApp (path);

	if (exists && !path.empty ())
	{
		DWORD handle = 0;
		DWORD sz = GetFileVersionInfoSizeW (path.c_str (), &handle);
		if (sz > 0)
		{
			std::vector<BYTE> buf (sz);
			if (GetFileVersionInfoW (path.c_str (), 0, sz, buf.data ()))
			{
				struct LANGANDCODEPAGE { WORD lang; WORD cp; };
				LANGANDCODEPAGE *trans = nullptr;
				UINT transLen = 0;
				std::vector<std::wstring> langList;

				if (VerQueryValueW (buf.data (), L"\\VarFileInfo\\Translation", (LPVOID *)&trans, &transLen) &&
					trans && transLen >= sizeof (LANGANDCODEPAGE))
				{
					WCHAR cpBuf[16];
					swprintf_s (cpBuf, L"%04x%04x", trans[0].lang, trans[0].cp);
					langList.push_back (cpBuf);
				}
				langList.push_back (L"040904b0");
				langList.push_back (L"040904e4");
				langList.push_back (L"000004b0");

				for (const auto &lcp : langList)
				{
					if (meta.company.empty ()) meta.company = QueryVerString (buf, lcp.c_str (), L"CompanyName");
					if (meta.description.empty ()) meta.description = QueryVerString (buf, lcp.c_str (), L"FileDescription");
					if (meta.productName.empty ()) meta.productName = QueryVerString (buf, lcp.c_str (), L"ProductName");
					if (meta.fileVersion.empty ()) meta.fileVersion = QueryVerString (buf, lcp.c_str (), L"FileVersion");
					if (!meta.company.empty () && !meta.description.empty ()) break;
				}
			}
		}

		meta.iconDataUrl = ExtractIconDataUrl (path);
	}

	{
		std::lock_guard<std::mutex> lock (g_metaMutex);
		if (g_metaCache.size () < 2000)
			g_metaCache[key] = meta;
	}

	return meta;
}

// ---- Build JSON snapshots ----

std::wstring BuildActivityArrayJson ()
{
	std::wostringstream ss;
	ss << L"[";
	std::lock_guard<std::mutex> lock (g_activityMutex);
	for (size_t i = 0; i < g_activity.size (); ++i)
	{
		const auto &ev = g_activity[i];
		if (i > 0) ss << L",";
		ss << L"{\"appId\":\"" << ev.appHash << L"\""
			<< L",\"appName\":\"" << JsonEscape (ev.appName) << L"\""
			<< L",\"path\":\"" << JsonEscape (ev.path) << L"\""
			<< L",\"remoteAddr\":\"" << JsonEscape (ev.remoteAddr) << L"\""
			<< L",\"remotePort\":" << ev.remotePort
			<< L",\"protocol\":\"" << JsonEscape (ev.protocol) << L"\""
			<< L",\"direction\":\"" << JsonEscape (ev.direction) << L"\""
			<< L",\"isAllow\":" << (ev.isAllow ? L"true" : L"false")
			<< L",\"timestamp\":" << ev.timestamp
			<< L"}";
	}
	ss << L"]";
	return ss.str ();
}

std::wstring BuildFullSnapshotJson ()
{
	MODERN_STATE_SNAPSHOT st = {};
	_modern_bridge_get_state (&st);

	MODERN_APP_SNAPSHOT *apps = nullptr;
	SIZE_T appCount = 0;
	_modern_bridge_get_apps (&apps, &appCount);

	auto running = GetRunningProcessPaths ();

	const wchar_t *modeStr = L"off";
	if (st.mode == 1) modeStr = L"strict";
	else if (st.mode == 2) modeStr = L"safe_pause";

	std::wostringstream ss;
	ss << L"{\"type\":\"snapshot\""
		<< L",\"mode\":\"" << modeStr << L"\""
		<< L",\"safePauseRemaining\":" << st.safepause_remaining
		<< L",\"isApplying\":" << (st.is_applying ? L"true" : L"false")
		<< L",\"theme\":\"" << (st.is_dark_theme ? L"dark" : L"light") << L"\""
		<< L",\"appVersion\":\"" << JsonEscape (APP_FORK_VERSION) << L"\""
		<< L",\"forkRepo\":\"" << JsonEscape (APP_FORK_OWNER L"/" APP_FORK_REPO) << L"\""
		<< L",\"appIconDataUrl\":\"" << JsonEscape (GetMainAppIconDataUrl ()) << L"\""
		<< L",\"settings\":{"
		<< L"\"notifications\":" << (st.notifications ? L"true" : L"false")
		<< L",\"sound\":" << (st.sound ? L"true" : L"false")
		<< L",\"blockInbound\":" << (st.block_inbound ? L"true" : L"false")
		<< L",\"stealthMode\":" << (st.stealth_mode ? L"true" : L"false")
		<< L",\"allowLoopback\":" << (st.allow_loopback ? L"true" : L"false")
		<< L",\"allowIpv6\":" << (st.allow_ipv6 ? L"true" : L"false")
		<< L"},\"apps\":[";

	bool first = true;
	for (SIZE_T i = 0; i < appCount; ++i)
	{
		const auto &a = apps[i];
		std::wstring path (a.path);
		std::wstring name (a.name);
		std::wstring sig (a.signature);
		std::wstring fileName = ExtractFileName (path);
		bool isRun = !path.empty () && (running.find (ToLower (path)) != running.end ());

		// Only fetch full metadata/icon for regular apps, allowed apps, or explicitly blocked apps to keep UI snappy
		FileMeta meta;
		if (a.category == 0 || a.is_enabled || a.is_silent || a.is_blocked)
		{
			meta = GetFileMeta (path, a.exists != FALSE);
		}
		else
		{
			meta.parentApp = InferParentApp (path);
		}

		const wchar_t *catStr = L"app";
		if (a.category == 1) catStr = L"uwp";
		else if (a.category == 2) catStr = L"service";
		else if (a.category == 3) catStr = L"system";

		const wchar_t *statusStr = a.is_enabled ? L"allowed" : L"blocked";

		if (!first) ss << L",";
		first = false;

		ss << L"{\"id\":\"" << a.app_hash << L"\""
			<< L",\"name\":\"" << JsonEscape (name.empty () ? fileName : name) << L"\""
			<< L",\"fileName\":\"" << JsonEscape (fileName) << L"\""
			<< L",\"path\":\"" << JsonEscape (path) << L"\""
			<< L",\"category\":\"" << catStr << L"\""
			<< L",\"status\":\"" << statusStr << L"\""
			<< L",\"exists\":" << (a.exists ? L"true" : L"false")
			<< L",\"isRunning\":" << (isRun ? L"true" : L"false")
			<< L",\"isSilent\":" << (a.is_silent ? L"true" : L"false")
			<< L",\"isSystem\":" << (a.is_system ? L"true" : L"false")
			<< L",\"timerRemaining\":" << a.timer_remaining
			<< L",\"timestamp\":" << a.timestamp
			<< L",\"company\":\"" << JsonEscape (meta.company) << L"\""
			<< L",\"description\":\"" << JsonEscape (meta.description) << L"\""
			<< L",\"productName\":\"" << JsonEscape (meta.productName) << L"\""
			<< L",\"fileVersion\":\"" << JsonEscape (meta.fileVersion) << L"\""
			<< L",\"parentApp\":\"" << JsonEscape (meta.parentApp) << L"\""
			<< L",\"signature\":\"" << JsonEscape (sig) << L"\""
			<< L",\"iconDataUrl\":\"" << JsonEscape (meta.iconDataUrl) << L"\""
			<< L"}";
	}

	_modern_bridge_free_apps (apps);

	ss << L"],\"activity\":" << BuildActivityArrayJson () << L"}";
	return ss.str ();
}

void PostJsonToWebView (const std::wstring &json)
{
	if (g_webview && g_active.load ())
		g_webview->PostWebMessageAsJson (json.c_str ());
}

void PostAsyncJsonFromWorker (const std::wstring &json)
{
	if (!g_hwnd || !IsWindow (g_hwnd))
		return;

	auto *copy = new std::wstring (json);
	if (!PostMessageW (g_hwnd, WM_MODERN_UI_ASYNC_JSON, 0, (LPARAM)copy))
		delete copy;
}

// ---- GitHub Fork Updater (WinHTTP) ----

std::vector<int> ParseSemver (const std::wstring &v)
{
	std::vector<int> parts;
	size_t i = 0;
	while (i < v.size () && !iswdigit (v[i])) ++i;
	while (i < v.size ())
	{
		if (!iswdigit (v[i])) break;
		int n = 0;
		while (i < v.size () && iswdigit (v[i]))
		{
			n = n * 10 + (v[i] - L'0');
			++i;
		}
		parts.push_back (n);
		if (i < v.size () && v[i] == L'.') ++i;
		else break;
	}
	while (parts.size () < 3) parts.push_back (0);
	return parts;
}

bool IsNewerVersion (const std::wstring &latest, const std::wstring &current)
{
	auto a = ParseSemver (latest);
	auto b = ParseSemver (current);
	for (size_t i = 0; i < 3; ++i)
	{
		if (a[i] > b[i]) return true;
		if (a[i] < b[i]) return false;
	}
	return false;
}

bool WinHttpGetToBytes (const std::wstring &url, std::string &outBody, DWORD &outStatus)
{
	outBody.clear ();
	outStatus = 0;

	URL_COMPONENTS uc = {};
	uc.dwStructSize = sizeof (uc);
	WCHAR host[256] = {};
	WCHAR path[2048] = {};
	uc.lpszHostName = host;
	uc.dwHostNameLength = (DWORD)std::size (host);
	uc.lpszUrlPath = path;
	uc.dwUrlPathLength = (DWORD)std::size (path);

	if (!WinHttpCrackUrl (url.c_str (), (DWORD)url.size (), 0, &uc))
		return false;

	HINTERNET hSession = WinHttpOpen (L"SimpleWall-Personal/" APP_FORK_VERSION, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSession) return false;

	DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
	WinHttpSetOption (hSession, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof (redirectPolicy));

	HINTERNET hConnect = WinHttpConnect (hSession, host, uc.nPort, 0);
	HINTERNET hRequest = nullptr;
	bool ok = false;

	if (hConnect)
	{
		DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
		hRequest = WinHttpOpenRequest (hConnect, L"GET", path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
	}

	if (hRequest)
	{
		WinHttpAddRequestHeaders (hRequest, L"Accept: application/vnd.github+json\r\n", (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
		if (WinHttpSendRequest (hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
			WinHttpReceiveResponse (hRequest, nullptr))
		{
			DWORD statusSize = sizeof (outStatus);
			WinHttpQueryHeaders (hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &outStatus, &statusSize, WINHTTP_NO_HEADER_INDEX);

			DWORD avail = 0;
			while (WinHttpQueryDataAvailable (hRequest, &avail) && avail > 0)
			{
				size_t oldSz = outBody.size ();
				outBody.resize (oldSz + avail);
				DWORD read = 0;
				if (!WinHttpReadData (hRequest, outBody.data () + oldSz, avail, &read))
					break;
				outBody.resize (oldSz + read);
			}
			ok = true;
		}
	}

	if (hRequest) WinHttpCloseHandle (hRequest);
	if (hConnect) WinHttpCloseHandle (hConnect);
	WinHttpCloseHandle (hSession);
	return ok;
}

void RunCheckUpdateAsync ()
{
	std::thread ([] () {
		std::wstring apiUrl = L"https://api.github.com/repos/" APP_FORK_OWNER L"/" APP_FORK_REPO L"/releases/latest";
		std::string body;
		DWORD status = 0;

		if (!WinHttpGetToBytes (apiUrl, body, status))
		{
			PostAsyncJsonFromWorker (L"{\"type\":\"updateResult\",\"error\":\"Could not connect to GitHub. Check your internet connection or allow SimpleWall in your firewall.\"}");
			return;
		}

		if (status == 404)
		{
			std::wostringstream ss;
			ss << L"{\"type\":\"updateResult\",\"hasUpdate\":false,\"latestVersion\":\"v" << JsonEscape (APP_FORK_VERSION)
				<< L"\",\"releaseNotes\":\"No releases have been published on " << APP_FORK_OWNER << L"/" << APP_FORK_REPO << L" yet.\"}";
			PostAsyncJsonFromWorker (ss.str ());
			return;
		}

		if (status != 200)
		{
			std::wostringstream ss;
			ss << L"{\"type\":\"updateResult\",\"error\":\"GitHub returned HTTP " << status << L".\"}";
			PostAsyncJsonFromWorker (ss.str ());
			return;
		}

		std::wstring wjson = Utf8ToWide (body);
		std::wstring tagName, htmlUrl, relNotes;
		ExtractJsonString (wjson, L"tag_name", tagName);
		ExtractJsonString (wjson, L"html_url", htmlUrl);
		ExtractJsonString (wjson, L"body", relNotes);

		// Find first .exe or .zip asset browser_download_url
		std::wstring downloadUrl, assetName;
		size_t searchPos = wjson.find (L"\"assets\"");
		while (searchPos != std::wstring::npos)
		{
			size_t urlKey = wjson.find (L"\"browser_download_url\"", searchPos);
			if (urlKey == std::wstring::npos) break;
			std::wstring slice = wjson.substr (urlKey, 600);
			std::wstring candidate;
			if (ExtractJsonString (slice, L"browser_download_url", candidate))
			{
				std::wstring low = ToLower (candidate);
				if (low.ends_with (L".exe") || low.ends_with (L".zip"))
				{
					downloadUrl = candidate;
					assetName = ExtractFileName (candidate);
					if (low.ends_with (L".exe")) break; // prefer direct .exe
				}
			}
			searchPos = urlKey + 22;
		}

		bool hasUpdate = !tagName.empty () && IsNewerVersion (tagName, APP_FORK_VERSION);

		std::wostringstream ss;
		ss << L"{\"type\":\"updateResult\""
			<< L",\"hasUpdate\":" << (hasUpdate ? L"true" : L"false")
			<< L",\"latestVersion\":\"" << JsonEscape (tagName) << L"\""
			<< L",\"htmlUrl\":\"" << JsonEscape (htmlUrl) << L"\""
			<< L",\"downloadUrl\":\"" << JsonEscape (downloadUrl) << L"\""
			<< L",\"assetName\":\"" << JsonEscape (assetName) << L"\""
			<< L",\"releaseNotes\":\"" << JsonEscape (relNotes) << L"\""
			<< L"}";
		PostAsyncJsonFromWorker (ss.str ());
	}).detach ();
}

void RunInstallUpdateAsync (std::wstring downloadUrl, std::wstring assetName)
{
	std::thread ([downloadUrl = std::move (downloadUrl), assetName = std::move (assetName)] () {
		std::wstring low = ToLower (downloadUrl);
		if (!low.starts_with (L"https://github.com/" APP_FORK_OWNER L"/") &&
			!low.starts_with (L"https://github.com/") &&
			!low.starts_with (L"https://objects.githubusercontent.com/") &&
			!low.starts_with (L"https://release-assets.githubusercontent.com/"))
		{
			PostAsyncJsonFromWorker (L"{\"type\":\"updateInstallStatus\",\"error\":\"Refused untrusted update URL.\"}");
			return;
		}

		std::string bytes;
		DWORD status = 0;
		if (!WinHttpGetToBytes (downloadUrl, bytes, status) || status != 200 || bytes.size () < 32768)
		{
			PostAsyncJsonFromWorker (L"{\"type\":\"updateInstallStatus\",\"error\":\"Failed to download update package from GitHub.\"}");
			return;
		}

		WCHAR tempDir[MAX_PATH] = {};
		GetTempPathW (MAX_PATH, tempDir);
		bool isZip = ToLower (assetName).ends_with (L".zip");
		std::wstring dlPath = std::wstring (tempDir) + (isZip ? L"simplewall_update_pkg.zip" : L"simplewall_update_new.exe");

		HANDLE hFile = CreateFileW (dlPath.c_str (), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			PostAsyncJsonFromWorker (L"{\"type\":\"updateInstallStatus\",\"error\":\"Could not save downloaded update file.\"}");
			return;
		}

		DWORD written = 0;
		WriteFile (hFile, bytes.data (), (DWORD)bytes.size (), &written, nullptr);
		CloseHandle (hFile);

		WCHAR selfPath[MAX_PATH] = {};
		GetModuleFileNameW (nullptr, selfPath, MAX_PATH);
		DWORD pid = GetCurrentProcessId ();

		std::wstring scriptPath = std::wstring (tempDir) + L"simplewall_apply_update.ps1";
		std::wostringstream ps;
		ps << L"$ErrorActionPreference = 'Stop'\r\n"
			<< L"try { Wait-Process -Id " << pid << L" -Timeout 20 -ErrorAction SilentlyContinue } catch {}\r\n"
			<< L"Start-Sleep -Milliseconds 600\r\n"
			<< L"$target = '" << selfPath << L"'\r\n"
			<< L"$src = '" << dlPath << L"'\r\n";

		if (isZip)
		{
			ps << L"$extDir = Join-Path $env:TEMP 'simplewall_update_extract'\r\n"
				<< L"if (Test-Path $extDir) { Remove-Item $extDir -Recurse -Force }\r\n"
				<< L"Expand-Archive -Path $src -DestinationPath $extDir -Force\r\n"
				<< L"$exe = Get-ChildItem -Path $extDir -Filter 'simplewall.exe' -Recurse | Select-Object -First 1\r\n"
				<< L"if (-not $exe) { exit 1 }\r\n"
				<< L"$src = $exe.FullName\r\n";
		}

		ps << L"Copy-Item -Path $target -Destination ($target + '.bak') -Force -ErrorAction SilentlyContinue\r\n"
			<< L"Copy-Item -Path $src -Destination $target -Force\r\n"
			<< L"Start-Process -FilePath $target\r\n";

		std::wstring psText = ps.str ();
		int utf8Len = WideCharToMultiByte (CP_UTF8, 0, psText.data (), (int)psText.size (), nullptr, 0, nullptr, nullptr);
		std::string psUtf8 ((size_t)utf8Len, '\0');
		WideCharToMultiByte (CP_UTF8, 0, psText.data (), (int)psText.size (), psUtf8.data (), utf8Len, nullptr, nullptr);

		HANDLE hScript = CreateFileW (scriptPath.c_str (), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hScript == INVALID_HANDLE_VALUE)
		{
			PostAsyncJsonFromWorker (L"{\"type\":\"updateInstallStatus\",\"error\":\"Could not create updater script.\"}");
			return;
		}
		WriteFile (hScript, psUtf8.data (), (DWORD)psUtf8.size (), &written, nullptr);
		CloseHandle (hScript);

		std::wstring cmd = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + scriptPath + L"\"";
		STARTUPINFOW si = {};
		si.cb = sizeof (si);
		PROCESS_INFORMATION pi = {};
		if (CreateProcessW (nullptr, cmd.data (), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			CloseHandle (pi.hThread);
			CloseHandle (pi.hProcess);
			PostAsyncJsonFromWorker (L"{\"type\":\"updateInstallStatus\",\"message\":\"Update ready - restarting simplewall...\"}");
			if (g_hwnd && IsWindow (g_hwnd))
				PostMessageW (g_hwnd, WM_MODERN_UI_EXIT_FOR_UPDATE, 0, 0);
		}
		else
		{
			PostAsyncJsonFromWorker (L"{\"type\":\"updateInstallStatus\",\"error\":\"Could not launch updater helper.\"}");
		}
	}).detach ();
}

// ---- Incoming message dispatcher (UI thread) ----

void HandleWebMessage (const std::wstring &json)
{
	std::wstring action;
	if (!ExtractJsonString (json, L"action", action))
		return;

	if (action == L"init" || action == L"refresh")
	{
		PostJsonToWebView (BuildFullSnapshotJson ());
	}
	else if (action == L"setTheme")
	{
		std::wstring theme;
		if (ExtractJsonString (json, L"theme", theme))
		{
			_modern_bridge_set_theme (g_hwnd, theme != L"light");
		}
	}
	else if (action == L"setMode")
	{
		std::wstring modeStr;
		LONG64 dur = 0;
		ExtractJsonString (json, L"mode", modeStr);
		ExtractJsonInt64 (json, L"durationSeconds", dur);

		int mode = 0;
		if (modeStr == L"strict") mode = 1;
		else if (modeStr == L"safe_pause") mode = 2;

		_modern_bridge_set_mode (g_hwnd, mode, dur);
	}
	else if (action == L"allowApp")
	{
		std::wstring idStr;
		LONG64 dur = 0;
		if (ExtractJsonString (json, L"id", idStr))
		{
			ExtractJsonInt64 (json, L"durationSeconds", dur);
			ULONG_PTR h = (ULONG_PTR)wcstoull (idStr.c_str (), nullptr, 10);
			if (h) _modern_bridge_allow_app (g_hwnd, h, dur);
		}
	}
	else if (action == L"blockApp")
	{
		std::wstring idStr;
		if (ExtractJsonString (json, L"id", idStr))
		{
			ULONG_PTR h = (ULONG_PTR)wcstoull (idStr.c_str (), nullptr, 10);
			if (h) _modern_bridge_block_app (g_hwnd, h);
		}
	}
	else if (action == L"deleteApps")
	{
		auto ids = ExtractJsonHashArray (json, L"ids");
		if (!ids.empty ())
			_modern_bridge_delete_apps (g_hwnd, ids.data (), ids.size ());
	}
	else if (action == L"addApp")
	{
		_modern_bridge_add_app (g_hwnd);
	}
	else if (action == L"openFolder")
	{
		std::wstring path;
		if (ExtractJsonString (json, L"path", path) && !path.empty ())
		{
			std::wstring args = L"/select,\"" + path + L"\"";
			ShellExecuteW (g_hwnd, L"open", L"explorer.exe", args.c_str (), nullptr, SW_SHOWNORMAL);
		}
	}
	else if (action == L"searchOnline")
	{
		std::wstring query;
		if (ExtractJsonString (json, L"query", query) && !query.empty ())
		{
			// Simple URL encoding for query
			std::wstring encoded;
			for (wchar_t c : query)
			{
				if (iswalnum (c) || c == L'-' || c == L'_' || c == L'.')
					encoded.push_back (c);
				else if (c == L' ')
					encoded.push_back (L'+');
				else
				{
					wchar_t hex[8];
					swprintf_s (hex, L"%%%02X", (unsigned int)(c & 0xFF));
					encoded += hex;
				}
			}
			std::wstring url = L"https://www.google.com/search?q=" + encoded;
			ShellExecuteW (g_hwnd, L"open", url.c_str (), nullptr, nullptr, SW_SHOWNORMAL);
		}
	}
	else if (action == L"openUrl")
	{
		std::wstring url;
		if (ExtractJsonString (json, L"url", url) && url.starts_with (L"https://"))
			ShellExecuteW (g_hwnd, L"open", url.c_str (), nullptr, nullptr, SW_SHOWNORMAL);
	}
	else if (action == L"updateSetting")
	{
		std::wstring key;
		bool val = false;
		if (ExtractJsonString (json, L"key", key) && ExtractJsonBool (json, L"value", val))
		{
			_modern_bridge_set_setting (g_hwnd, key.c_str (), val ? TRUE : FALSE);
		}
	}
	else if (action == L"clearActivity")
	{
		{
			std::lock_guard<std::mutex> lock (g_activityMutex);
			g_activity.clear ();
		}
		PostJsonToWebView (L"{\"type\":\"activityUpdate\",\"activity\":[]}");
	}
	else if (action == L"checkUpdate")
	{
		RunCheckUpdateAsync ();
	}
	else if (action == L"installUpdate")
	{
		std::wstring dlUrl, assetName;
		if (ExtractJsonString (json, L"downloadUrl", dlUrl))
		{
			ExtractJsonString (json, L"assetName", assetName);
			RunInstallUpdateAsync (dlUrl, assetName);
		}
	}
}

// ---- Load embedded HTML resource ----

std::wstring LoadEmbeddedResourceHtml (UINT resId)
{
	HMODULE hMod = GetModuleHandleW (nullptr);
	HRSRC hRes = FindResourceW (hMod, MAKEINTRESOURCEW (resId), RT_RCDATA);
	if (!hRes) return {};
	HGLOBAL hData = LoadResource (hMod, hRes);
	if (!hData) return {};
	DWORD sz = SizeofResource (hMod, hRes);
	const char *ptr = (const char *)LockResource (hData);
	if (!ptr || sz == 0) return {};
	return Utf8ToWide (std::string (ptr, sz));
}

// ---- Bottom-right animated alert popup helpers ----

void PositionAlertBottomRight ()
{
	if (!g_alertHwnd || !IsWindow (g_alertHwnd))
		return;

	UINT dpi = GetDpiForWindow (g_alertHwnd);
	if (dpi == 0) dpi = 96;
	int w = MulDiv (432, (int)dpi, 96);
	int h = MulDiv (282, (int)dpi, 96);
	int margin = MulDiv (16, (int)dpi, 96);

	RECT wa = {};
	SystemParametersInfoW (SPI_GETWORKAREA, 0, &wa, 0);

	int x = wa.right - w - margin;
	int y = wa.bottom - h - margin;

	SetWindowPos (g_alertHwnd, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE);

	if (g_alertController)
	{
		RECT rc = {0, 0, w, h};
		g_alertController->put_Bounds (rc);
	}
}

void ShowFrontAlert ()
{
	if (!g_alertHwnd || !g_alertWebview || !g_alertHtmlReady.load ())
		return;

	if (g_alertQueue.empty ())
	{
		ShowWindow (g_alertHwnd, SW_HIDE);
		if (g_alertController)
			g_alertController->put_IsVisible (FALSE);
		return;
	}

	const auto &a = g_alertQueue.front ();
	std::wstring fileName = ExtractFileName (a.path);
	FileMeta meta = GetFileMeta (a.path, !a.path.empty ());

	MODERN_STATE_SNAPSHOT st = {};
	_modern_bridge_get_state (&st);

	std::wostringstream ss;
	ss << L"{\"type\":\"showAlert\""
		<< L",\"id\":\"" << a.appHash << L"\""
		<< L",\"name\":\"" << JsonEscape (a.name.empty () ? fileName : a.name) << L"\""
		<< L",\"fileName\":\"" << JsonEscape (fileName) << L"\""
		<< L",\"path\":\"" << JsonEscape (a.path) << L"\""
		<< L",\"signature\":\"" << JsonEscape (a.signature) << L"\""
		<< L",\"company\":\"" << JsonEscape (meta.company) << L"\""
		<< L",\"description\":\"" << JsonEscape (meta.description) << L"\""
		<< L",\"parentApp\":\"" << JsonEscape (meta.parentApp) << L"\""
		<< L",\"iconDataUrl\":\"" << JsonEscape (meta.iconDataUrl) << L"\""
		<< L",\"remoteAddr\":\"" << JsonEscape (a.remoteAddr) << L"\""
		<< L",\"remotePort\":" << a.remotePort
		<< L",\"protocol\":\"" << JsonEscape (a.protocol) << L"\""
		<< L",\"canReopen\":" << (a.canReopen ? L"true" : L"false")
		<< L",\"queueCount\":" << g_alertQueue.size ()
		<< L",\"theme\":\"" << (st.is_dark_theme ? L"dark" : L"light") << L"\""
		<< L",\"soundEnabled\":" << (st.sound ? L"true" : L"false")
		<< L"}";

	PositionAlertBottomRight ();
	g_alertWebview->PostWebMessageAsJson (ss.str ().c_str ());
	if (g_alertController)
		g_alertController->put_IsVisible (TRUE);
	ShowWindow (g_alertHwnd, SW_SHOWNOACTIVATE);
}

void HandleAlertMessage (const std::wstring &json)
{
	std::wstring action;
	if (!ExtractJsonString (json, L"action", action))
		return;

	if (action == L"alertReady")
	{
		g_alertHtmlReady.store (true);
		if (!g_alertQueue.empty ())
			ShowFrontAlert ();
	}
	else if (action == L"decide")
	{
		std::wstring idStr, decision;
		LONG64 dur = 0;
		bool reopen = false;
		if (ExtractJsonString (json, L"id", idStr) && ExtractJsonString (json, L"decision", decision))
		{
			ExtractJsonInt64 (json, L"durationSeconds", dur);
			ExtractJsonBool (json, L"reopen", reopen);
			ULONG_PTR h = (ULONG_PTR)wcstoull (idStr.c_str (), nullptr, 10);
			if (h)
			{
				_modern_bridge_notify_decision (g_hwnd, h, decision == L"allow" ? TRUE : FALSE, dur, reopen ? TRUE : FALSE);
			}
		}
	}
	else if (action == L"animDone" || action == L"dismiss")
	{
		std::wstring idStr;
		ULONG_PTR h = 0;
		if (ExtractJsonString (json, L"id", idStr))
			h = (ULONG_PTR)wcstoull (idStr.c_str (), nullptr, 10);

		if (action == L"dismiss" && h)
			_modern_bridge_notify_dismiss (h);

		if (!g_alertQueue.empty ())
		{
			if (h == 0 || g_alertQueue.front ().appHash == h)
			{
				g_alertQueue.pop_front ();
			}
			else
			{
				for (auto it = g_alertQueue.begin (); it != g_alertQueue.end (); ++it)
				{
					if (it->appHash == h) { g_alertQueue.erase (it); break; }
				}
			}
		}

		ShowFrontAlert ();
	}
	else if (action == L"next")
	{
		if (g_alertQueue.size () > 1)
		{
			auto front = std::move (g_alertQueue.front ());
			g_alertQueue.pop_front ();
			g_alertQueue.push_back (std::move (front));
			ShowFrontAlert ();
		}
	}
	else if (action == L"toggleSound")
	{
		bool enabled = false;
		if (ExtractJsonBool (json, L"enabled", enabled))
			_modern_bridge_set_setting (g_hwnd, L"IsNotificationsSound", enabled ? TRUE : FALSE);
	}
	else if (action == L"openFolder")
	{
		std::wstring path;
		if (ExtractJsonString (json, L"path", path) && !path.empty ())
		{
			std::wstring args = L"/select,\"" + path + L"\"";
			ShellExecuteW (g_hwnd, L"open", L"explorer.exe", args.c_str (), nullptr, SW_SHOWNORMAL);
		}
	}
}

LRESULT CALLBACK AlertWndProc (HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
	switch (msg)
	{
		case WM_MOUSEACTIVATE:
			return MA_NOACTIVATE;
		case WM_SIZE:
			if (g_alertController)
			{
				RECT rc = {};
				if (GetClientRect (hwnd, &rc))
					g_alertController->put_Bounds (rc);
			}
			return 0;
	}
	return DefWindowProcW (hwnd, msg, wparam, lparam);
}

class AlertMessageHandler final : public ICoreWebView2WebMessageReceivedEventHandler
{
	std::atomic<ULONG> m_ref{1};
public:
	HRESULT STDMETHODCALLTYPE QueryInterface (REFIID riid, void **ppv) override
	{
		if (riid == IID_IUnknown || riid == IID_ICoreWebView2WebMessageReceivedEventHandler)
		{
			*ppv = static_cast<ICoreWebView2WebMessageReceivedEventHandler *>(this);
			AddRef ();
			return S_OK;
		}
		*ppv = nullptr;
		return E_NOINTERFACE;
	}
	ULONG STDMETHODCALLTYPE AddRef () override { return ++m_ref; }
	ULONG STDMETHODCALLTYPE Release () override
	{
		ULONG c = --m_ref;
		if (c == 0) delete this;
		return c;
	}
	HRESULT STDMETHODCALLTYPE Invoke (ICoreWebView2 *, ICoreWebView2WebMessageReceivedEventArgs *args) override
	{
		LPWSTR raw = nullptr;
		if (SUCCEEDED (args->TryGetWebMessageAsString (&raw)) && raw)
		{
			HandleAlertMessage (raw);
			CoTaskMemFree (raw);
		}
		return S_OK;
	}
};

class AlertCtrlCompletedHandler final : public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler
{
	std::atomic<ULONG> m_ref{1};
public:
	HRESULT STDMETHODCALLTYPE QueryInterface (REFIID riid, void **ppv) override
	{
		if (riid == IID_IUnknown || riid == IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler)
		{
			*ppv = static_cast<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *>(this);
			AddRef ();
			return S_OK;
		}
		*ppv = nullptr;
		return E_NOINTERFACE;
	}
	ULONG STDMETHODCALLTYPE AddRef () override { return ++m_ref; }
	ULONG STDMETHODCALLTYPE Release () override
	{
		ULONG c = --m_ref;
		if (c == 0) delete this;
		return c;
	}
	HRESULT STDMETHODCALLTYPE Invoke (HRESULT result, ICoreWebView2Controller *controller) override
	{
		if (FAILED (result) || !controller || !g_alertHwnd || !IsWindow (g_alertHwnd))
			return S_OK;

		g_alertController = controller;
		g_alertController->AddRef ();
		g_alertController->get_CoreWebView2 (&g_alertWebview);

		if (g_alertWebview)
		{
			ICoreWebView2Settings *settings = nullptr;
			if (SUCCEEDED (g_alertWebview->get_Settings (&settings)) && settings)
			{
				settings->put_AreDefaultContextMenusEnabled (FALSE);
				settings->put_AreDevToolsEnabled (FALSE);
				settings->put_IsStatusBarEnabled (FALSE);
				settings->put_IsZoomControlEnabled (FALSE);
				settings->Release ();
			}

			auto *h = new AlertMessageHandler ();
			g_alertWebview->add_WebMessageReceived (h, &g_alertMsgToken);
			h->Release ();

			g_alertController->put_IsVisible (FALSE);
			g_alertReady.store (true);

			std::wstring html = LoadEmbeddedResourceHtml (IDR_MODERN_ALERT);
			if (!html.empty ())
				g_alertWebview->NavigateToString (html.c_str ());
		}

		return S_OK;
	}
};

void InitAlertHostWindow (ICoreWebView2Environment *env)
{
	if (!env || g_alertHwnd)
		return;

	static bool classReg = false;
	if (!classReg)
	{
		WNDCLASSEXW wc = {};
		wc.cbSize = sizeof (wc);
		wc.lpfnWndProc = AlertWndProc;
		wc.hInstance = GetModuleHandleW (nullptr);
		wc.lpszClassName = L"SimpleWallModernAlertClass";
		RegisterClassExW (&wc);
		classReg = true;
	}

	g_alertHwnd = CreateWindowExW (
		WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
		L"SimpleWallModernAlertClass",
		L"simplewall Alert",
		WS_POPUP | WS_CLIPCHILDREN,
		0, 0, 432, 282,
		nullptr,
		nullptr,
		GetModuleHandleW (nullptr),
		nullptr
	);

	if (g_alertHwnd)
	{
		// Windows 11 rounded corners + no OS border (our HTML draws the animated glowing corner border!)
		DWORD corner = 2; // DWMWCP_ROUND
		DwmSetWindowAttribute (g_alertHwnd, 33, &corner, sizeof (corner));
		COLORREF noBorder = 0xFFFFFFFE; // DWMWA_COLOR_NONE
		DwmSetWindowAttribute (g_alertHwnd, 34, &noBorder, sizeof (noBorder));

		auto *handler = new AlertCtrlCompletedHandler ();
		env->CreateCoreWebView2Controller (g_alertHwnd, handler);
		handler->Release ();
	}
}

// ---- Pure COM WebView2 Handlers ----

class WebMessageHandler final : public ICoreWebView2WebMessageReceivedEventHandler
{
	std::atomic<ULONG> m_ref{1};
public:
	HRESULT STDMETHODCALLTYPE QueryInterface (REFIID riid, void **ppv) override
	{
		if (riid == IID_IUnknown || riid == IID_ICoreWebView2WebMessageReceivedEventHandler)
		{
			*ppv = static_cast<ICoreWebView2WebMessageReceivedEventHandler *>(this);
			AddRef ();
			return S_OK;
		}
		*ppv = nullptr;
		return E_NOINTERFACE;
	}
	ULONG STDMETHODCALLTYPE AddRef () override { return ++m_ref; }
	ULONG STDMETHODCALLTYPE Release () override
	{
		ULONG c = --m_ref;
		if (c == 0) delete this;
		return c;
	}
	HRESULT STDMETHODCALLTYPE Invoke (ICoreWebView2 *, ICoreWebView2WebMessageReceivedEventArgs *args) override
	{
		LPWSTR raw = nullptr;
		if (SUCCEEDED (args->TryGetWebMessageAsString (&raw)) && raw)
		{
			HandleWebMessage (raw);
			CoTaskMemFree (raw);
		}
		return S_OK;
	}
};

class CtrlCompletedHandler final : public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler
{
	std::atomic<ULONG> m_ref{1};
public:
	HRESULT STDMETHODCALLTYPE QueryInterface (REFIID riid, void **ppv) override
	{
		if (riid == IID_IUnknown || riid == IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler)
		{
			*ppv = static_cast<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *>(this);
			AddRef ();
			return S_OK;
		}
		*ppv = nullptr;
		return E_NOINTERFACE;
	}
	ULONG STDMETHODCALLTYPE AddRef () override { return ++m_ref; }
	ULONG STDMETHODCALLTYPE Release () override
	{
		ULONG c = --m_ref;
		if (c == 0) delete this;
		return c;
	}
	HRESULT STDMETHODCALLTYPE Invoke (HRESULT result, ICoreWebView2Controller *controller) override
	{
		if (FAILED (result) || !controller || !g_hwnd || !IsWindow (g_hwnd))
			return S_OK;

		g_controller = controller;
		g_controller->AddRef ();
		g_controller->get_CoreWebView2 (&g_webview);

		if (g_webview)
		{
			ICoreWebView2Settings *settings = nullptr;
			if (SUCCEEDED (g_webview->get_Settings (&settings)) && settings)
			{
				settings->put_AreDefaultContextMenusEnabled (FALSE);
				settings->put_AreDevToolsEnabled (FALSE);
				settings->put_IsStatusBarEnabled (FALSE);
				settings->put_IsZoomControlEnabled (FALSE);
				settings->Release ();
			}

			auto *msgHandler = new WebMessageHandler ();
			g_webview->add_WebMessageReceived (msgHandler, &g_msgToken);
			msgHandler->Release ();

			// Hide old Win32 controls & menu bar now that WebView2 is ready
			_modern_bridge_hide_legacy_controls (g_hwnd);
			g_active.store (true);

			// Resize to fit full client area
			RECT rc = {};
			if (GetClientRect (g_hwnd, &rc))
				g_controller->put_Bounds (rc);

			g_controller->put_IsVisible (TRUE);

			// Apply dark/light titlebar
			_modern_ui_apply_titlebar_theme (g_hwnd);

			std::wstring html = LoadEmbeddedResourceHtml (IDR_MODERN_UI);
			if (!html.empty ())
				g_webview->NavigateToString (html.c_str ());
		}

		return S_OK;
	}
};

class EnvCompletedHandler final : public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler
{
	std::atomic<ULONG> m_ref{1};
public:
	HRESULT STDMETHODCALLTYPE QueryInterface (REFIID riid, void **ppv) override
	{
		if (riid == IID_IUnknown || riid == IID_ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler)
		{
			*ppv = static_cast<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *>(this);
			AddRef ();
			return S_OK;
		}
		*ppv = nullptr;
		return E_NOINTERFACE;
	}
	ULONG STDMETHODCALLTYPE AddRef () override { return ++m_ref; }
	ULONG STDMETHODCALLTYPE Release () override
	{
		ULONG c = --m_ref;
		if (c == 0) delete this;
		return c;
	}
	HRESULT STDMETHODCALLTYPE Invoke (HRESULT result, ICoreWebView2Environment *env) override
	{
		if (FAILED (result) || !env || !g_hwnd || !IsWindow (g_hwnd))
			return S_OK;

		if (g_env) g_env->Release ();
		g_env = env;
		g_env->AddRef ();

		auto *ctrlHandler = new CtrlCompletedHandler ();
		env->CreateCoreWebView2Controller (g_hwnd, ctrlHandler);
		ctrlHandler->Release ();

		// Pre-warm the bottom-right animated alert popup window
		InitAlertHostWindow (env);

		return S_OK;
	}
};

} // namespace

extern "C"
{

BOOLEAN _modern_ui_init (
	_In_ HWND hwnd
)
{
	if (g_initialized.exchange (true))
		return TRUE;

	g_hwnd = hwnd;

	_modern_ui_apply_titlebar_theme (hwnd);

	// Ensure a generous comfortable window size on first launch
	RECT rc = {};
	if (GetWindowRect (hwnd, &rc))
	{
		int w = rc.right - rc.left;
		int h = rc.bottom - rc.top;
		if (w < 1020 || h < 660)
		{
			int nw = (w < 1140) ? 1140 : w;
			int nh = (h < 720) ? 720 : h;
			SetWindowPos (hwnd, nullptr, 0, 0, nw, nh, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
		}
	}

	// Writable per-user WebView2 folder (required when running elevated as Admin!)
	std::wstring userDataFolder;
	PWSTR localAppData = nullptr;
	if (SUCCEEDED (SHGetKnownFolderPath (FOLDERID_LocalAppData, 0, nullptr, &localAppData)) && localAppData)
	{
		userDataFolder = std::wstring (localAppData) + L"\\simplewall\\WebView2";
		CoTaskMemFree (localAppData);
		SHCreateDirectoryExW (nullptr, userDataFolder.c_str (), nullptr);
	}

	auto *envHandler = new EnvCompletedHandler ();
	HRESULT hr = CreateCoreWebView2EnvironmentWithOptions (
		nullptr,
		userDataFolder.empty () ? nullptr : userDataFolder.c_str (),
		nullptr,
		envHandler
	);
	envHandler->Release ();

	return SUCCEEDED (hr) ? TRUE : FALSE;
}

VOID _modern_ui_resize (
	_In_ HWND hwnd,
	_In_ LPCRECT rect
)
{
	UNREFERENCED_PARAMETER (hwnd);

	if (g_controller && rect)
	{
		g_controller->put_Bounds (*rect);
	}
}

VOID _modern_ui_destroy (
	VOID
)
{
	g_active.store (false);
	g_alertReady.store (false);
	g_alertHtmlReady.store (false);
	g_alertQueue.clear ();

	if (g_alertWebview)
	{
		g_alertWebview->remove_WebMessageReceived (g_alertMsgToken);
		g_alertWebview->Release ();
		g_alertWebview = nullptr;
	}

	if (g_alertController)
	{
		g_alertController->Close ();
		g_alertController->Release ();
		g_alertController = nullptr;
	}

	if (g_alertHwnd && IsWindow (g_alertHwnd))
	{
		DestroyWindow (g_alertHwnd);
		g_alertHwnd = nullptr;
	}

	if (g_webview)
	{
		g_webview->remove_WebMessageReceived (g_msgToken);
		g_webview->Release ();
		g_webview = nullptr;
	}

	if (g_controller)
	{
		g_controller->Close ();
		g_controller->Release ();
		g_controller = nullptr;
	}

	if (g_env)
	{
		g_env->Release ();
		g_env = nullptr;
	}

	g_hwnd = nullptr;
	g_initialized.store (false);
}

BOOLEAN _modern_ui_isactive (
	VOID
)
{
	return g_active.load () ? TRUE : FALSE;
}

VOID _modern_ui_notify_change (
	VOID
)
{
	if (!g_active.load () || !g_hwnd || !IsWindow (g_hwnd))
		return;

	if (!g_refreshPending.exchange (true))
		PostMessageW (g_hwnd, WM_MODERN_UI_REFRESH, 0, 0);
}

VOID _modern_ui_handle_refresh (
	_In_ HWND hwnd
)
{
	UNREFERENCED_PARAMETER (hwnd);

	g_refreshPending.store (false);

	if (!g_active.load () || !g_webview)
		return;

	PostJsonToWebView (BuildFullSnapshotJson ());
}

VOID _modern_ui_handle_async_json (
	_In_ HWND hwnd,
	_In_ LPARAM lparam
)
{
	UNREFERENCED_PARAMETER (hwnd);

	auto *json = reinterpret_cast<std::wstring *>(lparam);
	if (!json)
		return;

	if (g_active.load () && g_webview)
		PostJsonToWebView (*json);

	delete json;
}

VOID _modern_ui_apply_titlebar_theme (
	_In_ HWND hwnd
)
{
	if (!hwnd || !IsWindow (hwnd))
		return;

	MODERN_STATE_SNAPSHOT st = {};
	_modern_bridge_get_state (&st);

	BOOL useDark = st.is_dark_theme ? TRUE : FALSE;
	// 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 10 20H1+ & Windows 11)
	DwmSetWindowAttribute (hwnd, 20, &useDark, sizeof (useDark));
	// 35 = DWMWA_CAPTION_COLOR (Windows 11)
	COLORREF captionColor = useDark ? RGB (19, 25, 36) : RGB (255, 255, 255);
	DwmSetWindowAttribute (hwnd, 35, &captionColor, sizeof (captionColor));
	// 34 = DWMWA_BORDER_COLOR (remove Windows red accent outline with clean neutral border)
	COLORREF borderColor = useDark ? RGB (42, 52, 68) : RGB (203, 213, 225);
	DwmSetWindowAttribute (hwnd, 34, &borderColor, sizeof (borderColor));
	// 33 = DWMWA_WINDOW_CORNER_PREFERENCE -> DWMWCP_ROUND (2)
	DWORD corner = 2;
	DwmSetWindowAttribute (hwnd, 33, &corner, sizeof (corner));
}

BOOLEAN _modern_alert_isready (
	VOID
)
{
	return (g_alertReady.load () && g_alertHwnd && IsWindow (g_alertHwnd)) ? TRUE : FALSE;
}

BOOLEAN _modern_alert_enqueue (
	_In_ ULONG_PTR app_hash,
	_In_opt_ LPCWSTR name,
	_In_opt_ LPCWSTR path,
	_In_opt_ LPCWSTR signature,
	_In_opt_ LPCWSTR remote_addr,
	_In_ UINT16 remote_port,
	_In_opt_ LPCWSTR protocol,
	_In_ BOOLEAN can_reopen
)
{
	if (!_modern_alert_isready ())
		return FALSE;

	AlertItem item;
	item.appHash = app_hash;
	if (name) item.name = name;
	if (path) item.path = path;
	if (signature) item.signature = signature;
	if (remote_addr) item.remoteAddr = remote_addr;
	item.remotePort = remote_port;
	if (protocol) item.protocol = protocol;
	item.canReopen = (can_reopen != FALSE);

	bool wasEmpty = g_alertQueue.empty ();
	bool updated = false;
	for (auto &existing : g_alertQueue)
	{
		if (existing.appHash == app_hash)
		{
			existing = item;
			updated = true;
			break;
		}
	}

	if (!updated)
		g_alertQueue.push_back (std::move (item));

	if (wasEmpty || g_alertQueue.front ().appHash == app_hash || !IsWindowVisible (g_alertHwnd))
	{
		ShowFrontAlert ();
	}
	else
	{
		// Refresh queue counter on currently visible alert
		ShowFrontAlert ();
	}

	return TRUE;
}

VOID _modern_ui_push_activity_raw (
	_In_ ULONG_PTR app_hash,
	_In_opt_ LPCWSTR app_name,
	_In_opt_ LPCWSTR path,
	_In_opt_ LPCWSTR remote_addr,
	_In_ UINT16 remote_port,
	_In_opt_ LPCWSTR protocol,
	_In_opt_ LPCWSTR direction,
	_In_ BOOLEAN is_allow,
	_In_ LONG64 timestamp
)
{
	ActivityItem item;
	item.appHash = app_hash;
	if (app_name) item.appName = app_name;
	if (path) item.path = path;
	if (remote_addr) item.remoteAddr = remote_addr;
	item.remotePort = remote_port;
	if (protocol) item.protocol = protocol;
	if (direction) item.direction = direction;
	item.isAllow = (is_allow != FALSE);
	item.timestamp = timestamp;

	{
		std::lock_guard<std::mutex> lock (g_activityMutex);
		g_activity.push_front (std::move (item));
		if (g_activity.size () > kMaxActivity)
			g_activity.pop_back ();
	}

	_modern_ui_notify_change ();
}

} // extern "C"
