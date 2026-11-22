// simplewall Personal Edition
// Modern Edge WebView2 UI host, icon/metadata inspector, live process scanner, and GitHub Fork Updater

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <shlobj.h>
#include <shellapi.h>
#include <dwmapi.h>
#include <tlhelp32.h>
#include <wincodec.h>
#include <wincrypt.h>
#include <mscat.h>
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
#include <fstream>
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
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

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
	UINT32 count = 1;
};

struct FileMeta
{
	std::wstring company;
	std::wstring description;
	std::wstring productName;
	std::wstring fileVersion;
	std::wstring parentApp;
	std::wstring signature;
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

std::mutex g_auditMutex;

std::wstring GetAuditLogPath ()
{
	static std::wstring cached;
	if (!cached.empty ()) return cached;
	PWSTR appData = nullptr;
	if (SUCCEEDED (SHGetKnownFolderPath (FOLDERID_RoamingAppData, 0, nullptr, &appData)) && appData)
	{
		std::wstring dir = std::wstring (appData) + L"\\Henry++\\simplewall";
		CoTaskMemFree (appData);
		SHCreateDirectoryExW (nullptr, dir.c_str (), nullptr);
		cached = dir + L"\\simplewall_audit.log";
	}
	return cached;
}

void WriteAuditLogLine (const std::wstring &level, const std::wstring &msg)
{
	std::wstring path = GetAuditLogPath ();
	if (path.empty ()) return;

	SYSTEMTIME st = {};
	GetLocalTime (&st);
	WCHAR ts[40];
	swprintf_s (ts, L"%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	std::wstring line = L"[" + std::wstring (ts) + L"] [" + level + L"] " + msg + L"\r\n";

	int utf8Len = WideCharToMultiByte (CP_UTF8, 0, line.data (), (int)line.size (), nullptr, 0, nullptr, nullptr);
	if (utf8Len <= 0) return;
	std::string utf8 ((size_t)utf8Len, '\0');
	WideCharToMultiByte (CP_UTF8, 0, line.data (), (int)line.size (), utf8.data (), utf8Len, nullptr, nullptr);

	std::lock_guard<std::mutex> lock (g_auditMutex);

	WIN32_FILE_ATTRIBUTE_DATA fad = {};
	if (GetFileAttributesExW (path.c_str (), GetFileExInfoStandard, &fad) && fad.nFileSizeLow > 5 * 1024 * 1024)
	{
		std::wstring oldPath = path + L".old";
		MoveFileExW (path.c_str (), oldPath.c_str (), MOVEFILE_REPLACE_EXISTING);
	}

	HANDLE h = CreateFileW (path.c_str (), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h != INVALID_HANDLE_VALUE)
	{
		DWORD written = 0;
		WriteFile (h, utf8.data (), (DWORD)utf8.size (), &written, nullptr);
		CloseHandle (h);
	}
}

std::vector<std::wstring> ReadRecentAuditLines (size_t maxLines)
{
	std::vector<std::wstring> lines;
	std::wstring path = GetAuditLogPath ();
	if (path.empty ()) return lines;

	std::lock_guard<std::mutex> lock (g_auditMutex);
	std::ifstream f (path, std::ios::binary);
	if (!f) return lines;

	std::deque<std::string> ring;
	std::string s;
	while (std::getline (f, s))
	{
		if (!s.empty () && s.back () == '\r') s.pop_back ();
		if (s.empty ()) continue;
		ring.push_back (s);
		if (ring.size () > maxLines) ring.pop_front ();
	}

	// Return newest first
	for (auto it = ring.rbegin (); it != ring.rend (); ++it)
	{
		int wlen = MultiByteToWideChar (CP_UTF8, 0, it->data (), (int)it->size (), nullptr, 0);
		if (wlen > 0)
		{
			std::wstring w ((size_t)wlen, L'\0');
			MultiByteToWideChar (CP_UTF8, 0, it->data (), (int)it->size (), w.data (), wlen);
			lines.push_back (std::move (w));
		}
	}
	return lines;
}

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

// ---- Digital Signature Extractor (PE + Windows Catalog + Microsoft Store AppxSignature.p7x) ----

std::wstring GetSignerNameFromMsgAndStore (HCERTSTORE hStore, HCRYPTMSG hMsg)
{
	if (!hStore || !hMsg) return {};

	DWORD signerSize = 0;
	if (!CryptMsgGetParam (hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerSize) || signerSize == 0)
		return {};

	std::vector<BYTE> signerBuf (signerSize);
	if (!CryptMsgGetParam (hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerBuf.data (), &signerSize))
		return {};

	auto *pSigner = reinterpret_cast<PCMSG_SIGNER_INFO>(signerBuf.data ());
	CERT_INFO certInfo = {};
	certInfo.Issuer = pSigner->Issuer;
	certInfo.SerialNumber = pSigner->SerialNumber;

	PCCERT_CONTEXT pCert = CertFindCertificateInStore (
		hStore,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0,
		CERT_FIND_SUBJECT_CERT,
		&certInfo,
		nullptr
	);

	std::wstring result;
	if (pCert)
	{
		WCHAR nameBuf[256] = {};
		if (CertGetNameStringW (pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nameBuf, (DWORD)std::size (nameBuf)) > 1)
			result = Trim (nameBuf);
		CertFreeCertificateContext (pCert);
	}
	return result;
}

std::wstring ExtractSignerFromFileObject (const std::wstring &filePath)
{
	HCERTSTORE hStore = nullptr;
	HCRYPTMSG hMsg = nullptr;
	DWORD encoding = 0, contentType = 0, formatType = 0;

	BOOL ok = CryptQueryObject (
		CERT_QUERY_OBJECT_FILE,
		filePath.c_str (),
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
		CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&encoding,
		&contentType,
		&formatType,
		&hStore,
		&hMsg,
		nullptr
	);

	std::wstring signer;
	if (ok)
		signer = GetSignerNameFromMsgAndStore (hStore, hMsg);

	if (hStore) CertCloseStore (hStore, 0);
	if (hMsg) CryptMsgClose (hMsg);
	return signer;
}

std::wstring ExtractSignerFromCatalog (const std::wstring &filePath)
{
	HANDLE hFile = CreateFileW (filePath.c_str (), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) return {};

	HCATADMIN hCatAdmin = nullptr;
	std::wstring signer;

	if (CryptCATAdminAcquireContext2 (&hCatAdmin, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0))
	{
		DWORD hashSize = 0;
		CryptCATAdminCalcHashFromFileHandle2 (hCatAdmin, hFile, &hashSize, nullptr, 0);
		if (hashSize > 0)
		{
			std::vector<BYTE> hashBuf (hashSize);
			if (CryptCATAdminCalcHashFromFileHandle2 (hCatAdmin, hFile, &hashSize, hashBuf.data (), 0))
			{
				HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash (hCatAdmin, hashBuf.data (), hashSize, 0, nullptr);
				if (hCatInfo)
				{
					CATALOG_INFO catInfo = {};
					catInfo.cbStruct = sizeof (catInfo);
					if (CryptCATCatalogInfoFromContext (hCatInfo, &catInfo, 0))
					{
						signer = ExtractSignerFromFileObject (catInfo.wszCatalogFile);
					}
					CryptCATAdminReleaseCatalogContext (hCatAdmin, hCatInfo, 0);
				}
			}
		}
		CryptCATAdminReleaseContext (hCatAdmin, 0);
	}

	CloseHandle (hFile);
	return signer;
}

std::wstring ExtractSignerFromAppxP7x (const std::wstring &exePath)
{
	// Microsoft Store / MSIX packages store their package signature in <PackageRoot>\AppxSignature.p7x
	std::wstring low = ToLower (exePath);
	size_t idx = low.find (L"\\windowsapps\\");
	if (idx == std::wstring::npos) return {};

	size_t pkgStart = idx + wcslen (L"\\windowsapps\\");
	size_t pkgEnd = exePath.find (L'\\', pkgStart);
	if (pkgEnd == std::wstring::npos) return {};

	std::wstring p7xPath = exePath.substr (0, pkgEnd) + L"\\AppxSignature.p7x";
	HANDLE hFile = CreateFileW (p7xPath.c_str (), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) return {};

	LARGE_INTEGER fileSize = {};
	std::wstring signer;
	if (GetFileSizeEx (hFile, &fileSize) && fileSize.QuadPart > 8 && fileSize.QuadPart < 2 * 1024 * 1024)
	{
		std::vector<BYTE> buf ((size_t)fileSize.QuadPart);
		DWORD read = 0;
		if (ReadFile (hFile, buf.data (), (DWORD)buf.size (), &read, nullptr) && read > 8)
		{
			// AppxSignature.p7x starts with 4-byte magic "PKCX" (0x50 0x4B 0x43 0x58) followed by DER PKCS#7 SignedData
			size_t offset = (buf[0] == 'P' && buf[1] == 'K' && buf[2] == 'C' && buf[3] == 'X') ? 4 : 0;
			CERT_BLOB blob = {};
			blob.cbData = (DWORD)(read - offset);
			blob.pbData = buf.data () + offset;

			HCERTSTORE hStore = nullptr;
			HCRYPTMSG hMsg = nullptr;
			DWORD enc = 0, ctype = 0, ftype = 0;
			if (CryptQueryObject (
				CERT_QUERY_OBJECT_BLOB,
				&blob,
				CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
				CERT_QUERY_FORMAT_FLAG_BINARY,
				0,
				&enc, &ctype, &ftype,
				&hStore, &hMsg, nullptr))
			{
				signer = GetSignerNameFromMsgAndStore (hStore, hMsg);
				if (hStore) CertCloseStore (hStore, 0);
				if (hMsg) CryptMsgClose (hMsg);
			}
		}
	}

	CloseHandle (hFile);
	return signer;
}

std::wstring ExtractFileSignature (const std::wstring &filePath)
{
	if (filePath.empty ()) return {};

	// 1. Embedded Authenticode PE signature
	std::wstring s = ExtractSignerFromFileObject (filePath);
	if (!s.empty ()) return s;

	// 2. Microsoft Store / MSIX AppxSignature.p7x
	s = ExtractSignerFromAppxP7x (filePath);
	if (!s.empty ()) return s;

	// 3. Windows System Catalog (.cat)
	return ExtractSignerFromCatalog (filePath);
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

		meta.signature = ExtractFileSignature (path);
		meta.iconDataUrl = ExtractIconDataUrl (path);
	}

	{
		std::lock_guard<std::mutex> lock (g_metaMutex);
		if (g_metaCache.size () < 2000)
			g_metaCache[key] = meta;
	}

	return meta;
}

std::atomic<bool> g_metaEnrichRunning{false};

bool TryGetCachedMeta (const std::wstring &path, FileMeta &outMeta)
{
	std::wstring key = ToLower (path);
	std::lock_guard<std::mutex> lock (g_metaMutex);
	auto it = g_metaCache.find (key);
	if (it != g_metaCache.end ())
	{
		outMeta = it->second;
		return true;
	}
	return false;
}

void StartMetaEnrichmentAsync (std::vector<std::pair<std::wstring, bool>> pending)
{
	if (pending.empty () || g_metaEnrichRunning.exchange (true))
		return;

	std::thread ([pending = std::move (pending)] () {
		CoInitializeEx (nullptr, COINIT_APARTMENTTHREADED);
		for (const auto &p : pending)
		{
			if (!g_active.load ()) break;
			GetFileMeta (p.first, p.second);
		}
		CoUninitialize ();
		g_metaEnrichRunning.store (false);
		_modern_ui_notify_change ();
	}).detach ();
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
			<< L",\"count\":" << ev.count
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

	std::vector<std::pair<std::wstring, bool>> pendingMeta;
	bool first = true;
	for (SIZE_T i = 0; i < appCount; ++i)
	{
		const auto &a = apps[i];
		std::wstring path (a.path);
		std::wstring name (a.name);
		std::wstring sig (a.signature);
		std::wstring fileName = ExtractFileName (path);
		bool isRun = !path.empty () && (running.find (ToLower (path)) != running.end ());

		// Instant non-blocking lookup: never stall the UI thread on icons/catalog signatures!
		FileMeta meta;
		if (a.category == 0 || a.is_enabled || a.is_silent || a.is_blocked)
		{
			if (!TryGetCachedMeta (path, meta))
			{
				meta.parentApp = InferParentApp (path);
				if (!path.empty () && pendingMeta.size () < 200)
					pendingMeta.emplace_back (path, a.exists != FALSE);
			}
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

		if (sig.empty () && !meta.signature.empty ())
			sig = meta.signature;

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

	if (!pendingMeta.empty ())
		StartMetaEnrichmentAsync (std::move (pendingMeta));

	ss << L"],\"activity\":" << BuildActivityArrayJson () << L"}";
	return ss.str ();
}

// ---- System Diagnose & Active Internet Connections Scanner ----

std::wstring GetBfeServiceStatus ()
{
	SC_HANDLE scm = OpenSCManagerW (nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!scm) return L"Unknown";
	SC_HANDLE svc = OpenServiceW (scm, L"BFE", SERVICE_QUERY_STATUS);
	std::wstring res = L"Not Found";
	if (svc)
	{
		SERVICE_STATUS ss = {};
		if (QueryServiceStatus (svc, &ss))
		{
			switch (ss.dwCurrentState)
			{
				case SERVICE_RUNNING: res = L"Running"; break;
				case SERVICE_STOPPED: res = L"Stopped"; break;
				case SERVICE_START_PENDING: res = L"Starting"; break;
				default: res = L"Other"; break;
			}
		}
		CloseServiceHandle (svc);
	}
	CloseServiceHandle (scm);
	return res;
}

std::wstring TcpStateName (DWORD state)
{
	switch (state)
	{
		case MIB_TCP_STATE_LISTEN: return L"Listening";
		case MIB_TCP_STATE_SYN_SENT: return L"Connecting";
		case MIB_TCP_STATE_SYN_RCVD: return L"Syn Received";
		case MIB_TCP_STATE_ESTAB: return L"Connected";
		case MIB_TCP_STATE_FIN_WAIT1:
		case MIB_TCP_STATE_FIN_WAIT2:
		case MIB_TCP_STATE_CLOSING:
		case MIB_TCP_STATE_LAST_ACK: return L"Closing";
		case MIB_TCP_STATE_CLOSE_WAIT: return L"Close Wait";
		case MIB_TCP_STATE_TIME_WAIT: return L"Time Wait";
		default: return L"Closed";
	}
}

std::wstring FriendlyPortLabel (UINT16 port)
{
	switch (port)
	{
		case 53: return L"DNS";
		case 80: return L"HTTP";
		case 123: return L"NTP";
		case 443: return L"HTTPS";
		case 445: return L"SMB";
		case 993: return L"IMAPS";
		case 3389: return L"RDP";
		case 5353: return L"mDNS";
		case 8080: return L"HTTP-Alt";
		default: return L"";
	}
}

bool IsExternalAddr (const std::wstring &ip)
{
	if (ip.empty () || ip == L"0.0.0.0" || ip == L"::" || ip == L"::1" || ip == L"*")
		return false;
	if (ip.starts_with (L"127.") || ip.starts_with (L"10.") || ip.starts_with (L"192.168.") || ip.starts_with (L"169.254.") || ip.starts_with (L"fe80:") || ip.starts_with (L"fc") || ip.starts_with (L"fd"))
		return false;
	return true;
}

std::wstring FormatIpV4 (DWORD addr)
{
	WCHAR buf[64] = {};
	IN_ADDR in = {};
	in.S_un.S_addr = addr;
	InetNtopW (AF_INET, &in, buf, std::size (buf));
	return buf;
}

std::wstring FormatIpV6 (const BYTE addr[16])
{
	WCHAR buf[64] = {};
	InetNtopW (AF_INET6, addr, buf, std::size (buf));
	return buf;
}

std::wstring BuildDiagnoseJson ()
{
	MODERN_DIAG_INFO diag = {};
	_modern_bridge_get_diag (&diag);

	// Map lowercase app path -> (id, status) from simplewall
	MODERN_APP_SNAPSHOT *apps = nullptr;
	SIZE_T appCount = 0;
	_modern_bridge_get_apps (&apps, &appCount);
	struct AppLookup { ULONG_PTR id; bool enabled; std::wstring name; };
	std::unordered_map<std::wstring, AppLookup> pathMap;
	for (SIZE_T i = 0; i < appCount; ++i)
	{
		std::wstring p = ToLower (apps[i].path);
		if (!p.empty ())
			pathMap[p] = { apps[i].app_hash, apps[i].is_enabled != FALSE, apps[i].name };
	}
	_modern_bridge_free_apps (apps);

	// Cache PID -> exe path
	std::unordered_map<DWORD, std::wstring> pidPath;
	auto getPidPath = [&] (DWORD pid) -> std::wstring {
		if (pid == 0) return L"System Idle";
		if (pid == 4) return L"System";
		auto it = pidPath.find (pid);
		if (it != pidPath.end ()) return it->second;
		std::wstring path;
		HANDLE h = OpenProcess (PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (h)
		{
			WCHAR buf[1024];
			DWORD sz = (DWORD)std::size (buf);
			if (QueryFullProcessImageNameW (h, 0, buf, &sz))
				path.assign (buf, sz);
			CloseHandle (h);
		}
		pidPath[pid] = path;
		return path;
	};

	struct ConnEntry
	{
		DWORD pid = 0;
		std::wstring proto;
		std::wstring state;
		std::wstring localIp;
		UINT16 localPort = 0;
		std::wstring remoteIp;
		UINT16 remotePort = 0;
	};
	std::vector<ConnEntry> conns;

	// TCP IPv4
	{
		DWORD sz = 0;
		GetExtendedTcpTable (nullptr, &sz, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
		if (sz > 0)
		{
			std::vector<BYTE> buf (sz);
			if (GetExtendedTcpTable (buf.data (), &sz, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
			{
				auto *tbl = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buf.data ());
				for (DWORD i = 0; i < tbl->dwNumEntries; ++i)
				{
					const auto &r = tbl->table[i];
					ConnEntry c;
					c.pid = r.dwOwningPid;
					c.proto = L"TCP";
					c.state = TcpStateName (r.dwState);
					c.localIp = FormatIpV4 (r.dwLocalAddr);
					c.localPort = ntohs ((u_short)r.dwLocalPort);
					c.remoteIp = (r.dwState == MIB_TCP_STATE_LISTEN) ? L"*" : FormatIpV4 (r.dwRemoteAddr);
					c.remotePort = (r.dwState == MIB_TCP_STATE_LISTEN) ? 0 : ntohs ((u_short)r.dwRemotePort);
					conns.push_back (std::move (c));
				}
			}
		}
	}

	// TCP IPv6
	{
		DWORD sz = 0;
		GetExtendedTcpTable (nullptr, &sz, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
		if (sz > 0)
		{
			std::vector<BYTE> buf (sz);
			if (GetExtendedTcpTable (buf.data (), &sz, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
			{
				auto *tbl = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buf.data ());
				for (DWORD i = 0; i < tbl->dwNumEntries; ++i)
				{
					const auto &r = tbl->table[i];
					ConnEntry c;
					c.pid = r.dwOwningPid;
					c.proto = L"TCPv6";
					c.state = TcpStateName (r.dwState);
					c.localIp = FormatIpV6 (r.ucLocalAddr);
					c.localPort = ntohs ((u_short)r.dwLocalPort);
					c.remoteIp = (r.dwState == MIB_TCP_STATE_LISTEN) ? L"*" : FormatIpV6 (r.ucRemoteAddr);
					c.remotePort = (r.dwState == MIB_TCP_STATE_LISTEN) ? 0 : ntohs ((u_short)r.dwRemotePort);
					conns.push_back (std::move (c));
				}
			}
		}
	}

	// UDP IPv4
	{
		DWORD sz = 0;
		GetExtendedUdpTable (nullptr, &sz, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
		if (sz > 0)
		{
			std::vector<BYTE> buf (sz);
			if (GetExtendedUdpTable (buf.data (), &sz, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
			{
				auto *tbl = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buf.data ());
				for (DWORD i = 0; i < tbl->dwNumEntries; ++i)
				{
					const auto &r = tbl->table[i];
					ConnEntry c;
					c.pid = r.dwOwningPid;
					c.proto = L"UDP";
					c.state = L"Active";
					c.localIp = FormatIpV4 (r.dwLocalAddr);
					c.localPort = ntohs ((u_short)r.dwLocalPort);
					c.remoteIp = L"*";
					c.remotePort = 0;
					conns.push_back (std::move (c));
				}
			}
		}
	}

	// Sort: Connected external first, then Connected local, then Listening/UDP
	std::stable_sort (conns.begin (), conns.end (), [] (const ConnEntry &a, const ConnEntry &b) {
		auto rank = [] (const ConnEntry &c) {
			if (c.state == L"Connected" && IsExternalAddr (c.remoteIp)) return 0;
			if (c.state == L"Connected") return 1;
			if (c.state == L"Connecting") return 2;
			if (c.state == L"Listening") return 3;
			return 4;
		};
		return rank (a) < rank (b);
	});

	std::wstring bfeStatus = GetBfeServiceStatus ();
	auto auditLines = ReadRecentAuditLines (80);
	std::wstring auditPath = GetAuditLogPath ();

	std::wostringstream ss;
	ss << L"{\"type\":\"diagnoseResult\""
		<< L",\"health\":{"
		<< L"\"wfpInstalled\":" << (diag.wfp_installed ? L"true" : L"false")
		<< L",\"bfeStatus\":\"" << JsonEscape (bfeStatus) << L"\""
		<< L",\"profilePath\":\"" << JsonEscape (diag.profile_path) << L"\""
		<< L",\"profileExists\":" << (diag.profile_exists ? L"true" : L"false")
		<< L",\"profileSize\":" << diag.profile_size
		<< L",\"auditPath\":\"" << JsonEscape (auditPath) << L"\""
		<< L",\"alertReady\":" << (g_alertReady.load () ? L"true" : L"false")
		<< L"},\"connections\":[";

	size_t maxOut = std::min<size_t> (conns.size (), 250);
	for (size_t i = 0; i < maxOut; ++i)
	{
		const auto &c = conns[i];
		std::wstring path = getPidPath (c.pid);
		std::wstring fileName = ExtractFileName (path);
		bool realFile = path.size () > 3 && path[1] == L':';
		FileMeta meta = realFile ? GetFileMeta (path, true) : FileMeta{};
		if (path == L"System")
		{
			meta.company = L"Microsoft Windows";
			meta.parentApp = L"Windows Kernel";
			meta.signature = L"Microsoft Windows";
		}

		std::wstring appIdStr;
		std::wstring fwStatus = L"unlisted";
		std::wstring displayName = fileName.empty () ? (L"PID " + std::to_wstring (c.pid)) : fileName;

		auto it = pathMap.find (ToLower (path));
		if (it != pathMap.end ())
		{
			appIdStr = std::to_wstring (it->second.id);
			fwStatus = it->second.enabled ? L"allowed" : L"blocked";
			if (!it->second.name.empty ()) displayName = it->second.name;
		}

		if (i > 0) ss << L",";
		ss << L"{\"pid\":" << c.pid
			<< L",\"appId\":\"" << appIdStr << L"\""
			<< L",\"name\":\"" << JsonEscape (displayName) << L"\""
			<< L",\"fileName\":\"" << JsonEscape (fileName) << L"\""
			<< L",\"path\":\"" << JsonEscape (path) << L"\""
			<< L",\"company\":\"" << JsonEscape (meta.company) << L"\""
			<< L",\"signature\":\"" << JsonEscape (meta.signature) << L"\""
			<< L",\"parentApp\":\"" << JsonEscape (meta.parentApp) << L"\""
			<< L",\"iconDataUrl\":\"" << JsonEscape (meta.iconDataUrl) << L"\""
			<< L",\"proto\":\"" << JsonEscape (c.proto) << L"\""
			<< L",\"state\":\"" << JsonEscape (c.state) << L"\""
			<< L",\"localIp\":\"" << JsonEscape (c.localIp) << L"\""
			<< L",\"localPort\":" << c.localPort
			<< L",\"remoteIp\":\"" << JsonEscape (c.remoteIp) << L"\""
			<< L",\"remotePort\":" << c.remotePort
			<< L",\"portLabel\":\"" << JsonEscape (FriendlyPortLabel (c.remotePort ? c.remotePort : c.localPort)) << L"\""
			<< L",\"isExternal\":" << (IsExternalAddr (c.remoteIp) ? L"true" : L"false")
			<< L",\"fwStatus\":\"" << fwStatus << L"\""
			<< L"}";
	}

	ss << L"],\"auditLog\":[";
	for (size_t i = 0; i < auditLines.size (); ++i)
	{
		if (i > 0) ss << L",";
		ss << L"\"" << JsonEscape (auditLines[i]) << L"\"";
	}
	ss << L"]}";

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

bool WinHttpGetToBytesOnce (const std::wstring &url, DWORD accessType, std::string &outBody, DWORD &outStatus, DWORD &outErr, bool isBinaryDownload)
{
	outBody.clear ();
	outStatus = 0;
	outErr = 0;

	URL_COMPONENTS uc = {};
	uc.dwStructSize = sizeof (uc);
	WCHAR host[256] = {};
	WCHAR path[2048] = {};
	uc.lpszHostName = host;
	uc.dwHostNameLength = (DWORD)std::size (host);
	uc.lpszUrlPath = path;
	uc.dwUrlPathLength = (DWORD)std::size (path);

	if (!WinHttpCrackUrl (url.c_str (), (DWORD)url.size (), 0, &uc))
	{
		outErr = GetLastError ();
		return false;
	}

	HINTERNET hSession = WinHttpOpen (L"SimpleWall/" APP_FORK_VERSION, accessType, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSession)
	{
		outErr = GetLastError ();
		return false;
	}

	// Enable Windows 10/11 Happy Eyeballs (IPv6 fast fallback to IPv4 in ~200ms instead of 21s SYN hang!)
	BOOL fastFallback = TRUE;
	WinHttpSetOption (hSession, WINHTTP_OPTION_IPV6_FAST_FALLBACK, &fastFallback, sizeof (fastFallback));

	// Keep resolveTimeout = 0 so DNS never aborts prematurely; snappy 5s connect timeout with Happy Eyeballs
	WinHttpSetTimeouts (hSession, 0, 5000, 10000, 20000);

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
		if (!isBinaryDownload)
		{
			DWORD decomp = WINHTTP_DECOMPRESSION_FLAG_ALL;
			WinHttpSetOption (hRequest, WINHTTP_OPTION_DECOMPRESSION, &decomp, sizeof (decomp));
		}

		LPCWSTR acceptHdr = isBinaryDownload
			? L"Accept: application/octet-stream\r\n"
			: L"Accept: application/vnd.github+json\r\n";
		WinHttpAddRequestHeaders (hRequest, acceptHdr, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

		if (WinHttpSendRequest (hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
			WinHttpReceiveResponse (hRequest, nullptr))
		{
			DWORD statusSize = sizeof (outStatus);
			WinHttpQueryHeaders (hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &outStatus, &statusSize, WINHTTP_NO_HEADER_INDEX);

			DWORD contentLen = 0;
			DWORD lenSz = sizeof (contentLen);
			if (WinHttpQueryHeaders (hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &contentLen, &lenSz, WINHTTP_NO_HEADER_INDEX) &&
				contentLen > 0 && contentLen < 64 * 1024 * 1024)
			{
				outBody.reserve (contentLen);
			}

			std::vector<char> chunk (65536);
			DWORD read = 0;
			DWORD lastReportTick = GetTickCount ();

			while (WinHttpReadData (hRequest, chunk.data (), (DWORD)chunk.size (), &read) && read > 0)
			{
				outBody.append (chunk.data (), read);

				if (isBinaryDownload && contentLen > 0)
				{
					DWORD nowTick = GetTickCount ();
					if (nowTick - lastReportTick >= 120)
					{
						lastReportTick = nowTick;
						int pct = (int)((outBody.size () * 100) / contentLen);
						if (pct > 99) pct = 99;
						std::wostringstream prog;
						prog << L"{\"type\":\"updateInstallStatus\",\"progress\":" << pct
							<< L",\"message\":\"Downloading update... " << pct << L"%\"}";
						PostAsyncJsonFromWorker (prog.str ());
					}
				}
			}
			ok = true;
		}
		else
		{
			outErr = GetLastError ();
		}
	}
	else
	{
		outErr = GetLastError ();
	}

	if (hRequest) WinHttpCloseHandle (hRequest);
	if (hConnect) WinHttpCloseHandle (hConnect);
	WinHttpCloseHandle (hSession);
	return ok;
}

bool CurlIpv4Fallback (const std::wstring &url, std::string &outBody, DWORD &outStatus, bool isBinaryDownload)
{
	outBody.clear ();
	outStatus = 0;

	WCHAR tempDir[MAX_PATH] = {};
	GetTempPathW (MAX_PATH, tempDir);
	std::wstring outPath = std::wstring (tempDir) + (isBinaryDownload ? L"sw_curl_dl.bin" : L"sw_curl_api.json");
	DeleteFileW (outPath.c_str ());

	std::wstring cmd = L"\"C:\\Windows\\System32\\curl.exe\" -4 -sSL --connect-timeout 6 --max-time 25 "
		L"-H \"User-Agent: SimpleWall/" APP_FORK_VERSION L"\" "
		+ std::wstring (isBinaryDownload ? L"" : L"-H \"Accept: application/vnd.github+json\" ")
		+ L"-o \"" + outPath + L"\" -w \"%{http_code}\" \"" + url + L"\"";

	SECURITY_ATTRIBUTES sa = {};
	sa.nLength = sizeof (sa);
	sa.bInheritHandle = TRUE;

	HANDLE hRead = nullptr, hWrite = nullptr;
	if (!CreatePipe (&hRead, &hWrite, &sa, 0))
		return false;
	SetHandleInformation (hRead, HANDLE_FLAG_INHERIT, 0);

	STARTUPINFOW si = {};
	si.cb = sizeof (si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWrite;
	si.hStdError = hWrite;

	PROCESS_INFORMATION pi = {};
	bool launched = CreateProcessW (nullptr, cmd.data (), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi) != FALSE;
	CloseHandle (hWrite);

	std::string statusStr;
	if (launched)
	{
		char buf[64];
		DWORD r = 0;
		while (ReadFile (hRead, buf, sizeof (buf), &r, nullptr) && r > 0)
			statusStr.append (buf, r);

		WaitForSingleObject (pi.hProcess, 25000);
		CloseHandle (pi.hThread);
		CloseHandle (pi.hProcess);
	}
	CloseHandle (hRead);

	if (!launched || statusStr.empty ())
	{
		DeleteFileW (outPath.c_str ());
		return false;
	}

	outStatus = (DWORD)strtoul (statusStr.c_str (), nullptr, 10);

	HANDLE hFile = CreateFileW (outPath.c_str (), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		LARGE_INTEGER sz = {};
		if (GetFileSizeEx (hFile, &sz) && sz.QuadPart > 0 && sz.QuadPart < 64 * 1024 * 1024)
		{
			outBody.resize ((size_t)sz.QuadPart);
			DWORD total = 0, rd = 0;
			while (total < outBody.size () && ReadFile (hFile, outBody.data () + total, (DWORD)(outBody.size () - total), &rd, nullptr) && rd > 0)
				total += rd;
			outBody.resize (total);
		}
		CloseHandle (hFile);
	}
	DeleteFileW (outPath.c_str ());
	return outStatus > 0;
}

bool WinHttpGetToBytes (const std::wstring &url, std::string &outBody, DWORD &outStatus, bool isBinaryDownload = false)
{
	DWORD t0 = GetTickCount ();
	DWORD err = 0;

	// Tier 1: Fast direct WinHTTP with IPv6 Happy Eyeballs fast-fallback
	if (WinHttpGetToBytesOnce (url, WINHTTP_ACCESS_TYPE_NO_PROXY, outBody, outStatus, err, isBinaryDownload))
	{
		WCHAR logBuf[160];
		swprintf_s (logBuf, L"Updater WinHTTP OK (HTTP %lu in %lu ms)", outStatus, GetTickCount () - t0);
		WriteAuditLogLine (L"UPDATE", logBuf);
		return true;
	}

	// Tier 2: Pure IPv4 fallback via Windows built-in curl.exe -4 (bypasses dead NAT64 IPv6 immediately!)
	if (CurlIpv4Fallback (url, outBody, outStatus, isBinaryDownload))
	{
		WCHAR logBuf[180];
		swprintf_s (logBuf, L"Updater IPv4 fallback OK (HTTP %lu in %lu ms, winhttp err=%lu)", outStatus, GetTickCount () - t0, err);
		WriteAuditLogLine (L"UPDATE", logBuf);
		return true;
	}

	// Tier 3: WinHTTP with automatic proxy
	DWORD err2 = 0;
	if (WinHttpGetToBytesOnce (url, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, outBody, outStatus, err2, isBinaryDownload))
		return true;

	WCHAR logBuf[256];
	swprintf_s (logBuf, L"Updater failed after %lu ms (direct err=%lu, proxy err=%lu)", GetTickCount () - t0, err, err2);
	WriteAuditLogLine (L"UPDATE", logBuf);
	return false;
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
				bool isSetup = (low.find (L"setup") != std::wstring::npos);
				if ((low.ends_with (L".exe") && !isSetup) || low.ends_with (L".zip"))
				{
					downloadUrl = candidate;
					assetName = ExtractFileName (candidate);
					if (low.ends_with (L".exe") && !isSetup) break; // prefer direct simplewall.exe over installer
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
	UNREFERENCED_PARAMETER (assetName);
	std::thread ([downloadUrl = std::move (downloadUrl)] () {
		std::wstring low = ToLower (downloadUrl);
		if (!low.starts_with (L"https://github.com/" APP_FORK_OWNER L"/") &&
			!low.starts_with (L"https://github.com/") &&
			!low.starts_with (L"https://objects.githubusercontent.com/") &&
			!low.starts_with (L"https://release-assets.githubusercontent.com/"))
		{
			PostAsyncJsonFromWorker (L"{\"type\":\"updateInstallStatus\",\"error\":\"Refused untrusted update URL.\"}");
			return;
		}

		PostAsyncJsonFromWorker (L"{\"type\":\"updateInstallStatus\",\"progress\":5,\"message\":\"Downloading update...\"}");

		std::string bytes;
		DWORD status = 0;
		if (!WinHttpGetToBytes (downloadUrl, bytes, status, true) || status != 200 || bytes.size () < 32768)
		{
			WriteAuditLogLine (L"UPDATE", L"Update download failed");
			PostAsyncJsonFromWorker (L"{\"type\":\"updateInstallStatus\",\"error\":\"Failed to download update package from GitHub.\"}");
			return;
		}

		WCHAR tempDir[MAX_PATH] = {};
		GetTempPathW (MAX_PATH, tempDir);
		std::wstring dlPath = std::wstring (tempDir) + L"simplewall_update_new.exe";
		std::wstring bakPath = std::wstring (tempDir) + L"simplewall_prev.exe.bak";

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

		// Instant native cmd.exe swapper (boots in ~15ms instead of 4000ms PowerShell CLR!)
		std::wstring batPath = std::wstring (tempDir) + L"simplewall_apply_update.cmd";
		std::wostringstream bat;
		bat << L"@echo off\r\n"
			<< L"set \"TARGET=" << selfPath << L"\"\r\n"
			<< L"set \"SRC=" << dlPath << L"\"\r\n"
			<< L"set \"BAK=" << bakPath << L"\"\r\n"
			<< L"copy /y \"%TARGET%\" \"%BAK%\" >nul 2>&1\r\n"
			<< L"set /a tries=0\r\n"
			<< L":retry\r\n"
			<< L"move /y \"%SRC%\" \"%TARGET%\" >nul 2>&1\r\n"
			<< L"if errorlevel 1 (\r\n"
			<< L"  set /a tries+=1\r\n"
			<< L"  if %tries% GEQ 80 goto fail\r\n"
			<< L"  ping -n 1 -w 100 127.0.0.1 >nul\r\n"
			<< L"  goto retry\r\n"
			<< L")\r\n"
			<< L"start \"\" \"%TARGET%\"\r\n"
			<< L"del \"%~f0\" >nul 2>&1\r\n"
			<< L"exit /b 0\r\n"
			<< L":fail\r\n"
			<< L"start \"\" \"%TARGET%\"\r\n"
			<< L"del \"%~f0\" >nul 2>&1\r\n";

		std::wstring batText = bat.str ();
		int ansiLen = WideCharToMultiByte (CP_ACP, 0, batText.data (), (int)batText.size (), nullptr, 0, nullptr, nullptr);
		std::string batAnsi ((size_t)ansiLen, '\0');
		WideCharToMultiByte (CP_ACP, 0, batText.data (), (int)batText.size (), batAnsi.data (), ansiLen, nullptr, nullptr);

		HANDLE hScript = CreateFileW (batPath.c_str (), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hScript == INVALID_HANDLE_VALUE)
		{
			PostAsyncJsonFromWorker (L"{\"type\":\"updateInstallStatus\",\"error\":\"Could not create updater script.\"}");
			return;
		}
		WriteFile (hScript, batAnsi.data (), (DWORD)batAnsi.size (), &written, nullptr);
		CloseHandle (hScript);

		WriteAuditLogLine (L"UPDATE", L"Downloaded update cleanly, restarting to swap binary");

		std::wstring cmd = L"cmd.exe /c \"" + batPath + L"\"";
		STARTUPINFOW si = {};
		si.cb = sizeof (si);
		PROCESS_INFORMATION pi = {};
		if (CreateProcessW (nullptr, cmd.data (), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			CloseHandle (pi.hThread);
			CloseHandle (pi.hProcess);
			PostAsyncJsonFromWorker (L"{\"type\":\"updateInstallStatus\",\"progress\":100,\"message\":\"Installing update & restarting...\"}");
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
	else if (action == L"getDiagnose")
	{
		PostJsonToWebView (BuildDiagnoseJson ());
	}
	else if (action == L"openAuditLog")
	{
		std::wstring p = GetAuditLogPath ();
		if (!p.empty ())
			ShellExecuteW (g_hwnd, L"open", L"notepad.exe", p.c_str (), nullptr, SW_SHOWNORMAL);
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

std::wstring GetEmbeddedFontStyleTag ()
{
	static std::wstring cached;
	static bool loaded = false;
	if (!loaded)
	{
		loaded = true;
		HMODULE hMod = GetModuleHandleW (nullptr);
		HRSRC hRes = FindResourceW (hMod, MAKEINTRESOURCEW (IDR_MODERN_FONT), RT_RCDATA);
		if (hRes)
		{
			HGLOBAL hData = LoadResource (hMod, hRes);
			if (hData)
			{
				DWORD sz = SizeofResource (hMod, hRes);
				const BYTE *ptr = (const BYTE *)LockResource (hData);
				if (ptr && sz > 0)
				{
					cached = L"<style>@font-face{font-family:'Google Sans Flex';src:url(data:font/woff2;base64,"
						+ Base64Encode (ptr, sz)
						+ L") format('woff2');font-weight:400 700;font-style:normal;font-display:swap;}</style>";
				}
			}
		}
	}
	return cached;
}

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
	std::wstring html = Utf8ToWide (std::string (ptr, sz));
	std::wstring fontTag = GetEmbeddedFontStyleTag ();
	if (!fontTag.empty ())
	{
		size_t pos = html.find (L"</head>");
		if (pos != std::wstring::npos)
			html.insert (pos, fontTag);
	}
	return html;
}

// ---- Bottom-right animated alert popup helpers ----

// Smooth 60fps alert open/close window animation state
constexpr UINT_PTR kAlertAnimTimerId = 77;
int g_alertAnimDir = 0; // 1 = opening, -1 = closing, 0 = idle
DWORD g_alertAnimStart = 0;
int g_alertTargetX = 0;
int g_alertTargetY = 0;
int g_alertW = 432;
int g_alertH = 282;
int g_alertSlidePx = 18;

void ComputeAlertTargetRect ()
{
	if (!g_alertHwnd || !IsWindow (g_alertHwnd))
		return;

	UINT dpi = GetDpiForWindow (g_alertHwnd);
	if (dpi == 0) dpi = 96;
	g_alertW = MulDiv (432, (int)dpi, 96);
	g_alertH = MulDiv (282, (int)dpi, 96);
	g_alertSlidePx = MulDiv (18, (int)dpi, 96);
	int margin = MulDiv (16, (int)dpi, 96);

	RECT wa = {};
	SystemParametersInfoW (SPI_GETWORKAREA, 0, &wa, 0);

	g_alertTargetX = wa.right - g_alertW - margin;
	g_alertTargetY = wa.bottom - g_alertH - margin;

	if (g_alertController)
	{
		RECT rc = {0, 0, g_alertW, g_alertH};
		g_alertController->put_Bounds (rc);
	}
}

void StartAlertAnim (bool opening)
{
	if (!g_alertHwnd || !IsWindow (g_alertHwnd))
		return;

	ComputeAlertTargetRect ();
	g_alertAnimDir = opening ? 1 : -1;
	g_alertAnimStart = GetTickCount ();

	if (opening)
	{
		SetLayeredWindowAttributes (g_alertHwnd, 0, 0, LWA_ALPHA);
		SetWindowPos (g_alertHwnd, HWND_TOPMOST, g_alertTargetX, g_alertTargetY + g_alertSlidePx, g_alertW, g_alertH, SWP_NOACTIVATE);
		if (g_alertController)
			g_alertController->put_IsVisible (TRUE);
		ShowWindow (g_alertHwnd, SW_SHOWNOACTIVATE);
	}

	SetTimer (g_alertHwnd, kAlertAnimTimerId, 15, nullptr);
}

void StepAlertAnim ()
{
	if (!g_alertHwnd || g_alertAnimDir == 0)
		return;

	DWORD elapsed = GetTickCount () - g_alertAnimStart;
	float dur = (g_alertAnimDir > 0) ? 210.0f : 220.0f;
	float t = (float)elapsed / dur;
	if (t > 1.0f) t = 1.0f;

	float eased;
	int curY;
	BYTE alpha;

	if (g_alertAnimDir > 0)
	{
		// Cubic ease-out slide up + fade in
		float inv = 1.0f - t;
		eased = 1.0f - inv * inv * inv;
		curY = g_alertTargetY + (int)((1.0f - eased) * g_alertSlidePx);
		alpha = (BYTE)(eased * 255.0f);
	}
	else
	{
		// Quadratic ease-in slide down + fade out
		eased = t * t;
		curY = g_alertTargetY + (int)(eased * g_alertSlidePx);
		alpha = (BYTE)((1.0f - eased) * 255.0f);
	}

	SetLayeredWindowAttributes (g_alertHwnd, 0, alpha, LWA_ALPHA);
	SetWindowPos (g_alertHwnd, HWND_TOPMOST, g_alertTargetX, curY, g_alertW, g_alertH, SWP_NOACTIVATE | SWP_NOSIZE);

	if (t >= 1.0f)
	{
		KillTimer (g_alertHwnd, kAlertAnimTimerId);
		int finishedDir = g_alertAnimDir;
		g_alertAnimDir = 0;

		if (finishedDir < 0)
		{
			ShowWindow (g_alertHwnd, SW_HIDE);
			if (g_alertController)
				g_alertController->put_IsVisible (FALSE);
		}
	}
}

void ShowFrontAlert ()
{
	if (!g_alertHwnd || !g_alertWebview || !g_alertHtmlReady.load ())
		return;

	if (g_alertQueue.empty ())
	{
		if (IsWindowVisible (g_alertHwnd))
			StartAlertAnim (false);
		return;
	}

	const auto &a = g_alertQueue.front ();
	std::wstring fileName = ExtractFileName (a.path);
	FileMeta meta = GetFileMeta (a.path, !a.path.empty ());
	std::wstring sig = a.signature.empty () ? meta.signature : a.signature;

	MODERN_STATE_SNAPSHOT st = {};
	_modern_bridge_get_state (&st);

	std::wostringstream ss;
	ss << L"{\"type\":\"showAlert\""
		<< L",\"id\":\"" << a.appHash << L"\""
		<< L",\"name\":\"" << JsonEscape (a.name.empty () ? fileName : a.name) << L"\""
		<< L",\"fileName\":\"" << JsonEscape (fileName) << L"\""
		<< L",\"path\":\"" << JsonEscape (a.path) << L"\""
		<< L",\"signature\":\"" << JsonEscape (sig) << L"\""
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

	bool wasHidden = !IsWindowVisible (g_alertHwnd) || (g_alertAnimDir < 0);
	ComputeAlertTargetRect ();
	g_alertWebview->PostWebMessageAsJson (ss.str ().c_str ());

	if (wasHidden)
	{
		StartAlertAnim (true);
	}
	else
	{
		SetLayeredWindowAttributes (g_alertHwnd, 0, 255, LWA_ALPHA);
		SetWindowPos (g_alertHwnd, HWND_TOPMOST, g_alertTargetX, g_alertTargetY, g_alertW, g_alertH, SWP_NOACTIVATE);
	}
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
		case WM_TIMER:
			if (wparam == kAlertAnimTimerId)
			{
				StepAlertAnim ();
				return 0;
			}
			break;
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
			{
				ICoreWebView2Controller2 *ctrl2 = nullptr;
				if (SUCCEEDED (g_alertController->QueryInterface (IID_PPV_ARGS (&ctrl2))) && ctrl2)
				{
					COREWEBVIEW2_COLOR bg = {255, 18, 24, 36};
					ctrl2->put_DefaultBackgroundColor (bg);
					ctrl2->Release ();
				}
			}
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
		WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
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

			// Set WebView2 default background color to match Dark/Light theme (zero white flash!)
			{
				ICoreWebView2Controller2 *ctrl2 = nullptr;
				if (SUCCEEDED (g_controller->QueryInterface (IID_PPV_ARGS (&ctrl2))) && ctrl2)
				{
					MODERN_STATE_SNAPSHOT st = {};
					_modern_bridge_get_state (&st);
					COREWEBVIEW2_COLOR bg = st.is_dark_theme ? COREWEBVIEW2_COLOR{255, 12, 16, 23} : COREWEBVIEW2_COLOR{255, 243, 246, 251};
					ctrl2->put_DefaultBackgroundColor (bg);
					ctrl2->Release ();
				}
			}

			// Hide old Win32 controls & menu bar
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

	// Hide legacy Win32 controls IMMEDIATELY before first paint so the old UI never flashes!
	_modern_bridge_hide_legacy_controls (hwnd);
	_modern_ui_apply_titlebar_theme (hwnd);
	WriteAuditLogLine (L"START", L"simplewall v" APP_FORK_VERSION L" started");

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
		bool merged = false;
		// Collapse repeated identical attempts (same app + destination + allow/block) into a clean counter
		for (auto it = g_activity.begin (); it != g_activity.end (); ++it)
		{
			if (it->appHash == item.appHash &&
				it->remoteAddr == item.remoteAddr &&
				it->remotePort == item.remotePort &&
				it->isAllow == item.isAllow)
			{
				item.count = it->count + 1;
				g_activity.erase (it);
				g_activity.push_front (std::move (item));
				merged = true;
				break;
			}
		}
		if (!merged)
		{
			g_activity.push_front (std::move (item));
			if (g_activity.size () > kMaxActivity)
				g_activity.pop_back ();
		}
	}

	_modern_ui_notify_change ();
}

VOID _modern_ui_log_event (
	_In_ LPCWSTR level,
	_In_ LPCWSTR message
)
{
	if (!level || !message)
		return;

	WriteAuditLogLine (level, message);
}

BOOLEAN _modern_ui_paint_bg (
	_In_ HWND hwnd,
	_In_ HDC hdc
)
{
	if (!g_initialized.load () || hwnd != g_hwnd || !hdc)
		return FALSE;

	MODERN_STATE_SNAPSHOT st = {};
	_modern_bridge_get_state (&st);

	RECT rc = {};
	if (!GetClientRect (hwnd, &rc))
		return FALSE;

	HBRUSH br = CreateSolidBrush (st.is_dark_theme ? RGB (12, 16, 23) : RGB (243, 246, 251));
	if (br)
	{
		FillRect (hdc, &rc, br);
		DeleteObject (br);
		return TRUE;
	}
	return FALSE;
}

} // extern "C"
