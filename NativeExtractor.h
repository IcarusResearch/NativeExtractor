#pragma once

#include <Windows.h>
#include <vector>
#include <tchar.h>
#include <string>

namespace NativeExtractor {

	//TODO get dynamic
	static std::basic_string<TCHAR> TARGET_BUILD_VERSION = _T("1.0.2824.0");

	class HashExtractor final {

	public:
		HashExtractor() noexcept;
		DWORD ExtractFromDump(LPCTSTR szDumpFile) CONST noexcept;
		DWORD ExtractLive() CONST noexcept;

	private:
		std::basic_string<TCHAR> szHashFile;
		DWORD Extract(PBYTE pData, UINT uSize, ULONG_PTR pBase) CONST noexcept;
		std::vector<ULONG_PTR> HandleNamespace(PBYTE pNamespace, ULONG_PTR pBase, ULONG_PTR pFuncRegNative) CONST noexcept;

	};

}
