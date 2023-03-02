#include "NativeExtractor.h"

#include <fstream>
#include <Psapi.h>
#include <iostream>
#include <memory>
#include <vector>
#include <iomanip>

#include "Errors.h"

// Only tested on 1.0.2802.0 & 1.0.2824 & 1.0.2845
static LPCTSTR szTableSig = _T("E8 ?? ?? ?? ?? 48 8B D8 48 8D 05 ?? ?? ?? ?? 48 89 ?? 48 8D");
static LPCTSTR szSysTableSig = _T("53 48 83 EC ?? 48 8D 1D ?? ?? ?? ?? 4C");
// Will only work on 1.0.2845
static LPCTSTR szFuncRegNativeSig = _T("E9 B4 F0 2D 02");
static UINT uTableSize = 0x2AE;

BOOL FileExists(LPCTSTR szFile) {
	DWORD dwAttributes = GetFileAttributes(szFile);
	return !((dwAttributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND)
		|| ((dwAttributes & FILE_ATTRIBUTE_DEVICE) || (dwAttributes & FILE_ATTRIBUTE_DIRECTORY)));
}

HANDLE GetProcessHandle(HWND hWnd) {
	DWORD dwProcessId;
	GetWindowThreadProcessId(hWnd, &dwProcessId);
	return OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
}

std::vector<BYTE> BytesFromSignature(LPCTSTR szSignature) {
	std::vector<BYTE> vecBytes;
	while (*szSignature) {
		if (*szSignature == ' ') {
			++szSignature;
			continue;
		}
		TCHAR szByte[3] = { szSignature[0], szSignature[1], 0 };
		vecBytes.push_back(_tcstoul(szByte, NULL, 16));
		szSignature += 2;
	}
	return vecBytes;
}

std::vector<PBYTE> SigScan(PBYTE pData, UINT uSize, LPCTSTR szSignature, BOOL bFindAll) {
	std::vector<PBYTE> vecFound;
	std::vector<BYTE> vecSignature = BytesFromSignature(szSignature);
	BOOL bFound = TRUE;
	for (PBYTE i = pData; i < pData + uSize - vecSignature.size(); ++i) {
		for (UINT j = 0; j < vecSignature.size(); ++j) {
			if (vecSignature[j] != 0 && i[j] != vecSignature[j]) {
				bFound = FALSE;
				break;
			}
		}
		if (bFound) {
			vecFound.push_back(i);
			if (!bFindAll) {
				break;
			}
		}
		bFound = TRUE;
	}
	return vecFound;
}

NativeExtractor::HashExtractor::HashExtractor() noexcept {
	szHashFile = TARGET_BUILD_VERSION + _T(".nat");
}

DWORD NativeExtractor::HashExtractor::ExtractFromDump(LPCTSTR szDumpFile) CONST noexcept {
	if (FileExists(szHashFile.c_str())) {
		return FILE_EXISTS;
	}
	if (!FileExists(szDumpFile)) {
		return FILE_NOT_FOUND_OR_INVALID;
	}
	std::ifstream is(szDumpFile, std::ios::binary | std::ios::ate);
	if (!is) {
		return FAILED_TO_OPEN_STREAM;
	}
	CONST std::streampos endPos = is.tellg();
	PBYTE pData = reinterpret_cast<PBYTE>(VirtualAlloc(NULL, endPos, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	is.seekg(std::ios::beg);
	is.read(reinterpret_cast<PCHAR>(pData), endPos);
	// pData is the full GTA dump loaded into memory
	// TODO
	return SUCCESS;
}

DWORD NativeExtractor::HashExtractor::ExtractLive() CONST noexcept {
	if (FileExists(szHashFile.c_str())) {
		return FILE_EXISTS;
	}
	HWND hWnd = FindWindow(_T("grcWindow"), nullptr);
	if (!IsWindow(hWnd)) {
		return WINDOW_NOT_FOUND;
	}
	HANDLE hProcess = GetProcessHandle(hWnd);
	if (hProcess == NULL) {
		return OPEN_PROCESS_FAILED;
	}
	HMODULE hModules[1024];
	DWORD cbNeeded;
	if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
		CloseHandle(hProcess);
		return MODULE_RETRIEVAL_FAILED;
	}
	TCHAR szProcImage[MAX_PATH];
	if (!GetProcessImageFileName(hProcess, szProcImage, sizeof(szProcImage) / sizeof(TCHAR))) {
		CloseHandle(hProcess);
		return IMAGE_FILENAME_NOT_FOUND;
	}
	PTCHAR pProcImageName = _tcsrchr(szProcImage, _T('\\')) + 1;
	DWORD dwFoundIdx = -1;
	for (UINT i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
		TCHAR szBaseName[100];
		if (GetModuleBaseName(hProcess, hModules[i], szBaseName, sizeof(szBaseName) / sizeof(TCHAR)) && !(_tcscmp(pProcImageName, szBaseName))) {
			dwFoundIdx = i;
			break;
		}
	}
	if (dwFoundIdx == -1) {
		CloseHandle(hProcess);
		return MAIN_MODULE_NOT_FOUND;
	}
	MODULEINFO moduleInfo;
	if (!GetModuleInformation(hProcess, hModules[dwFoundIdx], &moduleInfo, sizeof(MODULEINFO))) {
		CloseHandle(hProcess);
		return MODULE_INFO_RETRIEVAL_FAILED;
	}
	ULONG_PTR pModuleBase = reinterpret_cast<ULONG_PTR>(moduleInfo.lpBaseOfDll);
	std::unique_ptr<BYTE[]> pAllocBase = std::make_unique<BYTE[]>(moduleInfo.SizeOfImage);
	if (!pAllocBase) {
		CloseHandle(hProcess);
		return MEMORY_ALLOCATION_FAILED;
	}
	PBYTE pData = reinterpret_cast<PBYTE>(pAllocBase.get());
	std::cout << std::hex << "Module base: " << std::uppercase << pModuleBase << "\n";
	std::cout << std::hex << "Module size: " << std::uppercase << moduleInfo.SizeOfImage << "\n";
	if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(pModuleBase), pData, moduleInfo.SizeOfImage, NULL)) {
		CloseHandle(hProcess);
		return REMOTE_READ_FAILED;
	}
	CloseHandle(hProcess);
	// pData is the full GTA.exe module loaded into process local memory
	return Extract(pData, moduleInfo.SizeOfImage, (ULONG_PTR)pData);
}

DWORD NativeExtractor::HashExtractor::Extract(PBYTE pData, UINT uSize, ULONG_PTR pBase) CONST noexcept {
	std::vector<PBYTE> vecTableVA = SigScan(pData, uSize, szTableSig, FALSE);
	std::vector<PBYTE> vecSysTableVA = SigScan(pData, uSize, szSysTableSig, FALSE);
	std::vector<PBYTE> vecFuncRegNativeVA = SigScan(pData, uSize, szFuncRegNativeSig, FALSE);
	if (vecTableVA.empty() || vecSysTableVA.empty() || vecFuncRegNativeVA.empty()) {
		return SIGNATURE_SCAN_FAILED;
	}
	std::ofstream out(szHashFile);
	if (!out) {
		return FILE_NOT_FOUND_OR_INVALID;
	}
	PBYTE pTableStart = vecTableVA[0];
	UINT uNamespaces = 1;
	std::vector<ULONG_PTR> vecHashes = HandleNamespace(vecSysTableVA[0], pBase, (ULONG_PTR)vecSysTableVA[0] + 0x291);
	out << "[Namespace 0 (" << std::dec << vecHashes.size() << " natives)]\n";
	for (auto& hash : vecHashes) {
		out << std::hex << std::setw(16) << std::setfill('0') << std::uppercase << hash << "\n";
	}
	out << "\n";
	for (PBYTE i = pTableStart; i < pTableStart + uTableSize; ++i) {
		if (*i == 0x48 && *(i + 1) == 0x8D && *(i + 2) == 0x05) { // LEA rax, [effAdr]
			PBYTE pNamespaceRVA = i + *(PINT32)(i + 3) + 7; // VA of effective address from LEA instruction
			std::cout << "Found namespace VA " << std::hex << std::uppercase << (ULONG_PTR)pNamespaceRVA << "\n";
			vecHashes = HandleNamespace(pNamespaceRVA, pBase, (ULONG_PTR)vecFuncRegNativeVA[0]);
			if (!vecHashes.empty()) {
				out << "[Namespace " << std::dec << uNamespaces << " (" << std::dec << vecHashes.size() << " natives)]\n";
				for (auto& hash : vecHashes) {
					out << std::hex << std::setw(16) << std::setfill('0') << std::uppercase << hash << "\n";
				}
				out << "\n";
				++uNamespaces;
			}
			i += 7;
		}
	}
	return SUCCESS;
}

std::vector<ULONG_PTR> NativeExtractor::HashExtractor::HandleNamespace(PBYTE pNamespace, ULONG_PTR pBase, ULONG_PTR pFuncRegNative) CONST noexcept {
	std::vector<ULONG_PTR> vecHashes;
	/*
	.text:00007FF7FBC825BA 48 8D 15 7B BD 8E FD                                lea     rdx, sub_7FF7F956E33C
	.text:00007FF7FBC825C1 48 B9 97 67 34 1A A6 A2 A4 63                       mov     rcx, 63A4A2A61A346797h
	.text:00007FF7FBC825CB 48 83 C4 28                                         add     rsp, 28h
	.text:00007FF7FBC825CF 48 8D 64 24 F8                                      lea     rsp, [rsp-8]
	.text:00007FF7FBC825D4 48 89 2C 24                                         mov     [rsp-20h+arg_18], rbp
	.text:00007FF7FBC825D8 48 8D 2D 51 1C 21 FE                                lea     rbp, sub_7FF7F9E94230 <--- funcRegNative
	.text:00007FF7FBC825DF 48 87 2C 24                                         xchg    rbp, [rsp-20h+arg_18]
	.text:00007FF7FBC825E3 48 8D 64 24 08                                      lea     rsp, [rsp+8]
	.text:00007FF7FBC825E8 FF 64 24 F8                                         jmp     [rsp-28h+arg_18]
	*/
	while (!(*pNamespace == 0x48 && *(pNamespace + 1) == 0x8D && *(pNamespace + 2) == 0x2D
		&& ((ULONG_PTR)(pNamespace + *(PINT32)(pNamespace + 3) + 7)) == pFuncRegNative || (ULONG_PTR)pNamespace == pFuncRegNative)) {
		if (*pNamespace == 0xBA) {
			vecHashes.push_back(*(PINT32)(pNamespace + 1));
			std::cout << "\tFound Hash: " << std::setw(16) << std::setfill('0') << *(PINT32)(pNamespace + 1) << "\r";
			pNamespace += 5;
			continue;
		}
		if (*pNamespace == 0xC2 && *(pNamespace + 1) == 0x00 && *(pNamespace + 2) == 0x00) { // retn 0x00
			// no hashes bc function does nothing
			std::cout << "\tNamespace has no content\n\n";
			return vecHashes;
		}
		// skip instructions that could contain instruction opcodes as operand (jmp, lea, mov, call)
		if (*pNamespace == 0xE8) { // call [address]
			pNamespace += 5;
			continue;
		}
		if (*pNamespace == 0xE9) { // jmp [address]
			pNamespace += *(PINT32)(pNamespace + 1) + 5;
			continue;
		}
		if (*pNamespace == 0x4C && *(pNamespace + 1) == 0x8D && *(pNamespace + 2) == 0x05) { // lea r8, [ptr]
			pNamespace += 7;
			continue;
		}
		if (*pNamespace == 0x48) {
			if (*(pNamespace + 1) == 0xBA || *(pNamespace + 1) == 0xB9) { // mov rdx, [hash]; mov rcx, [hash]
				vecHashes.push_back(*(PULONG_PTR)(pNamespace + 2));
				std::cout << "\tFound Hash: " << std::setw(16) << std::setfill('0') << *(PULONG_PTR)(pNamespace + 2) << "\r";
				pNamespace += 10;
				continue;
			}
			if (*(pNamespace + 1) == 0x8D && *(pNamespace + 2) == 0x15) { // lea rdx [effAdr]
				pNamespace += 7;
				continue;
			}
		}
		++pNamespace;
	}
	std::cout << "\n\tFound " << std::dec << vecHashes.size() << " natives\n\n";
	return vecHashes;
}
