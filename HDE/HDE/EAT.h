#pragma once
#include <windows.h>
#include <stdio.h>
#include <map>
#include <string>
#include <vector>
#pragma warning(disable : 4477)
using namespace std;
#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))
#define GetImgDirEntryRVA( pNTHdr, IDE ) (pNTHdr->OptionalHeader.DataDirectory[IDE].VirtualAddress)
#define GetImgDirEntrySize( pNTHdr, IDE ) (pNTHdr->OptionalHeader.DataDirectory[IDE].Size)
class EAT_TOOLS
{
public:
	static string ReturnSystemPath(const char *dllname)
	{
		BOOL bIsWow64 = FALSE; char syspath[256];
		typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
		LPFN_ISWOW64PROCESS fnIsWow64Process;
		fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
		if (NULL != fnIsWow64Process)
		{
			if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64)) {}
		}
		sprintf(syspath, "C:\\Windows\\%s\\%s", (bIsWow64 ? "SysWOW64" : "System32"), dllname);
		return string(syspath);
	};
protected:
	LPVOID GetSectionPtr(PSTR name, PIMAGE_NT_HEADERS pNTHeader, PBYTE imageBase)
	{
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
		for (unsigned i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
		{
			if (strncmp((char *)section->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0)
			return (LPVOID)(section->PointerToRawData + imageBase);
		}
		return 0;
	}
	PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader)	
	{
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
		for (unsigned i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
		{
			DWORD size = section->Misc.VirtualSize;
			if (0 == size) size = section->SizeOfRawData;
			if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size))) return section;
		}
		return 0;
	}
	template <class T> LPVOID GetPtrFromRVA(DWORD rva, T* pNTHeader, PBYTE imageBase) 
	{
		PIMAGE_SECTION_HEADER pSectionHdr; INT delta;
		pSectionHdr = GetEnclosingSectionHeader(rva, pNTHeader);
		if (!pSectionHdr) return 0;
		delta = (INT)(pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData);
		return (PVOID)(imageBase + rva - delta);
	}
	template <class T> LPVOID GetPtrFromVA(PVOID ptr, T* pNTHeader, PBYTE pImageBase) 
	{
		DWORD rva = PtrToLong((PBYTE)ptr - pNTHeader->OptionalHeader.ImageBase);
		return GetPtrFromRVA(rva, pNTHeader, pImageBase);
	}
public:
	void DumpExportsSection(const char *moduleName, multimap<PVOID, string> *ExportsList)
	{
		if (ExportsList == nullptr || moduleName == nullptr || strlen(moduleName) < 3) return;
		if (GetModuleHandleA(moduleName) == NULL) return;
		auto getFileSize = [](FILE *file)
		{
			long lCurPos, lEndPos;
			lCurPos = ftell(file);
			fseek(file, 0, 2);
			lEndPos = ftell(file);
			fseek(file, lCurPos, 0);
			return lEndPos;
		};
		FILE *hFile = fopen(ReturnSystemPath(moduleName).c_str(), "rb");
		if (!hFile) return;
		BYTE *fileBuf; long fileSize;
		fileSize = getFileSize(hFile);
		fileBuf = new BYTE[fileSize];
		fread(fileBuf, fileSize, 1, hFile);
		fclose(hFile); PIMAGE_NT_HEADERS pNTHeader;
		IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileBuf;
		pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY pExportDir; PIMAGE_SECTION_HEADER header; 
		INT delta; PSTR pszFilename; DWORD i; PDWORD pdwFunctions;
		PWORD pwOrdinals; DWORD *pszFuncNames; DWORD exportsStartRVA, exportsEndRVA;
		exportsStartRVA = GetImgDirEntryRVA(pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);
		exportsEndRVA = exportsStartRVA + GetImgDirEntrySize(pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);
		header = GetEnclosingSectionHeader(exportsStartRVA, pNTHeader);
		if (!header) return;
		delta = (INT)(header->VirtualAddress - header->PointerToRawData);
		PBYTE pImageBase = (PBYTE)dosHeader;
		pExportDir = (PIMAGE_EXPORT_DIRECTORY)GetPtrFromRVA(exportsStartRVA, pNTHeader, pImageBase);
		pszFilename = (PSTR)GetPtrFromRVA(pExportDir->Name, pNTHeader, pImageBase);
		pdwFunctions = (PDWORD)GetPtrFromRVA(pExportDir->AddressOfFunctions, pNTHeader, pImageBase);
		pwOrdinals = (PWORD)GetPtrFromRVA(pExportDir->AddressOfNameOrdinals, pNTHeader, pImageBase);
		pszFuncNames = (DWORD *)GetPtrFromRVA(pExportDir->AddressOfNames, pNTHeader, pImageBase);
		for (i = 0; i < pExportDir->NumberOfFunctions; i++, pdwFunctions++)
		{
			DWORD entryPointRVA = *pdwFunctions;
			if (entryPointRVA == 0) continue;               
			for (unsigned j = 0; j < pExportDir->NumberOfNames; j++)
			{
				if (pwOrdinals[j] == i)
				{
					char fname[55]; sprintf(fname, "%s", GetPtrFromRVA(pszFuncNames[j], pNTHeader, pImageBase));
					PVOID funcAddr = (PVOID)((DWORD_PTR)GetModuleHandleA(moduleName) + entryPointRVA);
					ExportsList->insert(ExportsList->begin(), pair<PVOID, string>(funcAddr, fname));
				}
			}
		}
		delete[] fileBuf;
	}
};