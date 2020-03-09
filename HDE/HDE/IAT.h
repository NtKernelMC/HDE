#pragma once
#include <windows.h>
#include <stdio.h>
#include <map>
#include <tuple>
#include <string>
#include <vector>
#pragma warning(disable : 4477)
#pragma warning(disable : 4090)
using namespace std;
class IAT_TOOLS
{
public:
	void DumpImportsSection(const char *moduleName, multimap<PVOID, tuple<string, string>> *ImportsList)
	{
		if (ImportsList == nullptr || moduleName == nullptr || strlen(moduleName) < 3) return;
		HMODULE module = GetModuleHandleA(moduleName);
		PIMAGE_DOS_HEADER img_dos_headers = (PIMAGE_DOS_HEADER)module;
		PIMAGE_NT_HEADERS img_nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)img_dos_headers + img_dos_headers->e_lfanew);
		PIMAGE_IMPORT_DESCRIPTOR img_import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)
		img_dos_headers + img_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		if (img_dos_headers->e_magic != IMAGE_DOS_SIGNATURE) return;
		for (IMAGE_IMPORT_DESCRIPTOR *iid = img_import_desc; iid->Name != 0; iid++)
		{
			for (int func_idx = 0; *(func_idx + (void**)(iid->FirstThunk + (size_t)module)) != nullptr; func_idx++) 
			{
				char* mod_func_name = (char*)(*(func_idx + (size_t*)(iid->OriginalFirstThunk + 
				(size_t)module)) + (size_t)module + 2);
				const intptr_t nmod_func_name = (intptr_t)mod_func_name;
				if (nmod_func_name >= 0)
				{
					char DllName[256]; memset(DllName, 0, sizeof(DllName));
					strcpy(DllName, (char*)(iid->Name + (size_t)module));
					for (DWORD x = 0; x < strlen(DllName); x++) DllName[x] = tolower(DllName[x]);
					ImportsList->insert(ImportsList->begin(), 
					pair<PVOID, tuple<string, string>>(*(func_idx + (void**)(iid->FirstThunk + (size_t)module)),
					make_tuple(mod_func_name, DllName)));
				}
			}
		}
	}
};