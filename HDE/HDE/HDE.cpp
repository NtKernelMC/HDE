/*
	HDE - Hooks Detection Engine
	Task: Prevent WIN API & NT API hooks
	Copyright: NtKernelMC
	Date: 29.05.2019

	[ENG] FEATURES =========================
	> Detection of inline hooks for many types (jmp, jmp ptr, call, call ptr)
	> Detection of export table hooks with protection to bypassing
	> Detection of import table hooks with protection to bypassing
	> Detection of vectored exception hooks for two types (PAGE_GUARD/PAGE_NOACCES)
	> Smart analysation system for all hooks types to prevent false-positives
	> Additional methods for controlling white-listed hooks list
	> Support for x86-x64 architectures and OS of Windows family from Vista+
	[RUS] ФУНКЦИОНАЛ ============================
	> Обнаружeние инлайн хуков различных видов (jmp, jmp ptr, call, call ptr)
	> Обнаружение хуков таблицы экспорта с защитой против обхода
	> Обнаружение хуков таблицы импорта с защитой против обхода
	> Обнаружение хуков работающих через векторный обработчик исключений двух видов (PAGE_GUARD/PAGE_NOACCES)
	> Умная система анализа для всех видов хуков для предотвращения ложных срабатываний
	> Дополнительный функционал для контроля вайт-листом разрешенных хуков
	> Поддержка для х86-х64 архитектур и операционных систем семейства Windows начиная с Vista и выше
*/
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#pragma warning(disable : 4244)
#pragma warning(disable : 4018)
#include <Windows.h>
#include <thread>
#include <vector>
#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <tuple>
#include <direct.h>
#include "EAT.h"
#include "HDE.h"
#include "IAT.h"
HMODULE thisDLL = nullptr;
using namespace std;
HANDLE hThread = nullptr, sThread = nullptr;
HdeTools *LastPointer = nullptr;
string GetNameOfModuledAddressSpace(PVOID addr, vector<string> mdls);
FARPROC __stdcall GetProcedureAddress(HMODULE hModule, const char* pszProcName);
char* strdel(char *s, size_t offset, size_t count)
{
	size_t len = strlen(s);
	if (offset > len) return s;
	if ((offset + count) > len) count = len - offset;
	strcpy(s + offset, s + offset + count);
	return s;
}
enum INSTRUCTION_TYPE
{
	JMP_ABS = 0,
	JMP_PTR = 1,
	CALL_ABS = 2,
	CALL_PTR = 3,
	PTR_64 = 4,
	UNKNOWN = 5
};
typedef struct
{
	PVOID base;
	SIZE_T length;
	BYTE opcode[3];
	BYTE opcodeLen;
	INSTRUCTION_TYPE type;
} PROLOGUE_INSTRUCTION, *PPROLOGUE_INSTRUCTION;
string GetMdlNameFromHmodule(HMODULE MDL)
{
	CHAR szFileName[MAX_PATH + 1];
	GetModuleFileNameA(MDL, szFileName, MAX_PATH + 1);
	char fname[256]; char *ipt = strrchr(szFileName, '\\');
	memset(fname, 0, sizeof(fname));
	strdel(szFileName, 0, (ipt - szFileName + 1));
	strncpy(fname, szFileName, strlen(szFileName));
	for (DWORD x = 0; x < strlen(fname); x++) fname[x] = tolower(fname[x]);
	return string(fname);
};
class SCAN_DATA sealed : public HdeTools, public IAT_TOOLS, public EAT_TOOLS
{
public:
	multimap<PVOID, string> ExportsList; vector<string> modules;
	UINT32 Delay; HdeCallback Callback; vector<PVOID> vehList;
	multimap<PVOID, tuple<string, string>> ImportsList;
	vector<PVOID> detectedInlineHooks; HookTypes typeOfScan;
	vector<PVOID> detectedEatHooks; vector<PVOID> detectedIatHooks;
	vector<PVOID> detectedVehHooks; PVOID LastVEH; vector<ExceptionRule> Rule;
	map<HMODULE, string> UnloadMdls; PVOID scanAddr;
	void SetFields(HookTypes scanType, HdeCallback callback, UINT32 delay, vector<PVOID> *vehs, PVOID addr = nullptr)
	{
		ClearFields();
		for (const auto& vehIter : *vehs)
		{
			this->vehList.push_back(vehIter);
		}
		// I don`t recommend to check more than 3-4 libraries, because it can cause fall of detection speed 
		modules.push_back("ntdll.dll");
		modules.push_back("kernelbase.dll");
		modules.push_back("kernel32.dll");
		modules.push_back("psapi.dll");
		for (const auto& exIter : modules)
		{
			DumpExportsSection(exIter.c_str(), &ExportsList);
		}
		this->typeOfScan = scanType;
		this->Callback = callback;
		this->Delay = delay;
		if (delay == NULL) this->scanAddr = addr;
	}
	void ClearFields()
	{
		this->Delay = 0x0; this->Callback = 0x0;
		ExportsList.clear(); ImportsList.clear();
		modules.clear(); vehList.clear();
		detectedInlineHooks.clear();
		detectedEatHooks.clear();
		detectedIatHooks.clear();
		detectedVehHooks.clear();
		Rule.clear();
	}
};
SCAN_DATA OldScanData;
vector<string> GenerateModuleNamesList()
{
	HMODULE hMods[1024]; DWORD cbNeeded; vector<string> MdlList;
	typedef BOOL(__stdcall *PtrEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
	PtrEnumProcessModules EnumProcModules =
	(PtrEnumProcessModules)GetProcAddress(LoadLibraryA("psapi.dll"), "EnumProcessModules");
	EnumProcModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded);
	for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
	{
		MdlList.push_back(GetMdlNameFromHmodule(hMods[i]));
	}
	return MdlList;
}
bool __stdcall IsPrologueWhole(const DWORD_PTR base, SCAN_DATA *pscan)
{
	auto hGetTargetModule = [&, base]() -> tuple<PVOID, string>
	{
		HMODULE hMods[1024]; DWORD cbNeeded;
		typedef BOOL(__stdcall *PtrEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
		PtrEnumProcessModules EnumProcModules = (PtrEnumProcessModules)GetProcAddress(LoadLibraryA("psapi.dll"), "EnumProcessModules");
		EnumProcModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded);
		typedef BOOL(__stdcall *GetMdlInfoP)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
		GetMdlInfoP GetMdlInfo = (GetMdlInfoP)GetProcAddress(LoadLibraryA("psapi.dll"), "GetModuleInformation");
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			MODULEINFO modinfo; GetMdlInfo(GetCurrentProcess(), hMods[i], &modinfo, sizeof(modinfo));
			if (base >= (DWORD_PTR)modinfo.lpBaseOfDll && base <= ((DWORD_PTR)modinfo.lpBaseOfDll + modinfo.SizeOfImage))
			{
				string moduleName = GetNameOfModuledAddressSpace((PVOID)base, GenerateModuleNamesList());
				string mdlName = "tmp_" + moduleName;
				char mdlPath[256]; memset(mdlPath, 0, sizeof(mdlPath)); _getcwd(mdlPath, 256);
				strcat(mdlPath, "\\"); strcat(mdlPath, mdlName.c_str());
				CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA(hMods[i], szFileName, MAX_PATH + 1);
				CopyFileA(szFileName, mdlPath, FALSE); 
				SetFileAttributesA(mdlPath, FILE_ATTRIBUTE_SYSTEM + FILE_ATTRIBUTE_HIDDEN);
				return make_tuple(modinfo.lpBaseOfDll, mdlName);
			}
		}
		return make_tuple((PVOID)0x0, "");
	};
	auto GetInstruction = [](DWORD_PTR base_addr, PROLOGUE_INSTRUCTION *Instruction)
	{
		Instruction->base = reinterpret_cast<PVOID>(base_addr);
		Instruction->type = UNKNOWN;
		Instruction->opcode[0] = *(BYTE*)base_addr;
		Instruction->opcode[1] = *(BYTE*)(base_addr + 0x1);
		Instruction->opcode[2] = *(BYTE*)(base_addr + 0x2);
		Instruction->opcodeLen = 3;
		Instruction->length = 7;
		if (*(BYTE*)base_addr == 0x48)
		{
			if (*(BYTE*)(base_addr + 0x1) == 0xFF && *(BYTE*)(base_addr + 0x2) == 0x25)
			{
				Instruction->type = PTR_64;
				Instruction->opcode[0] = 0x48;
				Instruction->opcode[1] = 0xFF;
				Instruction->opcode[2] = 0x25;
				Instruction->opcodeLen = 3;
				Instruction->length = 7;
			}
		}
		else if (*(BYTE*)base_addr == 0xFF)
		{
			if (*(BYTE*)(base_addr + 0x1) == 0x25)
			{
				Instruction->type = JMP_PTR;
				Instruction->opcode[0] = 0xFF;
				Instruction->opcode[1] = 0x25;
				Instruction->opcodeLen = 2;
				Instruction->length = 6;
			}
			else if (*(BYTE*)(base_addr + 0x1) == 0x15)
			{
				Instruction->type = CALL_PTR;
				Instruction->opcode[0] = 0xFF;
				Instruction->opcode[1] = 0x15;
				Instruction->opcodeLen = 2;
				Instruction->length = 6;
			}
		}
		else if(*(BYTE*)base_addr == 0xE9)
		{
			Instruction->type = JMP_ABS;
			Instruction->opcode[0] = 0xE9;
			Instruction->opcodeLen = 1;
			Instruction->length = 5;
		}
		else if (*(BYTE*)base_addr == 0xE8)
		{
			Instruction->type = CALL_ABS;
			Instruction->opcode[0] = 0xE8;
			Instruction->opcodeLen = 1;
			Instruction->length = 5;
		}
		return Instruction;
	};
	auto SameDeltaDestination = [&, pscan](PROLOGUE_INSTRUCTION *mapped_ins, PROLOGUE_INSTRUCTION *mem_ins) -> bool
	{
		if (mapped_ins->type == UNKNOWN && mem_ins->type == UNKNOWN)
		{
			if (*(BYTE*)mapped_ins->base == *(BYTE*)mem_ins->base) return true;
			else
			{
				if (GetModuleHandleA("user32.dll") != NULL) // fix of false-positives
				{
					if (mem_ins->base == GetProcedureAddress(GetModuleHandleA("user32.dll"), "gSharedInfo")) return true;
				}
			}
		}
		auto ReverseDelta = [&, mem_ins]
		(DWORD_PTR CurrentAddress, DWORD Delta, size_t InstructionLength, bool bigger = false) -> DWORD_PTR
		{
			if (bigger) return ((CurrentAddress + (Delta + InstructionLength)) - 0xFFFFFFFE);
			return CurrentAddress + (Delta + InstructionLength);
		};
#ifdef _WIN64
		constexpr bool X86 = false;
#else
		constexpr bool X86 = true;
#endif
		auto GetDeltaOffset = [](PROLOGUE_INSTRUCTION *ins) -> DWORD
		{
			if (ins->type == JMP_ABS || ins->type == CALL_ABS) return 0x1;
			else if (ins->type == JMP_PTR || ins->type == CALL_PTR) return 0x2;
			if (ins->type == PTR_64) return 0x3;
			return 0x0;
		};
		auto IsGreaterThan = [](LPCVOID Src, LPCVOID Dest, SIZE_T Delta) -> BOOLEAN
		{
			return (Src < Dest ? (SIZE_T)Dest - (SIZE_T)Src : (SIZE_T)Src - (SIZE_T)Dest) > Delta;
		};
		auto IsGreaterThan2Gb = [&, IsGreaterThan](LPCVOID Src, LPCVOID Dest) -> BOOLEAN
		{
			return IsGreaterThan(Src, Dest, 2 * 1024 * 1048576UL);
		};
		DWORD Delta; memcpy(&Delta, (PVOID)((DWORD_PTR)mapped_ins->base + GetDeltaOffset(mapped_ins)), 4);
		DWORD_PTR DestinyAddr = 0x0; if (GetDeltaOffset(mapped_ins) == 0x2 && X86) DestinyAddr = Delta;
		else DestinyAddr = ReverseDelta((DWORD_PTR)mapped_ins->base, Delta, mapped_ins->length);
		if (IsGreaterThan2Gb(mapped_ins->base, (PVOID)DestinyAddr) && GetDeltaOffset(mapped_ins) != 0x2)
		DestinyAddr = ReverseDelta((DWORD_PTR)mapped_ins->base, Delta, mapped_ins->length, true);
		string ModuleName = GetNameOfModuledAddressSpace((PVOID)DestinyAddr, GenerateModuleNamesList());
		memcpy(&Delta, (PVOID)((DWORD_PTR)mem_ins->base + GetDeltaOffset(mem_ins)), 4);
		if (GetDeltaOffset(mem_ins) == 0x2 && X86) DestinyAddr = Delta;
		else DestinyAddr = ReverseDelta((DWORD_PTR)mem_ins->base, Delta, mem_ins->length);
		if (IsGreaterThan2Gb(mem_ins->base, (PVOID)DestinyAddr) && GetDeltaOffset(mem_ins) != 0x2)
		DestinyAddr = ReverseDelta((DWORD_PTR)mem_ins->base, Delta, mem_ins->length, true);
		string SecondName = GetNameOfModuledAddressSpace((PVOID)DestinyAddr, GenerateModuleNamesList());
		char mdfModuleName[256]; memset(mdfModuleName, 0, sizeof(mdfModuleName)); 
		strcpy(mdfModuleName, ModuleName.c_str()); strdel(mdfModuleName, 0, 4);
		if (!strcmp(mdfModuleName, SecondName.c_str())) return true;
		return false;
	};
	tuple<PVOID, string> currentModule = hGetTargetModule();
	HMODULE dllBase = LoadLibraryExA(get<1>(currentModule).c_str(), 0, DONT_RESOLVE_DLL_REFERENCES);
	if (dllBase)
	{
		pscan->UnloadMdls.insert(pscan->UnloadMdls.begin(), pair<HMODULE, string>(dllBase, get<1>(currentModule)));
		DWORD_PTR getRVA = (base - (DWORD_PTR)get<0>(currentModule));
		DWORD_PTR mappedPrologue = ((DWORD_PTR)dllBase + getRVA);
		PROLOGUE_INSTRUCTION mappedInstruction; GetInstruction(mappedPrologue, &mappedInstruction);
		PROLOGUE_INSTRUCTION memoryInstruction; GetInstruction(base, &memoryInstruction);
		if (SameDeltaDestination(&mappedInstruction, &memoryInstruction)) return true;
	}
	return false;
}
string GetNameOfModuledAddressSpace(PVOID addr, vector<string> mdls)
{
	typedef BOOL(__stdcall *GetMdlInfoP)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
	GetMdlInfoP GetMdlInfo = (GetMdlInfoP)GetProcAddress(LoadLibraryA("psapi.dll"), "GetModuleInformation");
	for (const auto &it : mdls)
	{
		MODULEINFO modinfo; GetMdlInfo(GetCurrentProcess(), GetModuleHandleA(it.c_str()), &modinfo, sizeof(modinfo));
		if ((DWORD_PTR)addr >= (DWORD_PTR)modinfo.lpBaseOfDll 
		&& (DWORD_PTR)addr <= ((DWORD_PTR)modinfo.lpBaseOfDll + modinfo.SizeOfImage))
		{
			return GetMdlNameFromHmodule((HMODULE)modinfo.lpBaseOfDll);
		}
	}
	return string("NONE");
}
FARPROC __stdcall GetProcedureAddress(HMODULE hModule, const char* pszProcName)
{
	IMAGE_DOS_HEADER* pdhDosHeader = (IMAGE_DOS_HEADER*)hModule;
	if (pdhDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;
	IMAGE_NT_HEADERS* pndNTHeader = (IMAGE_NT_HEADERS*)(pdhDosHeader->e_lfanew + (DWORD_PTR)hModule);
	if (pndNTHeader->Signature != IMAGE_NT_SIGNATURE) return 0;
	IMAGE_EXPORT_DIRECTORY* iedExports = (IMAGE_EXPORT_DIRECTORY*)
	(pndNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (DWORD_PTR)hModule);
	DWORD* pNames = (DWORD*)(iedExports->AddressOfNames + (DWORD_PTR)hModule);
	short wOrdinalIndex = -1;
	for (int i = 0; i < iedExports->NumberOfFunctions; i++)
	{
		char* pszFunctionName = (char *)(pNames[i] + (DWORD_PTR)hModule);
		if (lstrcmpiA(pszFunctionName, pszProcName) == 0)
		{
			wOrdinalIndex = i;
			break;
		}
	}
	if (wOrdinalIndex == -1) return 0;
	short* pOrdinals = (short*)(iedExports->AddressOfNameOrdinals + (DWORD_PTR)hModule);
	DWORD* pAddresses = (DWORD*)(iedExports->AddressOfFunctions + (DWORD_PTR)hModule);
	short wAddressIndex = pOrdinals[wOrdinalIndex];
	return (FARPROC)(pAddresses[wAddressIndex] + (DWORD_PTR)hModule);
}
void __stdcall ScanForHooks(SCAN_DATA *scanData)
{
	auto GetHookTypeName = [](HdeTools::HookTypes type) -> string
	{
		switch (type)
		{
		case HdeTools::HookTypes::INLINE:
			return string("INLINE");
		case HdeTools::HookTypes::EAT:
			return string("EAT");
		case HdeTools::HookTypes::IAT:
			return string("IAT");
		case HdeTools::HookTypes::VEH:
			return string("VEH");
		}
	};
	auto Contains = [](const vector<PVOID> &Vec, const PVOID Element) -> const bool
	{
		if (std::find(Vec.begin(), Vec.end(), Element) != Vec.end()) return true;
		return false;
	};
	auto IsTargetHaveRule = [&, scanData](PVOID currAddr) -> bool
	{
		if (!scanData->Rule.empty())
		{
			for (const auto &eRule : scanData->Rule)
			{
				if (!eRule.ByAddrOrName)
				{
					if (currAddr == eRule.ProcedureAddr) return true;
				}
				else
				{
					char MappedName[256]; memset(MappedName, 0, sizeof(MappedName));
					typedef DWORD(__stdcall *LPFN_GetMappedFileNameA)
					(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
					HMODULE hPsapi = LoadLibraryA("psapi.dll");
					LPFN_GetMappedFileNameA lpGetMappedFileNameA = (LPFN_GetMappedFileNameA)
					GetProcAddress(hPsapi, "GetMappedFileNameA");
					lpGetMappedFileNameA(GetCurrentProcess(), currAddr, MappedName, sizeof(MappedName));
					if (!strcmp(MappedName, eRule.MappedName.c_str())) return true;
				}
			}
		}
		return false;
	};
	auto SendDetectionReport = [&, scanData, GetHookTypeName, Contains, IsTargetHaveRule]
	(PVOID base, HdeTools::HookTypes type) 
	{
		for (const auto& it : scanData->ExportsList)
		{
			if (type == HdeTools::HookTypes::VEH) base = scanData->LastVEH;
			if (IsTargetHaveRule(base)) return;
			string mdlName = GetNameOfModuledAddressSpace(it.first, GenerateModuleNamesList());
			HdeTools::HOOK_INFO hook; hook.base = base; hook.hookType = type;
			memset(hook.typeName, 0, sizeof(hook.typeName));
			strcpy(hook.typeName, GetHookTypeName(type).c_str());
			if (!Contains(scanData->detectedInlineHooks, hook.base) && type == HdeTools::HookTypes::INLINE)
			{
				scanData->detectedInlineHooks.push_back(hook.base); scanData->Callback(&hook);
			}
			else if (!Contains(scanData->detectedEatHooks, hook.base) && type == HdeTools::HookTypes::EAT)
			{
				scanData->detectedEatHooks.push_back(hook.base); scanData->Callback(&hook);
			}
			else if (!Contains(scanData->detectedIatHooks, hook.base) && type == HdeTools::HookTypes::IAT)
			{
				scanData->detectedIatHooks.push_back(hook.base); scanData->Callback(&hook);
			}
			else if (!Contains(scanData->detectedVehHooks, hook.base) && type == HdeTools::HookTypes::VEH)
			{
				scanData->detectedVehHooks.push_back(hook.base); scanData->Callback(&hook);
			}
		}
	};
	while (true)
	{
		for (const auto& it : scanData->ExportsList)
		{
			auto FindedHook = [&, it](const DWORD_PTR scan, SCAN_DATA *pscan, HdeTools::HookTypes type) -> bool
			{
				if (scan != NULL && pscan != nullptr)
				{
					switch (type)
					{
						case HdeTools::HookTypes::INLINE:
						{
							if (IsPrologueWhole(scan, pscan)) return true;
							break;
						}
						case HdeTools::HookTypes::EAT:
						{
							auto IsExportMissed = [&, it, pscan]() -> bool
							{
								string mdlName = GetNameOfModuledAddressSpace(it.first, GenerateModuleNamesList());
								DWORD_PTR exported = (DWORD_PTR)
								GetProcedureAddress(GetModuleHandleA(mdlName.c_str()), const_cast<char*>(it.second.c_str()));
								if ((DWORD_PTR)it.first == exported) return false;
								if (GetModuleHandleA("user32.dll") != NULL) // fix of false positives
								{
									if (it.second.find("DefDlgProcA") != string::npos) return false;
									else if (it.second.find("DefDlgProcW") != string::npos) return false;
									else if (it.second.find("DefWindowProcA") != string::npos) return false;
									else if (it.second.find("DefWindowProcW") != string::npos) return false;
								}
								return true;
							}; 
							if (IsExportMissed()) return true;
							break;
						}
						case HdeTools::HookTypes::IAT:
						{
							pscan->ImportsList.clear();
							pscan->DumpImportsSection(GetMdlNameFromHmodule(0).c_str(), &pscan->ImportsList);
							auto IsImportValid = [&, pscan]() -> bool
							{
								for (const auto& imp : pscan->ImportsList)
								{
									if (!strcmp(get<0>(imp.second).c_str(), it.second.c_str()))
									{
										string itName = GetNameOfModuledAddressSpace(it.first, GenerateModuleNamesList());
										if (imp.first != it.first && get<1>(imp.second).find(itName) != string::npos)
										{
											string impName = GetNameOfModuledAddressSpace(imp.first, GenerateModuleNamesList());
											if (impName.find("kernelbase.dll") != string::npos ||
											impName.find("ntdll.dll") != string::npos) return true;
											return false;
										}
									}
								}
								return true;
							};
							if (!IsImportValid()) return true;
							break;
						}
						case HdeTools::HookTypes::VEH:
						{
							if (!pscan->vehList.empty())
							{
								for (const auto& veh : pscan->vehList)
								{
									MEMORY_BASIC_INFORMATION mme = { 0 };
									VirtualQuery(veh, &mme, sizeof(MEMORY_BASIC_INFORMATION));
									if (mme.Protect & (PAGE_GUARD | PAGE_NOACCESS))
									{
										pscan->LastVEH = veh;
										return true;
									}
								}
							}
							break;
						}
					}
				}
				return false;
			};
			PVOID exportPtr = it.first; 
			if (scanData->Delay == NULL) exportPtr = scanData->scanAddr;
			if (scanData->typeOfScan == HdeTools::HookTypes::INLINE || scanData->typeOfScan == HdeTools::HookTypes::ALL)
			{
				if (FindedHook((DWORD_PTR)exportPtr, scanData, HdeTools::HookTypes::INLINE))
				SendDetectionReport(exportPtr, HdeTools::HookTypes::INLINE);
			}
			if (scanData->typeOfScan == HdeTools::HookTypes::EAT || scanData->typeOfScan == HdeTools::HookTypes::ALL)
			{
				if (FindedHook((DWORD_PTR)exportPtr, scanData, HdeTools::HookTypes::EAT))
				SendDetectionReport(exportPtr, HdeTools::HookTypes::EAT);
			}
			if (scanData->typeOfScan == HdeTools::HookTypes::IAT || scanData->typeOfScan == HdeTools::HookTypes::ALL)
			{
				if (FindedHook((DWORD_PTR)exportPtr, scanData, HdeTools::HookTypes::IAT))
				SendDetectionReport(exportPtr, HdeTools::HookTypes::IAT);
			}
			if (scanData->typeOfScan == HdeTools::HookTypes::VEH || scanData->typeOfScan == HdeTools::HookTypes::ALL)
			{
				if (FindedHook((DWORD_PTR)exportPtr, scanData, HdeTools::HookTypes::VEH))
				SendDetectionReport(exportPtr, HdeTools::HookTypes::VEH);
			}
			if (scanData->Delay == NULL)
			{
				sThread = NULL;
				return;
			}
		}
		Sleep(scanData->Delay);
	}
}
SCAN_DATA* ObtainScanData(SCAN_DATA* scanPtr)
{
	static SCAN_DATA* ScanPointer = nullptr;
	if (scanPtr != nullptr) ScanPointer = scanPtr;
	return ScanPointer;
}
HdeTools::HdeError __thiscall HdeTools::AddExceptionRule(const vector<ExceptionRule> &Rules)
{
	if (Rules.empty()) return HDE_RULES_EMPTY;
	if (!hThread) return HDE_NOT_INITIATED;
	SCAN_DATA* scanPtr = ObtainScanData(nullptr);
	if (scanPtr == nullptr) return HDE_INVALID_ARG;
	for (const auto& scanIter : Rules)
	{
		scanPtr->Rule.push_back(scanIter);
	}
	return HDE_SUCCESS;
}
HdeTools::HdeError __thiscall HdeTools::StartHDE(HookTypes scanType, HdeCallback callback, UINT32 delay, vector<PVOID> &vehList) 
{
	if (hThread) return HDE_THREAD_EXIST;
	if (callback == nullptr || (delay == NULL || delay < NULL) || (scanType <= 0 || scanType > 7)) return HDE_INVALID_ARG;
	static SCAN_DATA scanData; ObtainScanData(&scanData); scanData.SetFields(scanType, callback, delay, &vehList);
	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ScanForHooks, &scanData, 0, 0);
	if (!hThread) return HDE_THREAD_CANT_START;
	return HDE_SUCCESS;
}
HdeTools::HdeError __thiscall HdeTools::SingleHDE(HookTypes scanType, HdeCallback callback, PVOID addr, vector<PVOID> &vehList)
{
	if (sThread) return HDE_THREAD_EXIST;
	if (callback == nullptr || addr == nullptr || (scanType <= 0 || scanType > 7)) return HDE_INVALID_ARG;
	static SCAN_DATA scanData; scanData.SetFields(scanType, callback, 0, &vehList, addr);
	sThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ScanForHooks, &scanData, 0, 0);
	if (!sThread) return HDE_THREAD_CANT_START;
	return HDE_SUCCESS;
}
HdeTools::HdeError __thiscall HdeTools::IsActiveHDE(void)
{
	if (!hThread) return HDE_NON_ACTIVE;
	return HDE_ACTIVE;
}
HdeTools::HdeError __thiscall HdeTools::StopHDE(void)
{
	if (!hThread) return HDE_NOT_INITIATED;
	BOOL sts = TerminateThread(hThread, 0);
	if (sts) hThread = NULL;
	else return HDE_CANT_TERMINATE_THREAD;
	for (const auto& it : ObtainScanData(nullptr)->UnloadMdls)
	{
		BOOL ist = FreeLibrary(it.first);
		if (ist) DeleteFileA(it.second.c_str());
	}
	return HDE_SUCCESS;
}
HdeTools* __cdecl InitHDE()
{
	LastPointer = new HdeTools();
	return LastPointer;
}
int __stdcall DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) thisDLL = hModule;
	else if (ul_reason_for_call == DLL_PROCESS_DETACH) ObtainScanData(nullptr)->StopHDE();
	return 1;
}