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
	> Multi-Threaded scanning support
	> Additional methos for single-scanning and loop-scanning of native windows libraries
	> Support for x86-x64 architectures and OS of Windows family from Vista+
	[RUS] ФУНКЦИОНАЛ ============================
	> Обнаруение инлайн хуков различных видов (jmp, jmp ptr, call, call ptr)
	> Обнаружение хуков таблицы экспорта с защитой против обхода
	> Обнаружение хуков таблицы импорта с защитой против обхода
	> Обнаружение хуков работающих через векторный обработчик исключений двух видов (PAGE_GUARD/PAGE_NOACCES)
	> Поддержка мультипоточности для всех видов сканнера включая коллбэки
	> Дополнительные методы для одиночного скана выборочного типа
	> Умная система анализа для всех видов хуков для предотвращения ложных срабатываний
	> Дополнительный функционал для контроля вайт-листом разрешенных хуков
	> Поддержка для х86-х64 архитектур и операционных систем семества Windows начиная с Vista и выше
*/
#pragma once
#include <Windows.h>
#include <vector>
#ifdef _USRDLL
	#define HDE_API extern "C" __declspec(dllexport)
#else
	#ifdef _WIN64
		#pragma comment(lib, "HDE64.lib")
	#else
		#pragma comment(lib, "HDE86.lib")
	#endif
	#ifdef __cplusplus
	#define HDE_API extern "C" __declspec(dllimport)
	#else
	#define HDE_API __declspec(dllimport)
	#endif
#endif
class HdeTools 
{
public:
	enum HookTypes
	{
		INLINE = 1,
		EAT = 2,
		IAT = 3,
		VEH = 4,
		ALL = 5
	};
	enum HdeError
	{
		HDE_SUCCESS = 1,
		HDE_THREAD_EXIST = 2,
		HDE_NOT_INITIATED = 3,
		HDE_INVALID_ARG = 4,
		HDE_THREAD_CANT_START = 5,
		HDE_CANT_TERMINATE_THREAD = 6,
		HDE_DLL_NOT_LOADED = 7,
		HDE_ACTIVE = 8,
		HDE_NON_ACTIVE = 9,
		HDE_RULES_EMPTY = 10
	};
	typedef struct
	{
		PVOID base;
		HookTypes hookType;
		char typeName[256];
	} HOOK_INFO, *PHOOK_INFO;
	typedef void(__stdcall *HdeCallback)(PHOOK_INFO hook);
	typedef struct
	{
		PVOID ProcedureAddr;
		std::string MappedName;
		BOOLEAN ByAddrOrName;
	} ExceptionRule, *PExceptionRule;
	// Adds exception for creating new white-listed hook
	virtual HdeError __thiscall AddExceptionRule(const std::vector<ExceptionRule> &Rules);
	// Looping scan for system libraries
	virtual HdeError __thiscall StartHDE(HookTypes scanType, HdeCallback callback, UINT32 delay, std::vector<PVOID> &vehList);
	// Single scan for own functions
	virtual HdeError __thiscall SingleHDE(HookTypes scanType, HdeCallback callback, PVOID addr, std::vector<PVOID> &vehList);
	virtual HdeError __thiscall IsActiveHDE(void);
	virtual HdeError __thiscall StopHDE(void); 
};
HDE_API HdeTools* __cdecl InitHDE();