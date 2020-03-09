#pragma once
#include <Windows.h>
#include <Psapi.h>
#pragma comment (lib, "Psapi.lib")
class SigScan
{
public:
	explicit SigScan(DWORD_PTR &PTR, DWORD_PTR Addr, const char *pattern, const char *mask)
	{
		PTR = FindPattern(Addr, pattern, mask);
	}
	void SigScanWrapper(DWORD_PTR &PTR, DWORD_PTR Addr, const char *pattern, const char *mask)
	{
		PTR = FindPattern(Addr, pattern, mask);
	}
	DWORD_PTR FindPattern(DWORD_PTR base, const char *pattern, const char *mask)
	{
		DWORD patternLength = (DWORD)strlen(mask);
		for (DWORD i = 0; i < patternLength; i++)
		{
			bool found = true;
			for (DWORD j = 0; j < patternLength; j++)
			{
				found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
			}
			if (found)
			{
				return base + i;
			}
		}
		return NULL;
	}
};