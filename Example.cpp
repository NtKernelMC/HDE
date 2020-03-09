#include <windows.h>
#include <stdio.h>
#include <vector>
#include <memory>
#include "HDE.h"
#pragma warning(disable : 4477)
#pragma warning(disable : 4313)
using namespace std;
void __stdcall CallbackHDE(HdeTools::PHOOK_INFO hook) 
{
#ifdef _WIN64
	printf("\nDetected %s hook at: 0x%llX\n", hook->typeName, hook->base);
#else
	printf("\nDetected %s hook at: 0x%X\n", hook->typeName, hook->base);
#endif
}
int main() 
{
	vector<PVOID> addressator; addressator.clear(); // if you don`t need to search VEH hooks, u can leave this empty
	unique_ptr<HdeTools> hde(InitHDE());
	if (hde != nullptr)
	{
		printf("Current Thread ID: 0x%X\n", GetCurrentThreadId());
		HdeTools::HdeError hdRes = hde->StartHDE(HdeTools::HookTypes::ALL, CallbackHDE, 1000, addressator);
		if (hdRes == HdeTools::HDE_SUCCESS) printf("HDE successfully started.\n");
		else printf("Error: %d\n", hdRes);
	}
	/*
	// Example of Adding rules for exceptions (So your own hook will be not triggered by scanner)
	HdeTools::ExceptionRule NeueRule; NeueRule.ByAddrOrName = false;
	NeueRule.ProcedureAddr = YourAddress;
	vector<HdeTools::ExceptionRule> MyRules;
	MyRules.push_back(NeueRule);
	hde->AddExceptionRule(MyRules);*/
	system("pause");
	return 1;
}