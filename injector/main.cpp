#include <tchar.h>
#include <iostream>
#include <string>
#include <cstring>
#include <Windows.h>
#include <easyhook.h>

#pragma comment(lib, "EasyHook32.lib")

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD processId;
	std::wcout << "Enter the target process Id: ";
	std::cin >> processId;

	WCHAR* dllToInject = new WCHAR[512]; //  = L"C:\\Users\\madrat\\Desktop\\hooks.dll"
	std::wcout << "Enter path to dll: ";
	std::wcin >> dllToInject;
	wprintf(L"Attempting to inject: %s\n\n", dllToInject);

	// Inject dllToInject into the target process Id, passing 
	// freqOffset as the pass through data.
	NTSTATUS nt = RhInjectLibrary(
		processId,   // The process to inject into
		0,           // ThreadId to wake up upon injection
		EASYHOOK_INJECT_DEFAULT,
		dllToInject, // 32-bit
		NULL,		 // 64-bit not provided
		NULL, // data to send to injected DLL entry point
		0// size of data to send
	);

	if (nt != 0)
	{
		printf("RhInjectLibrary failed with error code = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		std::wcout << err << "\n";
	}
	else
	{
		std::wcout << L"Library injected successfully.\n";
	}

	return 0;
}