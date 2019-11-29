// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <iostream>
#include "easyhook.h"

#pragma comment(lib, "EasyHook32.lib")

BOOL IsDebuggerPresentHook()
{
	std::cout << "[HOOK] IsDebuggerPresentHook called!" << std::endl;
	std::cout << "[HOOK] Faking its result to: False!" << std::endl;
	return FALSE;
}

BOOL CheckRemoteDebuggerPresentHook(
	HANDLE hProcess,
	PBOOL  pbDebuggerPresent
)
{
	std::cout << "[HOOK] hook triggered at CheckRemoteDebuggerPresent" << std::endl;
	std::cout << "[HOOK] default call result to CheckRemoteDebuggerPresent: " << CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent) << std::endl;
	std::cout << "[HOOK] Faked result: False!" << std::endl;

	return FALSE;
}

__kernel_entry NTSTATUS __stdcall NtCreateFileHook(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PLARGE_INTEGER     AllocationSize,
	IN ULONG              FileAttributes,
	IN ULONG              ShareAccess,
	IN ULONG              CreateDisposition,
	IN ULONG              CreateOptions,
	IN PVOID              EaBuffer,
	IN ULONG              EaLength
)
{
	wprintf(L"[HOOK] Generated File name: %s\n", ObjectAttributes->ObjectName->Buffer);
	
	std::cout << "[HOOK] Changing default CreateDisposition to: FILE_OPEN_IF" << std::endl;
	CreateDisposition = FILE_OPEN_IF;

	__kernel_entry NTSTATUS __stdcall result = NtCreateFile(
		OUT FileHandle,
		IN DesiredAccess,
		IN ObjectAttributes,
		OUT IoStatusBlock,
		OUT AllocationSize,
		OUT FileAttributes,
		OUT ShareAccess,
		OUT CreateDisposition,
		OUT CreateOptions,
		OUT EaBuffer,
		OUT EaLength
		);
	std::cout << "[HOOK] NtCreateFile result: " << result << std::endl;
	return result;
}

extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	// IsDebuggerPresent
	HOOK_TRACE_INFO hHookIsDebuggerPresent = { NULL };
	std::cout << "[HOOK] Hook dll loaded!" << std::endl;
	std::cout << "[HOOK] Installing hook at: IsDebuggerPresent" << std::endl;

	HMODULE kernel32 = GetModuleHandle(TEXT("kernel32"));
	std::cout << "[HOOK] Got module handle of 'kernel32': " << kernel32 << std::endl;

	FARPROC func_IsDebuggerPresent = GetProcAddress(kernel32, "IsDebuggerPresent");
	std::cout << "[HOOK] Got address of 'IsDebuggerPresent': " << func_IsDebuggerPresent << std::endl;

	NTSTATUS result = LhInstallHook(
		func_IsDebuggerPresent,
		IsDebuggerPresentHook,
		NULL,
		&hHookIsDebuggerPresent);
	if (FAILED(result))
	{
		std::cout << "[HOOK] Failed to install hook at: IsDebuggerPresent" << std::endl;
		return;
	}
	std::cout << "[HOOK] Hook at IsDebuggerPresent installed successfully!" << std::endl;
	ULONG ACLEntries_1[1] = { 0 };
	LhSetExclusiveACL(ACLEntries_1, 1, &hHookIsDebuggerPresent);
	std::cout << "[HOOK] hook at: IsDebuggerPresent succesfully enabled!" << std::endl;


	// CheckRemoteDebuggerPresent
	HOOK_TRACE_INFO hHookCheckRemoteDebuggerPresent = { NULL };
	std::cout << "[HOOK] Installing hook at: CheckRemoteDebuggerPresent" << std::endl;

	FARPROC func_CheckRemoteDebuggerPresent = GetProcAddress(kernel32, "CheckRemoteDebuggerPresent");
	std::cout << "[HOOK] Got address of 'CheckRemoteDebuggerPresent': " << func_CheckRemoteDebuggerPresent << std::endl;

	result = LhInstallHook(
		func_CheckRemoteDebuggerPresent,
		CheckRemoteDebuggerPresentHook,
		NULL,
		&hHookCheckRemoteDebuggerPresent);
	if (FAILED(result))
	{
		std::cout << "[HOOK] Failed to install hook at: CheckRemoteDebuggerPresent" << std::endl;
		return;
	}
	std::cout << "[HOOK] Hook at CheckRemoteDebuggerPresent installed successfully!" << std::endl;
	ULONG ACLEntries_2[1] = { 0 };
	LhSetExclusiveACL(ACLEntries_2, 1, &hHookCheckRemoteDebuggerPresent);
	std::cout << "[HOOK] hook at: CheckRemoteDebuggerPresent succesfully enabled!" << std::endl;

	// NtCreateFile
	HOOK_TRACE_INFO hHookNtCreateFile = { NULL };
	std::cout << "[HOOK] Installing hook at: NtCreateFile" << std::endl;

	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	std::cout << "[HOOK] Got module handle of 'ntdll': " << ntdll << std::endl;

	FARPROC func_NtCreateFile = GetProcAddress(ntdll, "NtCreateFile");
	std::cout << "[HOOK] Got address of 'NtCreateFile': " << func_NtCreateFile << std::endl;

	NTSTATUS result_NtCreateFile = LhInstallHook(
		func_NtCreateFile,
		NtCreateFileHook,
		NULL,
		&hHookNtCreateFile);
	if (FAILED(result_NtCreateFile))
	{
		std::cout << "[HOOK] Failed to install hook at: NtCreateFile" << std::endl;
		return;
	}
	std::cout << "[HOOK] Hook at NtCreateFile installed successfully!" << std::endl;
	ULONG ACLEntries_3[1] = { 0 };
	LhSetExclusiveACL(ACLEntries_3, 1, &hHookNtCreateFile);
	std::cout << "[HOOK] hook at: NtCreateFile succesfully enabled!" << std::endl;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
