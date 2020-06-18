#pragma warning(push, 3)
#include <Windows.h>
#include <cstdio>
#include <cstdlib>
#pragma warning(pop)


const char header_file_name[] = "headers.txt";
const char import_file_name[] = "imports.txt";

//#define PRINT_TO_FILES

#ifdef PRINT_TO_FILES
FILE *headers_file = nullptr, *import_file = nullptr;
#else
FILE *headers_file = stdout, *import_file = stdout;
#endif

void usage();

bool is32bit(LPVOID dataPtr);

void printFile(LPVOID dataPtr);
void printFile32(LPVOID dataPtr);
void printFile64(LPVOID dataPtr);
void printDosHeader(PIMAGE_DOS_HEADER pidh);
void printNtHeaders32(PIMAGE_NT_HEADERS32 pinh);
void printNtHeaders64(PIMAGE_NT_HEADERS64 pinh);
void printSignature(DWORD sign);
void printFileHeader(PIMAGE_FILE_HEADER pifh);
void printOptionalHeader32(PIMAGE_OPTIONAL_HEADER32 pioh);
void printOptionalHeader64(PIMAGE_OPTIONAL_HEADER64 pioh);
void printSectionHeaders(PIMAGE_SECTION_HEADER pish, int numberOfSections);
void printSectionHeader(PIMAGE_SECTION_HEADER pish);
bool isNull(PIMAGE_IMPORT_DESCRIPTOR piid);
void printImportDescriptors(PIMAGE_IMPORT_DESCRIPTOR piid, LPVOID dataPtr, bool is32bit);
void printImportDescriptor(PIMAGE_IMPORT_DESCRIPTOR piid, LPVOID dataPtr, bool is32bit);
void printNamesTable32(DWORD rwa, LPVOID dataPtr);
void printNamesTable64(DWORD rwa, LPVOID dataPtr);
void printName32(DWORD rwa, LPVOID dataPtr);
void printName64(ULONGLONG rwa, LPVOID dataPtr);

void mapPEFile(HANDLE *hFile, HANDLE *hFileMapping, LPVOID *dataPtr, const WCHAR *file_name);
void unmapPEFile(HANDLE *hFile, HANDLE *hFileMapping, LPVOID *dataPtr);

void openOutputFiles();
void closeOutputFiles();




int wmain(int argc, wchar_t **argv)
{
    if(argc != 2)
        usage();


    HANDLE hFile = NULL, hFileMapping = NULL;
    LPVOID dataPtr = nullptr;

    mapPEFile(&hFile, &hFileMapping, &dataPtr, argv[1]);

#ifdef PRINT_TO_FILES
    openOutputFiles();
#endif

    printFile(dataPtr);

#ifdef PRINT_TO_FILES
    closeOutputFiles();
#endif

    unmapPEFile(&hFile, &hFileMapping, &dataPtr);

    printf("EXIT_SUCCESS\n");
    return EXIT_SUCCESS;
}


void usage()
{
    puts("usage: PE-info.exe filename");
    exit(EXIT_FAILURE);
}


bool is32bit(LPVOID dataPtr)
{
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)dataPtr;
    PIMAGE_NT_HEADERS32 pinh = (PIMAGE_NT_HEADERS32)((BYTE *)pidh + pidh->e_lfanew);

    WORD characteristics = pinh->FileHeader.Characteristics;
    if(characteristics & IMAGE_FILE_32BIT_MACHINE)
        return true;

    return false;
}


void printFile(LPVOID dataPtr)
{
    if(is32bit(dataPtr))
        printFile32(dataPtr);
    else
        printFile64(dataPtr);
}


void printFile32(LPVOID dataPtr)
{
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)dataPtr;
    printDosHeader(pidh);

    PIMAGE_NT_HEADERS32 pinh = (PIMAGE_NT_HEADERS32)((BYTE *)pidh + pidh->e_lfanew);
    printNtHeaders32(pinh);

    PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((BYTE *)pinh + sizeof(IMAGE_NT_HEADERS32));
    printSectionHeaders(pish, pinh->FileHeader.NumberOfSections);

    PIMAGE_IMPORT_DESCRIPTOR piid = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)pidh + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    printImportDescriptors(piid, dataPtr, true);
}


void printFile64(LPVOID dataPtr)
{
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)dataPtr;
    printDosHeader(pidh);

    PIMAGE_NT_HEADERS64 pinh = (PIMAGE_NT_HEADERS64)((BYTE *)pidh + pidh->e_lfanew);
    printNtHeaders64(pinh);

    PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((BYTE *)pinh + sizeof(IMAGE_NT_HEADERS64));
    printSectionHeaders(pish, pinh->FileHeader.NumberOfSections);

    PIMAGE_IMPORT_DESCRIPTOR piid = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)pidh + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    printImportDescriptors(piid, dataPtr, false);
}


void printDosHeader(PIMAGE_DOS_HEADER pidh)
{
    fprintf(headers_file, "\nIMAGE_DOS_HEADER\n{\n");


    fprintf(headers_file, "\te_magic = %x\n", pidh->e_magic);
    fprintf(headers_file, "\te_cblp = %x\n", pidh->e_cblp);
    fprintf(headers_file, "\te_cp = %x\n", pidh->e_cp);
    fprintf(headers_file, "\te_crlc = %x\n", pidh->e_crlc);
    fprintf(headers_file, "\te_cparhdr = %x\n", pidh->e_cparhdr);
    fprintf(headers_file, "\te_minalloc = %x\n", pidh->e_minalloc);
    fprintf(headers_file, "\te_maxalloc = %x\n", pidh->e_maxalloc);
    fprintf(headers_file, "\te_ss = %x\n", pidh->e_ss);
    fprintf(headers_file, "\te_sp = %x\n", pidh->e_sp);
    fprintf(headers_file, "\te_csum = %x\n", pidh->e_csum);
    fprintf(headers_file, "\te_ip = %x\n", pidh->e_ip);
    fprintf(headers_file, "\te_cs = %x\n", pidh->e_cs);
    fprintf(headers_file, "\te_lfarlc = %x\n", pidh->e_lfarlc);
    fprintf(headers_file, "\te_ovno = %x\n", pidh->e_ovno);
    fprintf(headers_file, "\te_res = { %x %x %x %x }\n", pidh->e_res[0], pidh->e_res[1], pidh->e_res[2], pidh->e_res[3]);
    fprintf(headers_file, "\te_oemid = %x\n", pidh->e_oemid);
    fprintf(headers_file, "\te_oeminfo = %x\n", pidh->e_oeminfo);

    fprintf(headers_file, "\te_res2 = { ");
    for(int i = 0; i < 10; i++)
        fprintf(headers_file, "%x ", pidh->e_res2[i]);
    fprintf(headers_file, "}\n");

    fprintf(headers_file, "\te_lfanew = %lx\n", pidh->e_lfanew);


    fprintf(headers_file, "}\n\n");
}


void printNtHeaders32(PIMAGE_NT_HEADERS32 pinh)
{
    fprintf(headers_file, "\nIMAGE_NT_HEADERS32\n{\n");

    printSignature(pinh->Signature);
    printFileHeader(&pinh->FileHeader);
    printOptionalHeader32(&pinh->OptionalHeader);

    fprintf(headers_file, "}\n\n");
}


void printNtHeaders64(PIMAGE_NT_HEADERS64 pinh)
{
    fprintf(headers_file, "\nIMAGE_NT_HEADERS64\n{\n");

    printSignature(pinh->Signature);
    printFileHeader(&pinh->FileHeader);
    printOptionalHeader64(&pinh->OptionalHeader);

    fprintf(headers_file, "}\n\n");
}


void printSignature(DWORD sign)
{
    char *cSign = reinterpret_cast<char *>(&sign);

    fprintf(headers_file, "\tSignature = { ");
    for(int i = 0; i < 4; i++)
    {
        if(cSign[i] != 0)
            fprintf(headers_file, "\'%c\' ", cSign[i]);
        else
            fprintf(headers_file, "0 ");
    }
    fprintf(headers_file, "}\n");
}


void printFileHeader(PIMAGE_FILE_HEADER pifh)
{
    fprintf(headers_file, "\tFileHeader = \n\t{\n");

    fprintf(headers_file, "\t\tMachine = %x\n", pifh->Machine);
    fprintf(headers_file, "\t\tNumberOfSections = %x\n", pifh->NumberOfSections);
    fprintf(headers_file, "\t\tTimeDateStamp = %lx\n", pifh->TimeDateStamp);
    fprintf(headers_file, "\t\tPointerToSymbolTable = %lx\n", pifh->PointerToSymbolTable);
    fprintf(headers_file, "\t\tNumberOfSymbols = %lx\n", pifh->NumberOfSymbols);
    fprintf(headers_file, "\t\tSizeOfOptionalHeader = %x\n", pifh->SizeOfOptionalHeader);
    fprintf(headers_file, "\t\tCharacteristics = %x\n", pifh->Characteristics);

    fprintf(headers_file, "\t}\n\n");
}


void printOptionalHeader32(PIMAGE_OPTIONAL_HEADER32 pioh)
{
    fprintf(headers_file, "\tOptionalHeader = \n\t{\n");

    fprintf(headers_file, "\t\tMagic = %x\n", pioh->Magic);
    fprintf(headers_file, "\t\tMajorLinkerVersion = %x\n", pioh->MajorLinkerVersion);
    fprintf(headers_file, "\t\tMinorLinkerVersion = %x\n", pioh->MinorLinkerVersion);
    fprintf(headers_file, "\t\tSizeOfCode = %lx\n", pioh->SizeOfCode);
    fprintf(headers_file, "\t\tSizeOfInitializedData = %lx\n", pioh->SizeOfInitializedData);
    fprintf(headers_file, "\t\tSizeOfUninitializedData = %lx\n", pioh->SizeOfUninitializedData);
    fprintf(headers_file, "\t\tAddressOfEntryPoint = %lx\n", pioh->AddressOfEntryPoint);
    fprintf(headers_file, "\t\tBaseOfCode = %lx\n", pioh->BaseOfCode);
    fprintf(headers_file, "\t\tBaseOfData = %lx\n", pioh->BaseOfData);

    fprintf(headers_file, "\t\tImageBase = %lx\n", pioh->ImageBase);
    fprintf(headers_file, "\t\tSectionAlignment = %lx\n", pioh->SectionAlignment);
    fprintf(headers_file, "\t\tFileAlignment = %lx\n", pioh->FileAlignment);
    fprintf(headers_file, "\t\tMajorOperatingSystemVersion = %x\n", pioh->MajorOperatingSystemVersion);
    fprintf(headers_file, "\t\tMinorOperatingSystemVersion = %x\n", pioh->MinorOperatingSystemVersion);
    fprintf(headers_file, "\t\tMajorImageVersion = %x\n", pioh->MajorImageVersion);
    fprintf(headers_file, "\t\tMinorImageVersion = %x\n", pioh->MinorImageVersion);
    fprintf(headers_file, "\t\tMajorSubsystemVersion = %x\n", pioh->MajorSubsystemVersion);
    fprintf(headers_file, "\t\tMinorSubsystemVersion = %x\n", pioh->MinorSubsystemVersion);
    fprintf(headers_file, "\t\tWin32VersionValue = %lx\n", pioh->Win32VersionValue);
    fprintf(headers_file, "\t\tSizeOfImage = %lx\n", pioh->SizeOfImage);
    fprintf(headers_file, "\t\tSizeOfHeaders = %lx\n", pioh->SizeOfHeaders);
    fprintf(headers_file, "\t\tCheckSum = %lx\n", pioh->CheckSum);
    fprintf(headers_file, "\t\tSubsystem = %x\n", pioh->Subsystem);
    fprintf(headers_file, "\t\tDllCharacteristics = %x\n", pioh->DllCharacteristics);
    fprintf(headers_file, "\t\tSizeOfStackReserve = %lx\n", pioh->SizeOfStackReserve);
    fprintf(headers_file, "\t\tSizeOfStackCommit = %lx\n", pioh->SizeOfStackCommit);
    fprintf(headers_file, "\t\tSizeOfHeapReserve = %lx\n", pioh->SizeOfHeapReserve);
    fprintf(headers_file, "\t\tSizeOfHeapCommit = %lx\n", pioh->SizeOfHeapCommit);
    fprintf(headers_file, "\t\tLoaderFlags = %lx\n", pioh->LoaderFlags);
    fprintf(headers_file, "\t\tNumberOfRvaAndSizes = %lx\n", pioh->NumberOfRvaAndSizes);

    for(int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        fprintf(headers_file, "\t\tDataDirectory[%x] = \n\t\t{\n\t\t\tVirtualAddress = %lx\n\t\t\tSize = %lx\n\t\t}\n",
            i, pioh->DataDirectory[i].VirtualAddress, pioh->DataDirectory[i].Size);
    }

    fprintf(headers_file, "\t}\n\n");
}


void printOptionalHeader64(PIMAGE_OPTIONAL_HEADER64 pioh)
{
    fprintf(headers_file, "\tOptionalHeader = \n\t{\n");

    fprintf(headers_file, "\t\tMagic = %x\n", pioh->Magic);
    fprintf(headers_file, "\t\tMajorLinkerVersion = %x\n", pioh->MajorLinkerVersion);
    fprintf(headers_file, "\t\tMinorLinkerVersion = %x\n", pioh->MinorLinkerVersion);
    fprintf(headers_file, "\t\tSizeOfCode = %lx\n", pioh->SizeOfCode);
    fprintf(headers_file, "\t\tSizeOfInitializedData = %lx\n", pioh->SizeOfInitializedData);
    fprintf(headers_file, "\t\tSizeOfUninitializedData = %lx\n", pioh->SizeOfUninitializedData);
    fprintf(headers_file, "\t\tAddressOfEntryPoint = %lx\n", pioh->AddressOfEntryPoint);
    fprintf(headers_file, "\t\tBaseOfCode = %lx\n", pioh->BaseOfCode);

    fprintf(headers_file, "\t\tImageBase = %llx\n", pioh->ImageBase);
    fprintf(headers_file, "\t\tSectionAlignment = %lx\n", pioh->SectionAlignment);
    fprintf(headers_file, "\t\tFileAlignment = %lx\n", pioh->FileAlignment);
    fprintf(headers_file, "\t\tMajorOperatingSystemVersion = %x\n", pioh->MajorOperatingSystemVersion);
    fprintf(headers_file, "\t\tMinorOperatingSystemVersion = %x\n", pioh->MinorOperatingSystemVersion);
    fprintf(headers_file, "\t\tMajorImageVersion = %x\n", pioh->MajorImageVersion);
    fprintf(headers_file, "\t\tMinorImageVersion = %x\n", pioh->MinorImageVersion);
    fprintf(headers_file, "\t\tMajorSubsystemVersion = %x\n", pioh->MajorSubsystemVersion);
    fprintf(headers_file, "\t\tMinorSubsystemVersion = %x\n", pioh->MinorSubsystemVersion);
    fprintf(headers_file, "\t\tWin32VersionValue = %lx\n", pioh->Win32VersionValue);
    fprintf(headers_file, "\t\tSizeOfImage = %lx\n", pioh->SizeOfImage);
    fprintf(headers_file, "\t\tSizeOfHeaders = %lx\n", pioh->SizeOfHeaders);
    fprintf(headers_file, "\t\tCheckSum = %lx\n", pioh->CheckSum);
    fprintf(headers_file, "\t\tSubsystem = %x\n", pioh->Subsystem);
    fprintf(headers_file, "\t\tDllCharacteristics = %x\n", pioh->DllCharacteristics);

    fprintf(headers_file, "\t\tSizeOfStackReserve = %llx\n", pioh->SizeOfStackReserve);
    fprintf(headers_file, "\t\tSizeOfStackCommit = %llx\n", pioh->SizeOfStackCommit);
    fprintf(headers_file, "\t\tSizeOfHeapReserve = %llx\n", pioh->SizeOfHeapReserve);
    fprintf(headers_file, "\t\tSizeOfHeapCommit = %llx\n", pioh->SizeOfHeapCommit);

    fprintf(headers_file, "\t\tLoaderFlags = %lx\n", pioh->LoaderFlags);
    fprintf(headers_file, "\t\tNumberOfRvaAndSizes = %lx\n", pioh->NumberOfRvaAndSizes);

    for(int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        fprintf(headers_file, "\t\tDataDirectory[%x] = \n\t\t{\n\t\t\tVirtualAddress = %lx\n\t\t\tSize = %lx\n\t\t}\n",
            i, pioh->DataDirectory[i].VirtualAddress, pioh->DataDirectory[i].Size);
    }


    fprintf(headers_file, "\t}\n\n");
}


void printSectionHeaders(PIMAGE_SECTION_HEADER pish, int numberOfSections)
{
    for(int i = 0; i < numberOfSections; i++)
    {
        fprintf(headers_file, "IMAGE_SECTION_HEADER[%x]\n{\n", i);
        printSectionHeader(&pish[i]);
        fprintf(headers_file, "}\n\n");
    }
}


void printSectionHeader(PIMAGE_SECTION_HEADER pish)
{
    fprintf(headers_file, "\tSubsystem = { ");
    for(int i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++)
    {
        if(pish->Name[i] != 0)
            fprintf(headers_file, "\'%c\' ", pish->Name[i]);
        else
            fprintf(headers_file, "0 ");
    }
    fprintf(headers_file, "}\n");

    fprintf(headers_file, "\tMisc.PhysicalAddress = %lx\n", pish->Misc.PhysicalAddress);
    fprintf(headers_file, "\tMisc.VirtualSize = %lx\n", pish->Misc.VirtualSize);

    fprintf(headers_file, "\tVirtualAddress = %lx\n", pish->VirtualAddress);
    fprintf(headers_file, "\tSizeOfRawData = %lx\n", pish->SizeOfRawData);
    fprintf(headers_file, "\tPointerToRawData = %lx\n", pish->PointerToRawData);
    fprintf(headers_file, "\tPointerToRelocations = %lx\n", pish->PointerToRelocations);
    fprintf(headers_file, "\tPointerToLinenumbers = %lx\n", pish->PointerToLinenumbers);
    fprintf(headers_file, "\tNumberOfRelocations = %x\n", pish->NumberOfRelocations);
    fprintf(headers_file, "\tNumberOfLinenumbers = %x\n", pish->NumberOfLinenumbers);
    fprintf(headers_file, "\tCharacteristics = %lx\n", pish->Characteristics);
}


bool isNull(PIMAGE_IMPORT_DESCRIPTOR piid)
{
    return (piid->Characteristics == 0) && (piid->TimeDateStamp == 0) && (piid->ForwarderChain == 0) && (piid->Name == 0) && (piid->FirstThunk == 0);
}


void printImportDescriptors(PIMAGE_IMPORT_DESCRIPTOR piid, LPVOID dataPtr, bool is32bit)
{
    int i = 0;
    while(!isNull(piid))
    {
        fprintf(import_file, "IMAGE_IMPORT_DESCRIPTOR[%x]\n{\n", i);
        printImportDescriptor(piid, dataPtr, is32bit);
        fprintf(import_file, "}\n\n");
        
        piid++;
        i++;
    }
}


void printImportDescriptor(PIMAGE_IMPORT_DESCRIPTOR piid, LPVOID dataPtr, bool is32bit)
{
    fprintf(import_file, "\tOriginalFirstThunk = %lx\n", piid->OriginalFirstThunk);

    fprintf(import_file, "\tfuncs\n\t{\n");
    if(is32bit)
        printNamesTable32(piid->OriginalFirstThunk, dataPtr);
    else
        printNamesTable64(piid->OriginalFirstThunk, dataPtr);
    fprintf(import_file, "\t}\n");

    fprintf(import_file, "\tTimeDateStamp = %lx\n", piid->TimeDateStamp);
    fprintf(import_file, "\tForwarderChain = %lx\n", piid->ForwarderChain);

    char *name = (char *)((BYTE *)dataPtr + piid->Name);
    fprintf(import_file, "\tName = \"%s\"\n", name);

    fprintf(import_file, "\tFirstThunk = %lx\n", piid->FirstThunk);
}


void printNamesTable32(DWORD rwa, LPVOID dataPtr)
{
    while(true)
    {
        DWORD *name_rwa = (DWORD *)((BYTE *)dataPtr + rwa);
        if(*name_rwa == 0)
            break;

        printName32(*name_rwa, dataPtr);

        rwa += sizeof(DWORD);
    }
}


void printNamesTable64(DWORD rwa, LPVOID dataPtr)
{
    while(true)
    {
        ULONGLONG *name_rwa = (ULONGLONG *)((BYTE *)dataPtr + rwa);
        if(*name_rwa == 0)
            break;

        printName64(*name_rwa, dataPtr);

        rwa += sizeof(ULONGLONG);
    }
}


void printName32(DWORD rwa, LPVOID dataPtr)
{
    char *name = (char *)((BYTE *)dataPtr + rwa + sizeof(WORD));
    fprintf(import_file, "\t\t\"%s\"\n", name);
}


void printName64(ULONGLONG rwa, LPVOID dataPtr)
{
    char *name = (char *)((BYTE *)dataPtr + rwa + sizeof(WORD));
    fprintf(import_file, "\t\t\"%s\"\n", name);
}


void mapPEFile(HANDLE *hFile, HANDLE *hFileMapping, LPVOID *dataPtr, const WCHAR *file_name)
{
    *hFile = CreateFileW(file_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(*hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFileW failed with error %ld\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    *hFileMapping = CreateFileMappingW(*hFile, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, 0);
    if(*hFileMapping == NULL)
    {
        printf("CreateFileMappingW failed with error %ld\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    *dataPtr = MapViewOfFile(*hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if(*dataPtr == NULL)
    {
        printf("MapViewOfFile failed with error %ld\n", GetLastError());
        exit(EXIT_FAILURE);
    }

}


void unmapPEFile(HANDLE *hFile, HANDLE *hFileMapping, LPVOID *dataPtr)
{
    BOOL bRet = UnmapViewOfFile(*dataPtr);
    if(!bRet)
    {
        printf("UnmapViewOfFile failed with error %ld\n", GetLastError());
    }
    *dataPtr = nullptr;


    bRet = CloseHandle(*hFileMapping);
    if(!bRet)
    {
        printf("UnmapViewOfFile failed with error %ld\n", GetLastError());
    }
    *hFileMapping = NULL;


    bRet = CloseHandle(*hFile);
    if(!bRet)
    {
        printf("UnmapViewOfFile failed with error %ld\n", GetLastError());
    }
    *hFile = NULL;
}


void openOutputFiles()
{
    headers_file = fopen(header_file_name, "w");
    if(headers_file == nullptr)
    {
        printf("fopen(header_file_name, ...) failed\n");
        exit(EXIT_FAILURE);
    }

    import_file = fopen(import_file_name, "w");
    if(import_file == nullptr)
    {
        printf("fopen(import_file_name, ...) failed\n");
        exit(EXIT_FAILURE);
    }
}


void closeOutputFiles()
{
    fclose(headers_file);
    headers_file = nullptr;

    fclose(import_file);
    import_file = nullptr;
}

