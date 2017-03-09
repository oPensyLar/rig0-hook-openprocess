#include "stdafx.h"
#include <ntstrsafe.h>


//Consts
#define BB_POOL_TAG 'enoB'
#define IMAGE_DOS_SIGNATURE                     0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE                      0x00004550  // PE00
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES        16
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC           0x20b
#define IMAGE_DIRECTORY_ENTRY_EXPORT             0   // Export Directory

//TypeDef
typedef USHORT *PUSHORT;


#if defined(_WIN64)
 typedef unsigned __int64 ULONG_PTR;
#else
 typedef unsigned long ULONG_PTR;
#endif


typedef struct _IMAGE_FILE_HEADER // Size=20
{
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;





typedef struct _IMAGE_DATA_DIRECTORY
{
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;





typedef enum _InjectType
{
    IT_Thread,      // CreateThread into LdrLoadDll
    IT_Apc,         // Force user APC into LdrLoadDll
    IT_MMap,        // Manual map
} InjectType;





typedef struct tagACTCTXW 
{
    ULONG  cbSize;
    ULONG  dwFlags;
    PWCH   lpSource;
    USHORT wProcessorArchitecture;
    USHORT wLangId;
    PWCH   lpAssemblyDirectory;
    PWCH   lpResourceName;
    PWCH   lpApplicationName;
    PVOID  hModule;
} ACTCTXW, *PACTCTXW;






typedef struct tagACTCTXW32
{
    ULONG  cbSize;
    ULONG  dwFlags;
    ULONG  lpSource;
    USHORT wProcessorArchitecture;
    USHORT wLangId;
    ULONG  lpAssemblyDirectory;
    ULONG  lpResourceName;
    ULONG  lpApplicationName;
    ULONG  hModule;
} ACTCTXW32, *PACTCTXW32;






/// <summary>
/// User-mode memory region
/// </summary>
typedef struct _USER_CONTEXT
{
    UCHAR code[0x1000];             // Code buffer
    union 
    {
        UNICODE_STRING ustr;
        UNICODE_STRING32 ustr32;
    };
    wchar_t buffer[0x400];          // Buffer for unicode string


    // Activation context data
    union
    {
        ACTCTXW actx;
        ACTCTXW32 actx32;
    };


    HANDLE hCTX;                    
    ULONG hCookie;

    PVOID ptr;                      // Tmp data
    union
    {
        NTSTATUS status;            // Last execution status
        PVOID retVal;               // Function return value
        ULONG retVal32;             // Function return value
    };

    //UCHAR tlsBuf[0x100];
} USER_CONTEXT, *PUSER_CONTEXT;






typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Name;
    ULONG   Base;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    ULONG   AddressOfFunctions;     // RVA from base of image
    ULONG   AddressOfNames;         // RVA from base of image
    ULONG   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;







typedef struct _IMAGE_DOS_HEADER
{
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;




typedef struct _IMAGE_OPTIONAL_HEADER64
{
    USHORT Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    ULONG SizeOfCode;
    ULONG SizeOfInitializedData;
    ULONG SizeOfUninitializedData;
    ULONG AddressOfEntryPoint;
    ULONG BaseOfCode;
    ULONGLONG ImageBase;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG Win32VersionValue;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    ULONG LoaderFlags;
    ULONG NumberOfRvaAndSizes;
    struct _IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;











typedef struct _IMAGE_OPTIONAL_HEADER32
{
    //
    // Standard fields.
    //

    USHORT  Magic;
    UCHAR   MajorLinkerVersion;
    UCHAR   MinorLinkerVersion;
    ULONG   SizeOfCode;
    ULONG   SizeOfInitializedData;
    ULONG   SizeOfUninitializedData;
    ULONG   AddressOfEntryPoint;
    ULONG   BaseOfCode;
    ULONG   BaseOfData;

    //
    // NT additional fields.
    //

    ULONG   ImageBase;
    ULONG   SectionAlignment;
    ULONG   FileAlignment;
    USHORT  MajorOperatingSystemVersion;
    USHORT  MinorOperatingSystemVersion;
    USHORT  MajorImageVersion;
    USHORT  MinorImageVersion;
    USHORT  MajorSubsystemVersion;
    USHORT  MinorSubsystemVersion;
    ULONG   Win32VersionValue;
    ULONG   SizeOfImage;
    ULONG   SizeOfHeaders;
    ULONG   CheckSum;
    USHORT  Subsystem;
    USHORT  DllCharacteristics;
    ULONG   SizeOfStackReserve;
    ULONG   SizeOfStackCommit;
    ULONG   SizeOfHeapReserve;
    ULONG   SizeOfHeapCommit;
    ULONG   LoaderFlags;
    ULONG   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;






typedef struct _IMAGE_NT_HEADERS64
{
    ULONG Signature;
    struct _IMAGE_FILE_HEADER FileHeader;
    struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;





typedef struct _IMAGE_NT_HEADERS
{
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS;






typedef struct _MMAP_CONTEXT
{
    PEPROCESS pProcess;     // Target process
    PVOID pWorkerBuf;       // Worker thread code buffer
    HANDLE hWorker;         // Worker thread handle
    PETHREAD pWorker;       // Worker thread object
    LIST_ENTRY modules;     // Manual module list
    PUSER_CONTEXT userMem;  // Tmp buffer in user space
    HANDLE hSync;           // APC sync handle
    PKEVENT pSync;          // APC sync object
    PVOID pSetEvent;        // ZwSetEvent address
    PVOID pLoadImage;       // LdrLoadDll address
    BOOLEAN tlsInitialized; // Static TLS was initialized
} MMAP_CONTEXT, *PMMAP_CONTEXT;









typedef enum _MmapFlags
{
    KNoFlags         = 0x00,    // No flags
    KManualImports   = 0x01,    // Manually map import libraries
    KWipeHeader      = 0x04,    // Wipe image PE headers
    KHideVAD         = 0x10,    // Make image appear as PAGE_NOACESS region
    KRebaseProcess   = 0x40,    // If target image is an .exe file, process base address will be replaced with mapped module value

    KNoExceptions    = 0x01000, // Do not create custom exception handler
    KNoSxS           = 0x08000, // Do not apply SxS activation context
    KNoTLS           = 0x10000, // Skip TLS initialization and don't execute TLS callbacks
} KMmapFlags;





typedef struct _MAP_MEMORY_REGION_RESULT
{
    ULONGLONG originalPtr;      // Address in target process
    ULONGLONG newPtr;           // Mapped address in host process
    ULONGLONG removedPtr;       // Unmapped region base, in case of conflicting region
    ULONG     size;             // Mapped region size
    ULONG     removedSize;      // Unmapped region size
} MAP_MEMORY_REGION_RESULT, *PMAP_MEMORY_REGION_RESULT;




typedef enum _ModType
{
    mt_mod32,       // 64 bit module
    mt_mod64,       // 32 bit module
    mt_default,     // type is deduced from target process
    mt_unknown      // Failed to detect type
} ModType;











typedef struct _MODULE_DATA
{
    LIST_ENTRY link;            // List link
    PUCHAR baseAddress;         // Base image address in target process
    PUCHAR localBase;           // Base image address in system space
    UNICODE_STRING name;        // File name
    UNICODE_STRING fullPath;    // Full file path
    SIZE_T size;                // Size of image
    ModType type;               // Module type
    enum KMmapFlags flags;      // Flags
    BOOLEAN manual;             // Image is manually mapped
    BOOLEAN initialized;        // DllMain was already called
} MODULE_DATA, *PMODULE_DATA;







typedef struct _INJECT_DLL
{
    InjectType type;                // Type of injection
    wchar_t    FullDllPath[512];    // Fully-qualified path to the target dll
    wchar_t    initArg[512];        // Init routine argument
    ULONG      initRVA;             // Init routine RVA, if 0 - no init routine
    ULONG      pid;                 // Target process ID
    BOOLEAN    wait;                // Wait on injection thread
    BOOLEAN    unlink;              // Unlink module after injection
    BOOLEAN    erasePE;             // Erase PE headers after injection   
    KMmapFlags flags;               // Manual map flags
    ULONGLONG  imageBase;           // Image address in memory to manually map
    ULONG      imageSize;           // Size of memory image
    BOOLEAN    asImage;             // Memory chunk has image layout
} INJECT_DLL, *PINJECT_DLL;





//Functions
NTSTATUS InjectDllWithParam(unsigned int pid, UNICODE_STRING path, InjectType itype, ULONG initRVA ,const UNICODE_STRING initArg, BOOLEAN unlink, BOOLEAN erasePE, BOOLEAN wait);



NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process( IN PEPROCESS Process );




NTSTATUS BBMapUserImage(IN PEPROCESS pProcess, IN PUNICODE_STRING path, IN PVOID buffer, IN ULONG_PTR size, IN BOOLEAN asImage, IN enum KMmapFlags flags, IN ULONG initRVA, IN PWCH initArg, OUT PMODULE_DATA pImage);




NTSTATUS BBCreateWorkerThread(IN PMMAP_CONTEXT pContext);








/// <summary>
/// Get exported function address
/// </summary>
/// <param name="pBase">Module base</param>
/// <param name="name_ord">Function name or ordinal</param>
/// <param name="pProcess">Target process for user module</param>
/// <returns>Found address, NULL if not found</returns>
PVOID BBGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord, IN PEPROCESS pProcess, IN PUNICODE_STRING modName);







NTSTATUS Injector(IN PINJECT_DLL pidProc);
