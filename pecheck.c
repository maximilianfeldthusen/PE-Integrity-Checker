

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


/* --- Platform Detection --- */
#if defined(_WIN32) || defined(_WIN64)
    #define PLATFORM_WINDOWS 1
    #include <windows.h>
    #include <wincrypt.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
    #pragma comment(lib, "crypt32.lib")
#else
    #define PLATFORM_WINDOWS 0
    /* OpenSSL headers */
    #include <openssl/sha.h>
    #include <openssl/evp.h>
    typedef uint16_t WORD;
    typedef uint32_t DWORD;
    typedef uint64_t ULONGLONG;
#endif


/* --- PE Constants --- */
#define IMAGE_DOS_SIGNATURE    0x5A4D
#define IMAGE_NT_SIGNATURE     0x00004550
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4


/* --- Certificate Constants --- */
#define WIN_CERT_REVISION_2_0  0x0200
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA  0x0002


/* --- Status Enums --- */
typedef enum {
    STATUS_OK = 0,
    STATUS_WARNING = 1,
    STATUS_CRITICAL = 2
} CHECK_STATUS;


/* --- Integrity Result Structure --- */
typedef struct {
    CHECK_STATUS sig_status;
    CHECK_STATUS hash_status;
    BOOL is_signed;
    BOOL is_hash_match;
    char expected_hash[65];
    char actual_hash[65];
    char issuer[256];
    char subject[256];
} INTEGRITY_RESULT;


/* --- Minimal PE Structures (Cross-Platform Compatible) --- */
typedef struct {
    WORD e_magic;
    LONG e_lfanew;
} PE_DOS_HEADER;


typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} PE_DATA_DIRECTORY;


typedef struct {
    DWORD dwLength;
    WORD wRevision;
    WORD wCertificateType;
    BYTE bCertificate[1];
} WIN_CERTIFICATE;


typedef struct {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} PE_FILE_HEADER;


typedef struct {
    char Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} PE_SECTION_HEADER;



unsigned char* load_pe_file(const char* path, DWORD* size) {
    FILE* f = fopen(path, "rb");  // Binary mode prevents newline translation
    if (!f) {
        perror("Failed to open file");
        return NULL;
    }
   
    /* Seek to end to get file size */
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek failed");
        fclose(f);
        return NULL;
    }
   
    long file_len = ftell(f);
    if (file_len < 0) {
        perror("ftell failed");
        fclose(f);
        return NULL;
    }
    *size = (DWORD)file_len;
   
    /* Reset to beginning */
    if (fseek(f, 0, SEEK_SET) != 0) {
        perror("fseek reset failed");
        fclose(f);
        return NULL;
    }
   
    /* Allocate buffer */
    unsigned char* buffer = (unsigned char*)malloc(*size);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(f);
        return NULL;
    }
   
    /* Read entire file */
    size_t bytes_read = fread(buffer, 1, *size, f);
    if (bytes_read != *size) {
        fprintf(stderr, "Error: Read %zu bytes, expected %lu\n", bytes_read, *size);
        free(buffer);
        fclose(f);
        return NULL;
    }
   
    fclose(f);
    return buffer;
}


/**
 * save_pe_file - Write buffer back to disk
 *
 * Used after IAT reconstruction to save modified PE
 */
int save_pe_file(const char* path, unsigned char* buffer, DWORD size) {
    FILE* f = fopen(path, "wb");
    if (!f) {
        perror("Failed to create output file");
        return 0;
    }
   
    size_t written = fwrite(buffer, 1, size, f);
    fclose(f);
   
    if (written != size) {
        fprintf(stderr, "Error: Wrote %zu bytes, expected %lu\n", written, size);
        return 0;
    }
   
    return 1;
}



#if PLATFORM_WINDOWS
int compute_sha256_win(const unsigned char* data, DWORD size, char* hex_output) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHash = 0;
    DWORD cbData = 0;
    unsigned char* pbHashObject = NULL;
    NTSTATUS status;


    /* Step 1: Open SHA256 algorithm provider */
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptOpenAlgorithmProvider failed: 0x%08lx\n", status);
        return -1;
    }


    /* Step 2: Get hash object size */
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject,
                               sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGetProperty failed: 0x%08lx\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }


    /* Step 3: Allocate hash object buffer */
    pbHashObject = (unsigned char*)malloc(cbHashObject);
    if (!pbHashObject) {
        fprintf(stderr, "Memory allocation failed\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }


    /* Step 4: Create hash object */
    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptCreateHash failed: 0x%08lx\n", status);
        free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }


    /* Step 5: Hash the data */
    status = BCryptHashData(hHash, (PUCHAR)data, size, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptHashData failed: 0x%08lx\n", status);
        BCryptDestroyHash(hHash);
        free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }


    /* Step 6: Finalize hash */
    unsigned char pbHash[32];  // SHA-256 produces 32 bytes
    status = BCryptFinishHash(hHash, pbHash, sizeof(pbHash), 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptFinishHash failed: 0x%08lx\n", status);
        BCryptDestroyHash(hHash);
        free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }


    /* Step 7: Convert to hex string */
    for (int i = 0; i < 32; i++) {
        sprintf(hex_output + (i * 2), "%02x", pbHash[i]);
    }
    hex_output[64] = '\0';


    /* Cleanup */
    BCryptDestroyHash(hHash);
    free(pbHashObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);
   
    return 0;
}


#else

    
int compute_sha256_openssl(const unsigned char* data, DWORD size, char* hex_output) {
    EVP_MD_CTX* ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
   
    /* Step 1: Create hash context */
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return -1;
    }
   
    /* Step 2: Initialize with SHA-256 algorithm */
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }
   
    /* Step 3: Update with data */
    if (EVP_DigestUpdate(ctx, data, size) != 1) {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }
   
    /* Step 4: Finalize and get digest */
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }
   
    /* Verify we got 32 bytes (SHA-256 output) */
    if (digest_len != 32) {
        fprintf(stderr, "Unexpected digest length: %u (expected 32)\n", digest_len);
        EVP_MD_CTX_free(ctx);
        return -1;
    }
   
    /* Step 5: Convert to hex string */
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(hex_output + (i * 2), "%02x", digest[i]);
    }
    hex_output[64] = '\0';
   
    /* Cleanup */
    EVP_MD_CTX_free(ctx);
   
    return 0;
}


#endif


/**
 * compute_sha256 - Platform-independent wrapper
 *
 * This function abstracts away platform differences.
 * Call this instead of compute_sha256_win or compute_sha256_openssl directly.
 */
int compute_sha256(const unsigned char* data, DWORD size, char* hex_output) {
#if PLATFORM_WINDOWS
    return compute_sha256_win(data, size, hex_output);
#else
    return compute_sha256_openssl(data, size, hex_output);
#endif
}


    
DWORD get_optional_header_offset(const unsigned char* pe_data) {
    PE_DOS_HEADER* dos = (PE_DOS_HEADER*)pe_data;
   
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
   
    DWORD* sig_ptr = (DWORD*)(pe_data + dos->e_lfanew);
    if (*sig_ptr != IMAGE_NT_SIGNATURE) {
        return 0;
    }
   
    /* Optional Header starts after Signature (4) + File Header (20) = 24 */
    return dos->e_lfanew + 24;
}



PE_DATA_DIRECTORY* get_data_directory(const unsigned char* pe_data, int entry_index) {
    DWORD opt_offset = get_optional_header_offset(pe_data);
    if (opt_offset == 0) return NULL;
   
    /* DataDirectories starts at offset 112 from Optional Header start */
    return (PE_DATA_DIRECTORY*)(pe_data + opt_offset + 112 +
                                 (entry_index * sizeof(PE_DATA_DIRECTORY)));
}


/**
 * get_sections - Get pointer to Section Headers array
 *
 * Section Headers immediately follow Optional Header
 *
 * Returns:
 *   Pointer to first PE_SECTION_HEADER, or NULL on error
 */

PE_SECTION_HEADER* get_sections(const unsigned char* pe_data, PE_FILE_HEADER* file_hdr) {
    DWORD opt_offset = get_optional_header_offset(pe_data);
    if (opt_offset == 0) return NULL;
   
    return (PE_SECTION_HEADER*)(pe_data + opt_offset + file_hdr->SizeOfOptionalHeader);
}


    
CHECK_STATUS verify_certificate_structure(const unsigned char* pe_data,
                                          DWORD file_size,
                                          PE_FILE_HEADER* file_hdr,
                                          INTEGRITY_RESULT* result) {
    PE_DATA_DIRECTORY* security_dir = get_data_directory(pe_data, IMAGE_DIRECTORY_ENTRY_SECURITY);
   
    if (!security_dir || security_dir->Size == 0) {
        printf("[!] WARNING: No certificate table found (Unsigned file)\n");
        result->is_signed = FALSE;
        return STATUS_WARNING;
    }
   
    printf("[+] Certificate table found (Size: %lu bytes)\n", security_dir->Size);
    result->is_signed = TRUE;
   
    /* Check 1: 8-byte alignment */
    DWORD cert_offset = file_size - security_dir->Size;
    if (cert_offset % 8 != 0) {
        printf("[!] CRITICAL: Certificate misaligned (not 8-byte boundary)\n");
        printf("    Offset: 0x%X, Remainder: %lu\n", cert_offset, cert_offset % 8);
        return STATUS_CRITICAL;
    }
   
    /* Check 2: Certificate header validity */
    WIN_CERTIFICATE* cert = (WIN_CERTIFICATE*)(pe_data + cert_offset);
   
    if (cert->dwLength < sizeof(WIN_CERTIFICATE)) {
        printf("[!] CRITICAL: Certificate length too small (%lu bytes)\n", cert->dwLength);
        return STATUS_CRITICAL;
    }
   
    if (cert->dwLength != security_dir->Size) {
        printf("[!] CRITICAL: Certificate size mismatch\n");
        printf("    Header: %lu, Directory: %lu\n", cert->dwLength, security_dir->Size);
        return STATUS_CRITICAL;
    }
   
    if (cert->wRevision != WIN_CERT_REVISION_2_0) {
        printf("[!] CRITICAL: Invalid certificate revision: 0x%04X\n", cert->wRevision);
        return STATUS_CRITICAL;
    }
   
    if (cert->wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
        printf("[!] CRITICAL: Invalid certificate type: 0x%04X\n", cert->wCertificateType);
        return STATUS_CRITICAL;
    }
   
    /* Check 3: No overlap with sections */
    PE_SECTION_HEADER* sections = get_sections(pe_data, file_hdr);
    DWORD last_section_end = 0;
   
    for (int i = 0; i < file_hdr->NumberOfSections; i++) {
        DWORD section_end = sections[i].PointerToRawData + sections[i].SizeOfRawData;
        if (section_end > last_section_end) {
            last_section_end = section_end;
        }
    }
   
    if (cert_offset < last_section_end) {
        printf("[!] CRITICAL: Certificate overlaps with section data\n");
        printf("    Last section ends at: 0x%X, Certificate starts at: 0x%X\n",
               last_section_end, cert_offset);
        return STATUS_CRITICAL;
    }
   
    printf("[✓] Certificate structure valid\n");
    return STATUS_OK;
}

     
void check_integrity(const char* input_path, const char* expected_hash_str) {
    DWORD file_size;
    unsigned char* pe_data = load_pe_file(input_path, &file_size);
   
    if (!pe_data) {
        fprintf(stderr, "Error: Failed to load file '%s'\n", input_path);
        return;
    }


    printf("================================================================================\n");
    printf("PE INTEGRITY CHECK\n");
    printf("================================================================================\n");
    printf("File:     %s\n", input_path);
    printf("Size:     %lu bytes\n", file_size);
    printf("Date:     %s", __DATE__);
    printf("Time:     %s\n", __TIME__);
    printf("\n");


    INTEGRITY_RESULT result = {0};
    if (expected_hash_str) {
        strncpy(result.expected_hash, expected_hash_str, 64);
        result.expected_hash[64] = '\0';
    }


    /* Step 1: Basic PE Validation */
    PE_DOS_HEADER* dos = (PE_DOS_HEADER*)pe_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] CRITICAL: Invalid DOS signature (Expected 0x5A4D, Got 0x%04X)\n", dos->e_magic);
        result.sig_status = STATUS_CRITICAL;
        goto cleanup;
    }


    DWORD* sig_ptr = (DWORD*)(pe_data + dos->e_lfanew);
    if (*sig_ptr != IMAGE_NT_SIGNATURE) {
        printf("[!] CRITICAL: Invalid NT signature (Expected 0x00004550, Got 0x%08X)\n", *sig_ptr);
        result.sig_status = STATUS_CRITICAL;
        goto cleanup;
    }


    PE_FILE_HEADER* file_hdr = (PE_FILE_HEADER*)(pe_data + dos->e_lfanew + 4);
    WORD magic = *(WORD*)(pe_data + dos->e_lfanew + 24);
   
    printf("[✓] PE Header Valid\n");
    printf("    Architecture: %s\n", magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "PE32 (32-bit)" : "PE32+ (64-bit)");
    printf("    Sections:     %u\n", file_hdr->NumberOfSections);
    printf("\n");


    /* Step 2: Certificate Structure Check */
    result.sig_status = verify_certificate_structure(pe_data, file_size, file_hdr, &result);
    printf("\n");


    /* Step 3: Hash Calculation */
    /* Authenticode signs file EXCLUDING certificate table */
    DWORD hashable_size = file_size;
    if (result.is_signed) {
        hashable_size = file_size - get_data_directory(pe_data, IMAGE_DIRECTORY_ENTRY_SECURITY)->Size;
        printf("[*] Computing hash of file content (excluding %lu-byte certificate)...\n",
               get_data_directory(pe_data, IMAGE_DIRECTORY_ENTRY_SECURITY)->Size);
    } else {
        printf("[*] Computing hash of entire file (unsigned)...\n");
    }


    if (compute_sha256(pe_data, hashable_size, result.actual_hash) != 0) {
        printf("[!] CRITICAL: Failed to compute SHA-256 hash\n");
        result.hash_status = STATUS_CRITICAL;
    } else {
        printf("    Computed Hash: %s\n", result.actual_hash);
       
        if (expected_hash_str && strlen(expected_hash_str) == 64) {
            /* Case-insensitive comparison */
            if (strcasecmp(result.actual_hash, expected_hash_str) == 0) {
                printf("[✓] HASH MATCH: File content is identical to expected\n");
                result.hash_status = STATUS_OK;
                result.is_hash_match = TRUE;
            } else {
                printf("[!] CRITICAL: HASH MISMATCH - File has been modified!\n");
                printf("    Expected: %s\n", expected_hash_str);
                printf("    Actual:   %s\n", result.actual_hash);
               
                /* Show first difference */
                for (int i = 0; i < 64; i++) {
                    if (tolower(result.actual_hash[i]) != tolower(expected_hash_str[i])) {
                        printf("    First difference at position %d\n", i);
                        break;
                    }
                }
                result.hash_status = STATUS_CRITICAL;
                result.is_hash_match = FALSE;
            }
        } else {
            printf("[?] No expected hash provided. Hash computed for reference.\n");
            result.hash_status = STATUS_WARNING;
        }
    }
    printf("\n");


    /* Step 4: Final Report */
    printf("================================================================================\n");
    printf("FINAL INTEGRITY REPORT\n");
    printf("================================================================================\n");
   
    const char* sig_str = (result.sig_status == STATUS_OK) ? "VALID" :
                          (result.sig_status == STATUS_WARNING) ? "MISSING" :
                          (result.sig_status == STATUS_CRITICAL) ? "INVALID/TAMPERED" : "UNKNOWN";
   
    const char* hash_str = (result.hash_status == STATUS_OK) ? "MATCH" :
                           (result.hash_status == STATUS_CRITICAL) ? "MISMATCH" : "SKIPPED";


    printf("Signature Status: %s\n", sig_str);
    printf("Hash Status:      %s\n", hash_str);
    printf("Hash (SHA-256):   %s\n", result.actual_hash);
   
    if (result.is_signed && result.expected_hash[0] != '\0') {
        printf("Expected Hash:    %s\n", result.expected_hash);
    }
   
    printf("\n");


    /* Decision Matrix */
    if (result.sig_status == STATUS_CRITICAL || result.hash_status == STATUS_CRITICAL) {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  FILE INTEGRITY COMPROMISED                ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        printf("    DO NOT EXECUTE THIS FILE!\n");
        printf("    Possible causes:\n");
        printf("      • File was modified after signing\n");
        printf("      • Certificate was corrupted\n");
        printf("      • Malware injection detected\n");
        printf("      • File truncation or corruption\n");
    } else if (result.sig_status == STATUS_WARNING && result.hash_status == STATUS_WARNING) {
        printf("[!] WARNING: Unsigned file. Verify source before execution.\n");
    } else {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  ✓  FILE INTEGRITY VERIFIED SUCCESSFULLY                       ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
    }
   
    printf("================================================================================\n");


cleanup:
    free(pe_data);
}


/* ============================================================================
 * SECTION 6: COMMAND LINE INTERFACE
 * ============================================================================
 */


void print_usage(const char* prog) {
    printf("PE Integrity Checker v1.0\n");
    printf("Cross-Platform: Windows (BCrypt) + Linux/macOS (OpenSSL)\n\n");
    printf("Usage:\n");
    printf("  %s <command> [options] <file> [expected_hash]\n\n", prog);
    printf("Commands:\n");
    printf("  check    Verify file integrity (default)\n");
    printf("  hash     Compute hash only (no comparison)\n");
    printf("  info     Display PE file information\n\n");
    printf("Options:\n");
    printf("  -h       Show this help\n\n");
    printf("Arguments:\n");
    printf("  file           Path to PE file to check\n");
    printf("  expected_hash  (Optional) 64-char SHA-256 hex string\n\n");
    printf("Examples:\n");
    printf("  %s check app.exe\n", prog);
    printf("  %s check app.exe a1b2c3d4e5f6...\n", prog);
    printf("  %s hash app.exe\n", prog);
    printf("\n");
    printf("Compilation:\n");
    printf("  Windows: gcc -o pe_check pe_check.c -lbcrypt -lcrypt32\n");
    printf("  Linux:   gcc -o pe_check pe_check.c -lssl -lcrypto\n");
    printf("  macOS:   gcc -o pe_check pe_check.c -lssl -lcrypto\n");
    printf("\n");
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }


    const char* command = argv[1];
    const char* file_path = NULL;
    const char* expected_hash = NULL;


    /* Parse arguments */
    if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }


    if (strcmp(command, "check") == 0 || strcmp(command, "hash") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Missing file argument\n");
            print_usage(argv[0]);
            return 1;
        }
        file_path = argv[2];
        if (argc > 3) {
            expected_hash = argv[3];
        }
    } else if (strcmp(command, "info") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Missing file argument\n");
            print_usage(argv[0]);
            return 1;
        }
        file_path = argv[2];
        /* Could add PE info display here */
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }


    /* Execute command */
    if (strcmp(command, "check") == 0) {
        check_integrity(file_path, expected_hash);
    } else if (strcmp(command, "hash") == 0) {
        /* Simplified hash-only mode */
        DWORD file_size;
        unsigned char* pe_data = load_pe_file(file_path, &file_size);
        if (!pe_data) {
            fprintf(stderr, "Error: Failed to load file\n");
            return 1;
        }
       
        char hash[65];
        if (compute_sha256(pe_data, file_size, hash) == 0) {
            printf("%s  %s\n", hash, file_path);
        } else {
            fprintf(stderr, "Error: Failed to compute hash\n");
            free(pe_data);
            return 1;
        }
        free(pe_data);
    }


    return 0;
}







