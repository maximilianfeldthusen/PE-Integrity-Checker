## PE-Integrity-Checker

Here’s your text converted into clean **GitHub-flavored Markdown (GFM)** with proper structure, headings, tables, and code blocks:

---

# Part 2: Detailed Code Explanation

## Section 1: File I/O Functions

### `load_pe_file()`

```c
unsigned char* load_pe_file(const char* path, DWORD* size)
```

**Purpose:**
Load entire PE file into memory for analysis.

### Why binary mode (`"rb"`)?

```c
FILE* f = fopen(path, "rb");  // Binary prevents newline translation
```

* On Windows, text mode converts `\r\n` → `\n`
* PE files are binary — any translation corrupts the data

### Error handling

```c
if (fseek(f, 0, SEEK_END) != 0) {
    perror("fseek failed");
    return NULL;
}
```

* Every operation checks for errors
* Resources are cleaned up on failure

---

### `save_pe_file()`

```c
int save_pe_file(const char* path, unsigned char* buffer, DWORD size)
```

**Purpose:**
Write modified PE back to disk (used after IAT reconstruction).

### Return value

* `1` = Success
* `0` = Failure (with error message)

---

## Section 2: SHA-256 Hash Implementation

### Windows: BCrypt API

```c
int compute_sha256_win(const unsigned char* data, DWORD size, char* hex_output)
```

### Step-by-step flow

1. `BCryptOpenAlgorithmProvider()` → Get SHA256 algorithm handle
2. `BCryptGetProperty()` → Get hash object size
3. `malloc()` → Allocate hash object buffer
4. `BCryptCreateHash()` → Create hash context
5. `BCryptHashData()` → Feed data to hash
6. `BCryptFinishHash()` → Get final digest
7. `sprintf()` → Convert to hex string
8. Cleanup (free, close handles)

---

### Why BCrypt over older CryptoAPI?

| Feature               | BCrypt | CryptoAPI (Legacy) |
| --------------------- | ------ | ------------------ |
| Modern API            | ✓      | ✗                  |
| Hardware acceleration | ✓      | Limited            |
| FIPS 140-2            | ✓      | Partial            |
| Active development    | ✓      | Deprecated         |

---

### Linux/macOS: OpenSSL

```c
int compute_sha256_openssl(const unsigned char* data, DWORD size, char* hex_output)
```

### Step-by-step flow

1. `EVP_MD_CTX_new()` → Create hash context
2. `EVP_DigestInit_ex()` → Initialize with SHA256
3. `EVP_DigestUpdate()` → Feed data
4. `EVP_DigestFinal_ex()` → Get final digest
5. `sprintf()` → Convert to hex string
6. `EVP_MD_CTX_free()` → Cleanup

---

### Installation requirements

#### Ubuntu / Debian

```bash
sudo apt-get install libssl-dev
```

#### macOS

```bash
brew install openssl
```

#### RHEL / CentOS

```bash
sudo yum install openssl-devel
```

---

### Why OpenSSL?

* Industry standard (used by Apache, Nginx, etc.)
* Actively maintained
* Cross-platform consistency
* Extensive documentation

---

### Platform Wrapper

```c
int compute_sha256(const unsigned char* data, DWORD size, char* hex_output)
{
#if PLATFORM_WINDOWS
    return compute_sha256_win(data, size, hex_output);
#else
    return compute_sha256_openssl(data, size, hex_output);
#endif
}
```

### Benefits

* Single function call in main code
* Platform detection at compile time
* No runtime overhead

---

## Section 3: PE Structure Accessors

### `get_optional_header_offset()`

```c
DWORD get_optional_header_offset(const unsigned char* pe_data)
```

**Calculates:**
`e_lfanew + 24`

### Why 24?

**NT Headers layout:**

```
Signature:        4 bytes
FileHeader:      20 bytes
-------------------------
Total:           24 bytes
```

---

If you want, I can also convert **Part 1** or generate a **README.md with diagrams and visuals** for GitHub.
