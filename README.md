# PE Visualizer v2.0

**Portable Executable (PE32/PE64) Static Analysis Platform**

A malware analysis and binary reverse engineering tool combining high-performance C++20 backend analysis with an intuitive Next.js/TypeScript frontend. Supports comprehensive PE parsing, x86/x64 disassembly, YARA scanning, entropy analysis, and anomaly detection.

---

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| **Total Files** | 31 |
| **Total Lines of Code** | 15,907 |
| **Frontend Files** | 15 |
| **Frontend Lines** | 11,457 |
| **Backend Files** | 16 |
| **Backend Lines** | 4,450 |
| **Frontend Language** | TypeScript/React (Next.js 14) |
| **Backend Language** | C++20 |

---

## 🏗️ Architecture

```
PE-Visualizer/
├── build.bat                         # Build automation script
├── README.md                          # Project documentation
│
├── frontend/                          # Next.js 14 + TypeScript UI (11,457 LOC, 15 files)
│   ├── app/
│   │   ├── api/upload/route.ts       # File upload API endpoint
│   │   ├── globals.css               # Global styles
│   │   ├── layout.tsx                # Root layout component
│   │   └── page.tsx                  # Main SPA application
│   ├── lib/
│   │   ├── api.ts                    # API client & utilities
│   │   ├── store.ts                  # Zustand state management
│   │   └── types.ts                  # TypeScript PE type definitions
│   ├── next.config.js                # Next.js configuration
│   ├── package.json                  # Dependencies & scripts
│   ├── postcss.config.js             # PostCSS configuration
│   ├── tailwind.config.ts            # Tailwind CSS configuration
│   └── tsconfig.json                 # TypeScript configuration
│
└── server/                           # C++20 High-Performance Backend (4,450 LOC, 16 files)
    ├── CMakeLists.txt                # CMake build configuration
    ├── vcpkg.json                    # C++ dependency manifest
    └── src/
        ├── main.cpp                  # Entry point & HTTP route handlers
        ├── pe_parser.hpp/.cpp        # Comprehensive PE binary parser
        ├── disassembler.hpp/.cpp     # x86/x64 disassembly engine (Zydis)
        ├── yara_scanner.hpp/.cpp     # Threat intelligence rule engine
        ├── http_handler.hpp/.cpp     # Boost.Beast HTTP server
        ├── anomaly_detector.cpp      # Anomaly detection engine
        ├── entropy.cpp               # Entropy calculation & analysis
        ├── string_extractor.cpp      # String extraction & categorization
        ├── resource_parser.cpp       # PE resource section parsing
        └── rich_header.cpp           # Rich header analysis
```

---

## ✨ Core Features

### 🔍 PE Parsing Engine
Complete PE32/PE64 binary analysis with 20+ sub-components:

| Component | Capabilities |
|-----------|--------------|
| **DOS Header** | Full IMAGE_DOS_HEADER extraction + stub analysis |
| **Rich Header** | XOR decryption, checksum validation, VS version detection (2002–2022) |
| **File Header** | Machine type, timestamp decoding, characteristics flags |
| **Optional Header** | PE32/PE64 detection, all standard fields, checksum validation |
| **Data Directories** | All 16 directory entries with RVA/size validation |
| **Sections** | RWX permissions, entropy metrics, MD5/SHA-256 hashing, anomaly detection |
| **Import Directory** | Full INT/IAT parsing, bound imports, ordinal resolution, API classification |
| **Delay Imports** | Attribute-based parsing, RVA/VA conversion, delay load tree |
| **Export Directory** | Function enumeration, forwarder detection, ordinal tracking |
| **Resources** | Recursive 3-level tree parsing, entropy/format analysis per resource |
| **Debug Directory** | PDB path extraction, GUID/age (CodeView RSDS), all debug types |
| **TLS Directory** | PE32/PE64 callback array enumeration |
| **Load Config** | CFG/SEH flags, /GS cookie detection, guard protection flags |
| **Exception Directory** | x64 RUNTIME_FUNCTION unwinding info |
| **Base Relocations** | Block-by-block parsing, relocation type decoding |
| **CLR/.NET Header** | Runtime version, managed code flags, entry point tokens |
| **Overlay Detection** | File tail analysis, entropy profiling, embedded file detection |
| **Hashing** | MD5, SHA-1, SHA-256 (OpenSSL), Import Hash (ImpHash) |
| **Signatures** | Authenticode certificate detection |

### 🎯 Anomaly Detection
15+ anomaly checks for malware identification:
- RWX sections (executable + writable)
- Entry point outside code sections
- Packed/suspicious sections (UPX, etc.)
- Anti-debug API imports
- Process injection patterns
- Suspicious registry access
- Network command & control patterns
- Unusual import chains

### 🔧 Disassembler (x86/x64)
- **Engine:** Zydis decoder library
- **Syntax:** Intel syntax with forced segment/size prefixes
- **Features:**
  - Color-coded instruction classification (call, jmp, jcc, ret, nop, privileged, syscall, stack, mov)
  - Branch target resolution with absolute address calculation
  - Interactive navigation: click to follow calls/jumps
  - Entry point auto-jump with configurable view
  - RVA/size filtering

### 🛡️ YARA Threat Intelligence
Embedded detection engine with 14 rule categories:
- PE file structure validation
- Anti-debug API detection (IsDebuggerPresent, NtQueryInformationProcess, etc.)
- Process injection detection (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
- Network & C2 patterns (InternetOpenUrl, WSAConnect, WinHttp)
- Packer signatures (UPX, MPRESS, ASPack, VMProtect, Themida)
- Shellcode patterns (PEB access, Metasploit stagers)
- Cryptographic constants (AES S-box, SHA-256 init, RC4/RSA strings)
- Process hollowing sequences
- Credential harvesting & keyloggers
- Embedded/dropper PE detection
- Persistence registry keys
- PowerShell/script execution
- Custom rule support via web UI
- Per-match string location preview with hex/ASCII dump

### 📊 Entropy Analysis
- Block-by-block entropy calculation (256-byte chunks)
- Section-level entropy metrics
- Visual entropy map with area charts
- Packed/compressed section detection

### 🔎 String Extraction
- ASCII + UTF-16LE extraction
- Automatic categorization:
  - URLs & domains
  - IP addresses (IPv4/IPv6)
  - Registry keys
  - Email addresses
  - File paths
- Paginated browser with search/filtering

---

## 🎨 Frontend UI Components

| Panel | Description |
|-------|-------------|
| **Overview** | Executive summary: file hashes, PE badges, security features grid, section entropy bar chart, security profile radar, anomaly summary |
| **Headers** | Tabbed view: DOS, Rich, File, Optional headers + all data directories |
| **Sections** | Table view with RWX flags, entropy bars, hashes, quick-launch disassembler/hex views |
| **Imports** | Collapsible DLL tree with function list, bound import detection, search |
| **Exports** | Directory metadata, searchable function table, forwarder analysis |
| **Resources** | Recursive tree view, per-resource entropy metrics, format detection |
| **Disassembler** | Full listing with color-coded instructions, branch following, entry point navigation |
| **Hex View** | 16-byte-wide hex dump with ASCII column, RVA-based navigation |
| **Strings** | Paginated display, category filters, encoding toggles, search functionality |
| **YARA Matches** | Built-in rules + custom rule editor, match details with string locations |
| **Anomalies** | Severity-filtered alerts with category badges and descriptions |
| **Entropy Map** | Visual area chart (256-byte blocks) + section entropy overlay |
| **Debug Info** | All debug entries: PDB path, GUID, age, debug type catalog |

---

## 🚀 Getting Started

### Requirements
- **Backend:** C++20, CMake 3.20+, vcpkg, Boost, OpenSSL, Zydis
- **Frontend:** Node.js 18+, npm/yarn

On Windows, building the backend with `build.bat` requires Visual Studio Build Tools or Visual Studio with the **Desktop development with C++** workload, plus vcpkg.

### Build & Run
```bash
# Build backend and frontend from a Visual Studio Developer terminal
.\build.bat

# Build only the frontend (does not require CMake, MSVC, or vcpkg)
.\build.bat --frontend-only

# Run the frontend in development mode
cd frontend
npm install
npm run dev
```

The backend listens on `127.0.0.1:9000` by default; the frontend proxies API requests to that port.

---

## 📦 Technology Stack

### Backend
- **Language:** C++20
- **HTTP Server:** Boost.Beast
- **PE Parsing:** Custom implementation
- **Disassembly:** Zydis library
- **Threat Scanning:** YARA engine
- **Cryptography:** OpenSSL

### Frontend
- **Framework:** Next.js 14
- **Language:** TypeScript
- **Styling:** Tailwind CSS
- **State:** Zustand
- **Visualization:** Recharts
- **UI:** Custom React components

---

## 📝 License & Attribution

Comprehensive binary analysis platform built with precision and professional-grade tooling for security researchers, malware analysts, and reverse engineers.
| **TLS** | Directory fields + callback address list |
| **Load Config** | CFG/SEH/Cookie flags, guard flags decoded |
| **.NET CLR** | Runtime version, flags |
| **Overlay** | Offset, size, entropy, format, hex preview |
| **Relocations** | Block table: VA, size, entry count |
| **Signature** | Signed/verified status |

---

## Build & Run

### Prerequisites

**Backend (Windows build script):**
```
- CMake 3.20+
- Visual Studio Build Tools or Visual Studio with the Desktop development with C++ workload
- vcpkg
- Boost 1.82+ (system, filesystem)
- OpenSSL 3.x
- nlohmann/json 3.11+
- YARA 4.4+ (libyara)
- Zydis 4.x
- C++20 compiler (MSVC 19.29+ / GCC 12+ / Clang 15+)
```

**Frontend:**
```
- Node.js 18+
- npm / yarn
```

### Backend Build

```bash
cd server

# Configure (example with vcpkg)
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-windows

cmake --build build --config Release

# Run
./build/Release/pe_server.exe --host 127.0.0.1 --port 9000 --threads 8
```

### Frontend

```bash
cd frontend
npm install
npm run dev          # Development: http://localhost:3000
npm run build && npm start  # Production
```

---

## API Reference

All endpoints return `application/json`. CORS is fully open for development.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/upload` | Upload PE file (base64), returns `session_id` |
| `GET`  | `/api/analyze?session=ID` | Full PE analysis JSON |
| `GET`  | `/api/disasm?session=ID&rva=N&size=N&max=N` | Disassemble at RVA |
| `GET`  | `/api/hexdump?session=ID&rva=N&size=N` | Hex dump rows |
| `POST` | `/api/yara` | `{session, rules}` — YARA scan |
| `GET`  | `/api/strings?session=ID&filter=CAT&q=QUERY&limit=N&offset=N` | Extracted strings |
| `GET`  | `/api/section_data?session=ID&name=.text` | Raw section hex |
| `GET`  | `/api/entropy_map?session=ID` | Block + section entropy |
| `GET`  | `/api/sessions` | List all sessions |
| `DELETE` | `/api/session?id=ID` | Delete session |
| `GET`  | `/health` | Server health check |

### Upload Request
```json
{
  "filename": "malware.exe",
  "data": "<base64-encoded bytes>"
}
```

### Upload Response
```json
{
  "session_id": "1a2b3c4d5e6f7a8b",
  "filename": "malware.exe",
  "file_size": 102400,
  "pe_type": "EXE",
  "valid": true
}
```

---

## Anomaly Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| Zero timestamp | MEDIUM | TimeDateStamp stripped |
| Implausible timestamp | HIGH | Far-future date |
| RWX section | HIGH | Writable + executable |
| High section entropy | MEDIUM | >7.0 bits |
| Raw data beyond EOF | HIGH | Malformed PE |
| EP in non-executable section | HIGH | Packer indicator |
| EP outside all sections | CRITICAL | Shellcode/stub |
| No imports | HIGH | Packed/obfuscated |
| Very few imports | MEDIUM | Possibly packed |
| TLS callbacks | MEDIUM | Pre-EP execution |
| No Rich header | LOW | Non-MSVC tool |
| Invalid checksum | MEDIUM | Post-build modification |
| Overlay data | MEDIUM/HIGH | Appended payload |
| High file entropy | MEDIUM | >7.2 bits |
| Suspicious APIs | MEDIUM | Injection/anti-debug APIs found |

---

## Session Management

Sessions are held in-memory on the server with no disk writes. Each session stores:
- Raw file bytes
- Parsed PE structure
- Pre-computed JSON response

Sessions persist until explicitly deleted or server restart. Max recommended concurrent sessions: ~20 (RAM-dependent).

---

## Security Note

This tool performs **read-only static analysis** — it never executes, loads, or maps the PE file. All parsing is done on the raw byte buffer. Safe to analyze live malware samples.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend language | C++20 |
| HTTP server | Boost.Beast 1.82 |
| PE parsing | Custom (windows.h / winnt.h structs) |
| Disassembler | Zydis 4.x |
| YARA | libyara 4.4 |
| Hashing | OpenSSL 3.x (MD5/SHA1/SHA256) |
| JSON | nlohmann/json 3.11 |
| Frontend framework | Next.js 14 (App Router) |
| Language | TypeScript 5 |
| State management | Zustand |
| UI components | shadcn/ui + Radix UI |
| Charts | Recharts |
| Animations | Framer Motion |
| Styling | Tailwind CSS |
| Data fetching | Axios + SWR |
| File upload | react-dropzone |
