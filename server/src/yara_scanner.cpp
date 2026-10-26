#include "yara_scanner.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <mutex>

namespace pe {

// ─── YARA global init/finalize ────────────────────────────────────────────────
// yr_initialize / yr_finalize are reference-counted globally. Calling them in
// every constructor/destructor causes double-finalize if multiple YaraScanner
// instances exist simultaneously (UB, crash). Use a singleton guard.
namespace {
    std::mutex  g_yara_init_mutex;
    int         g_yara_refcount = 0;

    void yara_addref() {
        std::lock_guard<std::mutex> lk(g_yara_init_mutex);
        if (g_yara_refcount++ == 0)
            yr_initialize();
    }

    void yara_release() {
        std::lock_guard<std::mutex> lk(g_yara_init_mutex);
        if (--g_yara_refcount == 0)
            yr_finalize();
    }
}

YaraScanner::YaraScanner() {
    yara_addref();
}

YaraScanner::~YaraScanner() {
    clear_rules();
    yara_release();
}

void YaraScanner::clear_rules() {
    if (m_rules)    { yr_rules_destroy(m_rules);       m_rules    = nullptr; }
    if (m_compiler) { yr_compiler_destroy(m_compiler); m_compiler = nullptr; }
    m_rule_count = 0;
}

bool YaraScanner::load_rules_file(const std::string& path, std::string& error) {
    clear_rules();
    if (yr_compiler_create(&m_compiler) != ERROR_SUCCESS) {
        error = "Failed to create YARA compiler";
        return false;
    }
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) { error = "Cannot open rules file: " + path; return false; }
    int rc = yr_compiler_add_file(m_compiler, fp, nullptr, path.c_str());
    fclose(fp);
    if (rc > 0) {
        // Drain compiler errors
        char errbuf[256];
        yr_compiler_get_error_message(m_compiler, errbuf, sizeof(errbuf));
        error = "YARA compile error: " + std::string(errbuf);
        return false;
    }
    if (yr_compiler_get_rules(m_compiler, &m_rules) != ERROR_SUCCESS) {
        error = "Failed to get compiled rules";
        return false;
    }
    YR_RULE* rule;
    yr_rules_foreach(m_rules, rule) { m_rule_count++; }
    return true;
}

bool YaraScanner::load_rules_string(const std::string& source,
                                     const std::string& ns, std::string& error) {
    clear_rules();
    if (yr_compiler_create(&m_compiler) != ERROR_SUCCESS) {
        error = "Failed to create YARA compiler";
        return false;
    }
    int rc = yr_compiler_add_string(m_compiler, source.c_str(),
                                     ns.empty() ? nullptr : ns.c_str());
    if (rc > 0) {
        char errbuf[256] = {};
        yr_compiler_get_error_message(m_compiler, errbuf, sizeof(errbuf));
        error = "YARA compile error: " + std::string(errbuf);
        return false;
    }
    if (yr_compiler_get_rules(m_compiler, &m_rules) != ERROR_SUCCESS) {
        error = "Failed to get compiled rules";
        return false;
    }
    YR_RULE* rule;
    yr_rules_foreach(m_rules, rule) { m_rule_count++; }
    return true;
}

int YaraScanner::scan_callback(YR_SCAN_CONTEXT* ctx, int message,
                                 void* message_data, void* user_data) {
    if (message != CALLBACK_MSG_RULE_MATCHING)
        return CALLBACK_CONTINUE;

    auto* sc   = reinterpret_cast<ScanContext*>(user_data);
    auto* rule = reinterpret_cast<YR_RULE*>(message_data);

    YaraMatch m;
    m.rule_name     = rule->identifier;
    m.namespace_str = rule->ns->name ? rule->ns->name : "";

    const char* tag;
    yr_rule_tags_foreach(rule, tag) {
        if (!m.tags.empty()) m.tags += ' ';
        m.tags += tag;
    }

    YR_META* meta;
    yr_rule_metas_foreach(rule, meta) {
        std::string kv = std::string(meta->identifier) + " = ";
        if      (meta->type == META_TYPE_STRING)  kv += '"' + std::string(meta->string) + '"';
        else if (meta->type == META_TYPE_INTEGER)  kv += std::to_string(meta->integer);
        else if (meta->type == META_TYPE_BOOLEAN)  kv += meta->integer ? "true" : "false";
        m.meta_pairs.push_back(std::move(kv));
    }

    YR_STRING* str;
    yr_rule_strings_foreach(rule, str) {
        YR_MATCH* match;
        yr_string_matches_foreach(ctx, str, match) {
            YaraMatch::StringMatch sm;
            sm.identifier = str->identifier;
            sm.offset     = match->offset;

            size_t preview = std::min(static_cast<size_t>(match->data_length), size_t(32));
            // Hex preview
            sm.data_hex.reserve(preview * 3);
            static const char HEX[] = "0123456789ABCDEF";
            for (size_t i = 0; i < preview; i++) {
                uint8_t b = match->data[i];
                sm.data_hex += HEX[b >> 4];
                sm.data_hex += HEX[b & 0xF];
                sm.data_hex += ' ';
            }
            // ASCII preview
            sm.data_ascii.reserve(preview);
            for (size_t i = 0; i < preview; i++) {
                uint8_t b = match->data[i];
                sm.data_ascii += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
            }
            m.string_matches.push_back(std::move(sm));
        }
    }

    sc->matches->push_back(std::move(m));
    return CALLBACK_CONTINUE;
}

std::vector<YaraMatch> YaraScanner::scan(const uint8_t* data, size_t size,
                                           int timeout_secs) {
    std::vector<YaraMatch> matches;
    if (!m_rules || !data || size == 0) return matches;

    ScanContext sc{&matches};
    yr_rules_scan_mem(m_rules,
                      const_cast<uint8_t*>(data), size,
                      SCAN_FLAGS_REPORT_RULES_MATCHING,
                      scan_callback, &sc,
                      timeout_secs);
    return matches;
}

nlohmann::json YaraScanner::scan_json(const uint8_t* data, size_t size,
                                       int timeout_secs) {
    auto matches = scan(data, size, timeout_secs);
    nlohmann::json arr = nlohmann::json::array();
    arr.get_ref<nlohmann::json::array_t&>().reserve(matches.size());
    for (auto& m : matches) {
        nlohmann::json jm;
        jm["rule"]      = m.rule_name;
        jm["namespace"] = m.namespace_str;
        jm["tags"]      = m.tags;
        jm["meta"]      = m.meta_pairs;
        jm["strings"]   = nlohmann::json::array();
        for (auto& sm : m.string_matches) {
            jm["strings"].push_back({
                {"id",    sm.identifier},
                {"offset",sm.offset},
                {"hex",   sm.data_hex},
                {"ascii", sm.data_ascii},
            });
        }
        arr.push_back(std::move(jm));
    }
    return arr;
}

std::string YaraScanner::builtin_rules() {
    return R"YARA(
rule IsPEFile {
    meta:
        description = "Detects PE executable files"
        category = "generic"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe
}

rule SuspiciousImports_AntiDebug {
    meta:
        description = "Anti-debugging API calls"
        severity = "medium"
        category = "anti_analysis"
    strings:
        $a1 = "IsDebuggerPresent" ascii wide
        $a2 = "CheckRemoteDebuggerPresent" ascii wide
        $a3 = "NtQueryInformationProcess" ascii wide
        $a4 = "OutputDebugString" ascii wide
        $a5 = "FindWindow" ascii wide
        $a6 = "ZwSetInformationThread" ascii wide
        $a7 = "DbgBreakPoint" ascii wide
    condition:
        3 of them
}

rule SuspiciousImports_Injection {
    meta:
        description = "Process injection APIs"
        severity = "high"
        category = "injection"
    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "NtCreateThreadEx" ascii wide
        $a5 = "RtlCreateUserThread" ascii wide
        $a6 = "QueueUserAPC" ascii wide
    condition:
        2 of them
}

rule SuspiciousImports_NetworkC2 {
    meta:
        description = "Network/C2 related APIs"
        severity = "medium"
        category = "network"
    strings:
        $n1 = "InternetOpenUrl" ascii wide
        $n2 = "HttpSendRequest" ascii wide
        $n3 = "WSAConnect" ascii wide
        $n4 = "socket" ascii wide
        $n5 = "WinHttpOpen" ascii wide
        $n6 = "URLDownloadToFile" ascii wide
    condition:
        2 of them
}

rule PossiblyPacked_KnownSections {
    meta:
        description = "Known packer section names"
        severity = "high"
        category = "packer"
    strings:
        $upx0    = "UPX0" ascii
        $upx1    = "UPX1" ascii
        $upx2    = "UPX!" ascii
        $nspack   = ".nsp0" ascii
        $mpress   = "MPRESS" ascii
        $fsg      = "FSG!" ascii
        $aspack   = "ASPack" ascii
        $petite   = "PEtite" ascii
        $themida  = ".themida" ascii
        $vmprotect= ".vmp0" ascii
        $pecompact= "PECompact" ascii
        $enigma   = ".enigma1" ascii
    condition:
        any of them
}

rule SuspiciousStrings_URLs {
    meta:
        description = "Suspicious hardcoded URLs or IPs"
        severity = "medium"
        category = "network"
    strings:
        $r1 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii wide
        $r2 = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{2,5}/ ascii wide
        $r3 = ".onion" ascii wide nocase
        $r4 = "pastebin.com" ascii wide nocase
        $r5 = "raw.githubusercontent.com" ascii wide nocase
    condition:
        any of them
}

rule SuspiciousStrings_Persistence {
    meta:
        description = "Registry-based persistence strings"
        severity = "medium"
        category = "persistence"
    strings:
        $r1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $r2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $r3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $r4 = "SYSTEM\\CurrentControlSet\\Services" ascii wide nocase
        $r5 = "ScheduledTasks" ascii wide nocase
    condition:
        any of them
}

rule PowershellExecution {
    meta:
        description = "PowerShell execution strings"
        severity = "high"
        category = "execution"
    strings:
        $p1 = "powershell" ascii wide nocase
        $p2 = "-EncodedCommand" ascii wide nocase
        $p3 = "-nop" ascii wide nocase
        $p4 = "-WindowStyle Hidden" ascii wide nocase
        $p5 = "IEX(" ascii wide
        $p6 = "Invoke-Expression" ascii wide nocase
        $p7 = "FromBase64String" ascii wide
    condition:
        2 of them
}

rule Shellcode_Signatures {
    meta:
        description = "Common shellcode byte patterns"
        severity = "high"
        category = "shellcode"
    strings:
        $s1 = { 64 A1 30 00 00 00 }           // fs:[30h] PEB x86
        $s2 = { 65 48 8B 04 25 60 00 00 00 }  // gs:[60h] PEB x64
        $s3 = { 60 89 E5 31 D2 64 8B }        // pushad; classic shellcode
        $s4 = { FC E8 8? 00 00 00 }            // Metasploit stager
        $s5 = { EB 27 5B 53 }                 // GetPC trick
        $msf_bind = { FC E8 89 00 00 00 }     // Metasploit bindshell
    condition:
        any of them
}

rule CryptoConstants {
    meta:
        description = "Cryptographic constants"
        severity = "info"
        category = "crypto"
    strings:
        $aes_sbox    = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $sha256_init = { 6A 09 E6 67 BB 67 AE 85 }
        $tea_delta   = { 9E 37 79 B9 }
        $md5_const   = { 01 23 45 67 89 AB CD EF }
        $rc4_str     = "RC4" ascii wide nocase
        $aes_str     = "AES" ascii wide nocase
    condition:
        any of ($aes_sbox, $sha256_init, $tea_delta, $md5_const) or 2 of ($rc4_str, $aes_str)
}

rule SuspiciousAPISequence_Hollow {
    meta:
        description = "Process hollowing API sequence"
        severity = "critical"
        category = "injection"
    strings:
        $a1 = "CreateProcess" ascii wide
        $a2 = "NtUnmapViewOfSection" ascii wide
        $a3 = "VirtualAllocEx" ascii wide
        $a4 = "WriteProcessMemory" ascii wide
        $a5 = "SetThreadContext" ascii wide
        $a6 = "ResumeThread" ascii wide
    condition:
        4 of them
}

rule SuspiciousStrings_CredentialAccess {
    meta:
        description = "Credential access / keylogging indicators"
        severity = "high"
        category = "credential_access"
    strings:
        $k1 = "GetAsyncKeyState" ascii wide
        $k2 = "SetWindowsHookEx" ascii wide
        $k3 = "GetClipboardData" ascii wide
        $k4 = "SamQueryInformationUser" ascii wide
        $k5 = "lsass" ascii wide nocase
        $k6 = "Mimikatz" ascii wide nocase
        $k7 = "sekurlsa" ascii wide nocase
        $k8 = "wce.exe" ascii wide nocase
    condition:
        any of them
}

rule EmbeddedPE {
    meta:
        description = "Embedded PE file within PE"
        severity = "high"
        category = "dropper"
    strings:
        $mz = { 4D 5A 90 00 }
        $pe = { 50 45 00 00 }
    condition:
        #mz > 1 or #pe > 1
}

rule SuspiciousDebugArtifacts {
    meta:
        description = "Debug path reveals suspicious build environment"
        severity = "low"
        category = "attribution"
    strings:
        $d3  = "C:\\Users\\user\\" ascii nocase
        $d4  = "pentest" ascii nocase
        $d5  = "hack" ascii nocase
        $d6  = "malware" ascii nocase
        $d7  = "\\backdoor\\" ascii nocase
        $d8  = "\\payload\\" ascii nocase
        $d9  = "\\rat\\" ascii nocase
        $d10 = "\\keylogger\\" ascii nocase
    condition:
        any of ($d3, $d4, $d5, $d6, $d7, $d8, $d9, $d10)
}
)YARA";
}

} // namespace pe
