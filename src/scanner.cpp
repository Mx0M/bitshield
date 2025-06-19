#include "scanner.h"
#include "utils.h"
#include "aes.h"
#include <fstream>
#include <unordered_set>
#include <algorithm>
#include <iostream>
#include <regex>
#include <filesystem>
#include <yara.h>
YR_RULES *yara_rules = nullptr;

static std::unordered_set<std::string> known_signatures;

bool matches_suspicious_patterns(const std::string &content)
{

    static const std::vector<std::regex> patterns = {
        // Suspicious executables and scripting tools
        std::regex(R"(cmd\.exe|powershell|wscript|cscript|bash\s+-i|/bin/sh)", std::regex::icase),

        // Encoded payloads
        std::regex(R"([a-zA-Z0-9+/]{100,}={0,2})"), // base64
        std::regex(R"(0x[a-fA-F0-9]{4,})"),         // shellcode hex

        // Downloads & network
        std::regex(R"(wget|curl|Invoke-WebRequest|netcat|nc\s+-e)", std::regex::icase),
        std::regex(R"((http|https|ftp):\/\/[^\s'"<>]+)", std::regex::icase),

        // Obfuscation and execution tricks
        std::regex(R"(eval\s*\(|ChrW?\(|fromCharCode|decodeURIComponent|unescape)", std::regex::icase),

        // Windows persistence
        std::regex(R"(Set-ExecutionPolicy|runonce|CurrentVersion\\Run|schtasks\.exe)", std::regex::icase),

        // Scripting languages or macros
        std::regex(R"(VBScript|CreateObject|GetObject|Shell\s*\()", std::regex::icase),

        // Credential or token stealing
        std::regex(R"((password|token|Authorization|Bearer)[^\\n]{0,40})", std::regex::icase)};

    for (const auto &pattern : patterns)
    {
        if (std::regex_search(content, pattern))
        {
            return true;
        }
    }
    return false;
}

std::string to_lower(const std::string &s)
{
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::tolower);
    return out;
}
void load_signatures(const std::string &filepath)
{

    known_signatures.clear();
    std::ifstream file(filepath);
    // std::cout << "done" << filepath;
    std::string line;
    if (!file.is_open())
    {
        std::cerr << "[ERROR] Cannot open signature file: " << filepath << "\n";
        return;
    }
    while (std::getline(file, line))
    {
        if (!line.empty())
            known_signatures.insert(to_lower(line));
    }
}

bool is_signature_matched(const std::string &hash)
{
    return known_signatures.find(hash) != known_signatures.end();
}
void cleanup_yara()
{
    if (yara_rules)
        yr_rules_destroy(yara_rules);

    yr_finalize();
}
bool load_yara_rules(const std::string &compiled_rules_path)
{
    if (yr_initialize() != ERROR_SUCCESS)
    {
        std::cerr << "[-] YARA init failed\n";
        return false;
    }

    if (yr_rules_load(compiled_rules_path.c_str(), &yara_rules) != ERROR_SUCCESS)
    {
        std::cerr << "[-] Failed to load compiled YARA rules: " << compiled_rules_path << "\n";
        return false;
    }

    std::cout << "[+] YARA rules loaded successfully\n";
    return true;
}

bool yara_scan_and_handle(const std::string &filepath)
{
    bool match_found = false;

    // Scan file using YARA
    int result = yr_rules_scan_file(
        yara_rules,
        filepath.c_str(),
        0, // no flags
        [](YR_SCAN_CONTEXT *context, int message, void *message_data, void *user_data) -> int
        {
            if (message == CALLBACK_MSG_RULE_MATCHING)
            {
                *(bool *)user_data = true;
            }
            return CALLBACK_CONTINUE;
        },
        &match_found,
        0);

    if (result != ERROR_SUCCESS || !match_found)
        return false; // No match

    // YARA matched: Quarantine

    return true;
}
ScanResult scan_file(const std::string &filepath)
{
    ScanResult res;
    res.file = filepath;
    res.sha256 = to_lower(sha256_file(filepath));
    auto data = read_file_binary(filepath);
    res.entropy = calculate_entropy(data);
    // bool result = scan_with_yara(file_path);
    std::string text(data.begin(), data.end());

    if (is_signature_matched(res.sha256))
    {
        std::vector<uint8_t> nonce, tag;
        res.result = "malware-signature-match";
        res.quarantined = true;

        // Encrypt + save
        auto enc = aes_gcm_encrypt(data, get_fixed_aes_key(), nonce, tag);
        save_encrypted_file("quarantine/" + get_filename(filepath) + ".enc", enc, nonce, tag);
        res.quarantined = true;
        std::filesystem::remove(filepath);
        return res;
    }

    if (matches_suspicious_patterns(text))
    {
        res.result = "heuristic-pattern-match";
        res.quarantined = true;

        std::vector<uint8_t> nonce, tag;
        auto enc = aes_gcm_encrypt(data, get_fixed_aes_key(), nonce, tag);
        save_encrypted_file("quarantine/" + get_filename(filepath) + ".enc", enc, nonce, tag);
        std::filesystem::remove(filepath);

        return res;
    }
    if (yara_scan_and_handle(filepath))
    {
        std::vector<uint8_t> nonce, tag;
        res.result = "malware-yara-match";
        res.quarantined = true;

        auto enc = aes_gcm_encrypt(data, get_fixed_aes_key(), nonce, tag);
        save_encrypted_file("quarantine/" + get_filename(filepath) + ".enc", enc, nonce, tag);
        std::filesystem::remove(filepath);

        return res;
    }

    if (res.entropy > 7.5)
    {
        res.result = "suspicious";
        std::vector<uint8_t> nonce, tag, key = get_fixed_aes_key();
        auto enc = aes_gcm_encrypt(data, key, nonce, tag);
        save_encrypted_file("quarantine/" + get_filename(filepath) + ".enc", enc, nonce, tag);
        std::filesystem::remove(filepath);
        res.quarantined = true;
    }
    else
    {
        res.result = "clean";
        res.quarantined = false;
    }

    return res;
}

std::string ScanResult::to_json() const
{
    return "{ \"file\": \"" + file + "\", \"sha256\": \"" + sha256 +
           "\", \"result\": \"" + result + "\", \"entropy\": " + std::to_string(entropy) +
           ", \"quarantined\": " + (quarantined ? "true" : "false") + " }";
}
