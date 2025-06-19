#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>

struct ScanResult
{
    std::string file;
    std::string sha256;
    std::string result;
    double entropy;
    bool quarantined;

    std::string to_json() const;
};

ScanResult scan_file(const std::string &filepath);
std::vector<std::string> collect_files(const std::string &path);
void load_signatures(const std::string &filepath);
bool load_yara_rules(const std::string &compiled_rules_path);
bool is_signature_matched(const std::string &hash);
void cleanup_yara();
#endif
