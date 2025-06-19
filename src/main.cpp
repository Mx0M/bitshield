#include <iostream>
#include <filesystem>
#include "scanner.h"
#include "utils.h"
#include "threadpool.h"

void scan_files_multithreaded(const std::vector<std::string> &files)
{
    size_t thread_count = std::thread::hardware_concurrency();
    ThreadPool pool(thread_count == 0 ? 4 : thread_count);

    std::vector<std::future<void>> results;
    for (const auto &file : files)
    {
        results.emplace_back(pool.enqueue([file]()
                                          {
                                              auto result = scan_file(file); // your existing function
                                              std::cout << result.to_json() << std::endl;
                                              ; // optional logging
                                          }));
    }

    // Wait for all to finish
    for (auto &f : results)
        f.get();
}
int main(int argc, char *argv[])
{

    std::cout << "BBBBBBBBBBBBBBBBB   IIIIIIIIIITTTTTTTTTTTTTTTTTTTTTTT   SSSSSSSSSSSSSSS HHHHHHHHH     HHHHHHHHHIIIIIIIIIIEEEEEEEEEEEEEEEEEEEEEELLLLLLLLLLL             DDDDDDDDDDDDD";
    std::cout << "B::::::::::::::::B  I::::::::IT:::::::::::::::::::::T SS:::::::::::::::SH:::::::H     H:::::::HI::::::::IE::::::::::::::::::::EL:::::::::L             D::::::::::::DDD";
    std::cout << "B::::::BBBBBB:::::B I::::::::IT:::::::::::::::::::::TS:::::SSSSSS::::::SH:::::::H     H:::::::HI::::::::IE::::::::::::::::::::EL:::::::::L             D:::::::::::::::DD";
    std::cout << "BB:::::B     B:::::BII::::::IIT:::::TT:::::::TT:::::TS:::::S     SSSSSSSHH::::::H     H::::::HHII::::::IIEE::::::EEEEEEEEE::::ELL:::::::LL             DDD:::::DDDDD:::::D";
    std::cout << "B::::B     B:::::B  I::::I  TTTTTT  T:::::T  TTTTTTS:::::S              H:::::H     H:::::H    I::::I    E:::::E       EEEEEE  L:::::L                 D:::::D    D:::::D";
    std::cout << "B::::B     B:::::B  I::::I          T:::::T        S:::::S              H:::::H     H:::::H    I::::I    E:::::E               L:::::L                 D:::::D     D:::::D";
    std::cout << "B::::BBBBBB:::::B   I::::I          T:::::T         S::::SSSS           H::::::HHHHH::::::H    I::::I    E::::::EEEEEEEEEE     L:::::L                 D:::::D     D:::::D";
    std::cout << "B:::::::::::::BB    I::::I          T:::::T          SS::::::SSSSS      H:::::::::::::::::H    I::::I    E:::::::::::::::E     L:::::L                 D:::::D     D:::::D";
    std::cout << "B::::BBBBBB:::::B   I::::I          T:::::T            SSS::::::::SS    H:::::::::::::::::H    I::::I    E:::::::::::::::E     L:::::L                 D:::::D     D:::::D";
    std::cout << "B::::B     B:::::B  I::::I          T:::::T               SSSSSS::::S   H::::::HHHHH::::::H    I::::I    E::::::EEEEEEEEEE     L:::::L                 D:::::D     D:::::D";
    std::cout << "B::::B     B:::::B  I::::I          T:::::T                    S:::::S  H:::::H     H:::::H    I::::I    E:::::E               L:::::L                 D:::::D     D:::::D";
    std::cout << "B::::B     B:::::B  I::::I          T:::::T                    S:::::S  H:::::H     H:::::H    I::::I    E:::::E       EEEEEE  L:::::L         LLLLLL  D:::::D    D:::::D";
    std::cout << "BB:::::BBBBBB::::::BII::::::II      TT:::::::TT      SSSSSSS     S:::::SHH::::::H     H::::::HHII::::::IIEE::::::EEEEEEEE:::::ELL:::::::LLLLLLLLL:::::LDDD:::::DDDDD:::::D";
    std::cout << "B:::::::::::::::::B I::::::::I      T:::::::::T      S::::::SSSSSS:::::SH:::::::H     H:::::::HI::::::::IE::::::::::::::::::::EL::::::::::::::::::::::LD:::::::::::::::DD";
    std::cout << "B::::::::::::::::B  I::::::::I      T:::::::::T      S:::::::::::::::SS H:::::::H     H:::::::HI::::::::IE::::::::::::::::::::EL::::::::::::::::::::::LD::::::::::::DDD";
    std::cout << "BBBBBBBBBBBBBBBBB   IIIIIIIIII      TTTTTTTTTTT       SSSSSSSSSSSSSSS   HHHHHHHHH     HHHHHHHHHIIIIIIIIIIEEEEEEEEEEEEEEEEEEEEEELLLLLLLLLLLLLLLLLLLLLLLLDDDDDDDDDDDDD";

    if (argc >= 3 && std::string(argv[1]) == "--restore")
    {
        std::string enc_path = argv[2];
        std::string rest_path = argv[3];
        restore_file(enc_path, rest_path);
        return 0;
    }

    load_signatures("signatures/signatures.txt"); // make this configurable later
    load_yara_rules("signatures/compiles_rules.yarc");

    if (argc < 2)
    {
        std::cerr << "Usage: AVScanner <file_or_folder_path>" << std::endl;
        return 1;
    }

    std::string path = argv[1];
    std::vector<std::string> files = collect_files(path);
    scan_files_multithreaded(files);
    // for (const auto &file : files)
    // {
    //     ScanResult result = scan_file(file);
    //     std::cout << result.to_json() << std::endl;
    // }

    cleanup_yara();

    return 0;
}
