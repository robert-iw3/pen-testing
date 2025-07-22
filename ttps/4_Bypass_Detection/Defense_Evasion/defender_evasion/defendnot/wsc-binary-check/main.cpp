#include <Windows.h>
#include <winternl.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <print>
#include <ranges>
#include <set>

#include "shared/defer.hpp"

#pragma comment(lib, "Crypt32.lib")

namespace {
    constexpr std::string_view kTargetDirectory = "c:\\Windows\\System32";
    /* constexpr */ auto kTargetFileExts = std::set<std::string_view>{".exe"};

    constexpr std::uint16_t kDosMagic = 0x5A4D;
    constexpr std::uint32_t kNtSignature = 0x00004550;
    constexpr std::uint16_t kARM64Machine = 0xAA64;
    constexpr std::uint16_t kAMD64Machine = 0x8664;
    constexpr std::uint16_t kI386Machine = 0x014C;
    constexpr std::uint16_t kDllCharacteristicsForceIntegrityMask = 0x80;

    [[nodiscard]] std::optional<std::vector<std::uint8_t>> read_file(const std::filesystem::path path) {
        std::ifstream file(path, std::ios::binary);
        if (!file.good()) {
            return std::nullopt;
        }

        const auto size = std::filesystem::file_size(path);
        std::vector<std::uint8_t> buffer(size);

        file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        return buffer;
    }

    [[nodiscard]] bool check_characteristics(const std::span<std::uint8_t> data) {
        if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
            throw std::runtime_error("got invalid pe image");
        }

        const auto p_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(data.data());
        if (p_dos->e_magic != kDosMagic) {
            throw std::runtime_error("got invalid pe image (2)");
        }

        const auto p_nt = reinterpret_cast<PIMAGE_NT_HEADERS>(data.data() + p_dos->e_lfanew);
        if (p_nt->Signature != kNtSignature) {
            throw std::runtime_error("got invalid pe image (3)");
        }

        const auto machine = p_nt->FileHeader.Machine;
        std::uint16_t characteristics;

        if (machine == kARM64Machine || machine == kAMD64Machine) {
            characteristics = reinterpret_cast<PIMAGE_NT_HEADERS64>(p_nt)->OptionalHeader.DllCharacteristics;
        } else if (machine == kI386Machine) {
            characteristics = reinterpret_cast<PIMAGE_NT_HEADERS32>(p_nt)->OptionalHeader.DllCharacteristics;
        } else {
            throw std::runtime_error(std::format("unsupported machine: {:#x}", machine));
        }

        return (characteristics & kDllCharacteristicsForceIntegrityMask) != 0;
    }

    [[nodiscard]] bool check_signature(const std::filesystem::path path) {
        HCERTSTORE store = {0};
        HCRYPTMSG msg = {0};
        if (!CryptQueryObject(1, path.wstring().c_str(), 0x400, 0xE, 0, nullptr, nullptr, nullptr, &store, &msg, nullptr) //
            || !store || !msg) {
            /// Most likely the binary is just not signed
            return false;
        }

        defer->void {
            CryptMsgClose(msg);
            CertCloseStore(store, 1);
        };

        PCCERT_CONTEXT signer = nullptr;
        if (!CryptMsgGetAndVerifySigner(msg, 0, nullptr, 2, &signer, nullptr) || signer == nullptr) {
            throw std::runtime_error(std::format("CryptMsgGetAndVerifySigner() on {}", path.string()));
        }

        defer->void {
            CertFreeCertificateContext(signer);
        };

        /// I don't think we have to do something with signer?
        return true;
    }
} // namespace

int main() try {
    for (auto& entry : std::filesystem::recursive_directory_iterator(kTargetDirectory, std::filesystem::directory_options::skip_permission_denied)) {
        auto path = entry.path();
        auto ext = path.extension().string() //
                   | std::views::transform([](const char c) -> char { return ::tolower(c); }) //
                   | std::ranges::to<std::string>();

        if (!kTargetFileExts.contains(ext)) {
            continue;
        }

        auto file = read_file(path);
        if (!file.has_value()) {
            std::println(stderr, "unable to read {}", path.string());
            continue;
        }

        const std::span file_ptr = *file;
        if (!check_characteristics(file_ptr)) {
            continue;
        }

        if (!check_signature(path)) {
            continue;
        }

        std::println("matches: {}", path.string());
    }

    return EXIT_SUCCESS;
} catch (const std::exception& e) {
    std::println(stderr, "fatal error: {}", e.what());
    return EXIT_FAILURE;
}
