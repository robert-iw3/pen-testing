#pragma once
#include <Windows.h>

#include <stdexcept>
#include <string_view>

namespace shared {
    constexpr std::string_view kSegName = "defender-disabler-ipc";

    enum class InterProcessCommunicationMode : std::uint8_t {
        READ = 0,
        WRITE,
        READ_WRITE,
    };

    class InterProcessCommunication {
        class Data {
        public:
            bool finished = false;
            bool success = false;
        };
        static_assert(std::is_trivially_copyable_v<Data>);

    public:
        explicit InterProcessCommunication(InterProcessCommunicationMode mode, bool should_create = false): mode_(mode), was_created_(should_create) {
            int flag = mode == InterProcessCommunicationMode::READ       ? FILE_MAP_READ :
                       mode == InterProcessCommunicationMode::READ_WRITE ? FILE_MAP_ALL_ACCESS :
                                                                           FILE_MAP_WRITE;

            if (should_create) {
                setup_handle(CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(Data), kSegName.data()));
            } else {
                setup_handle(OpenFileMappingA(flag, FALSE, kSegName.data()));
            }

            data_ = reinterpret_cast<Data*>(MapViewOfFile(handle_, flag, 0, 0, sizeof(Data)));
            if (data_ == nullptr) {
                throw std::runtime_error("unable to map ipc");
            }
        }

        ~InterProcessCommunication() {
            if (data_ != nullptr && was_created_ &&
                (mode_ == InterProcessCommunicationMode::WRITE || mode_ == InterProcessCommunicationMode::READ_WRITE)) {
                /// Erase all data
                std::memset(data_, 0, sizeof(*data_));
            }

            if (data_ != nullptr) {
                UnmapViewOfFile(data_);
                data_ = nullptr;
            }

            if (handle_ != INVALID_HANDLE_VALUE) {
                CloseHandle(handle_);
                handle_ = INVALID_HANDLE_VALUE;
            }
        }

        [[nodiscard]] Data* operator->() noexcept {
            return data_;
        }

    private:
        void setup_handle(HANDLE handle) {
            handle_ = handle;
            valid_ = handle_ != INVALID_HANDLE_VALUE;
            throw_if_invalid();
        }

        void throw_if_invalid() const {
            if (!valid_) {
                throw std::runtime_error("unable to access ipc seg");
            }
        }

        HANDLE handle_ = INVALID_HANDLE_VALUE;
        bool valid_ = false;
        Data* data_ = nullptr;
        InterProcessCommunicationMode mode_;
        bool was_created_;
    };
} // namespace shared