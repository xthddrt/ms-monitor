#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "../include/msmon_protocol.h"

static std::atomic<bool> gStop(false);

static BOOL WINAPI ConsoleHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        gStop.store(true);
        return TRUE;
    }
    return FALSE;
}

static std::string WideToUtf8(const wchar_t* value)
{
    if (value == nullptr || *value == L'\0') return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) return {};
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), size, nullptr, nullptr);
    result.resize(static_cast<size_t>(size - 1));
    return result;
}

static std::string JsonEscape(const std::string& value)
{
    std::ostringstream output;
    for (unsigned char c : value) {
        switch (c) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (c < 0x20) {
                output << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(c)
                       << std::dec << std::setfill(' ');
            } else {
                output << static_cast<char>(c);
            }
        }
    }
    return output.str();
}

static const char* EventTypeName(unsigned long type)
{
    switch (type) {
    case MsMonProcessStart: return "process_start";
    case MsMonProcessExit: return "process_exit";
    case MsMonThreadStart: return "thread_start";
    case MsMonThreadExit: return "thread_exit";
    case MsMonImageLoad: return "image_load";
    case MsMonFileCreate: return "file_create";
    case MsMonFileRead: return "file_read";
    case MsMonFileWrite: return "file_write";
    case MsMonFileSetInformation: return "file_set_information";
    case MsMonRegistryOpen: return "registry_open";
    case MsMonRegistryCreate: return "registry_create";
    case MsMonRegistrySetValue: return "registry_set_value";
    case MsMonRegistryDelete: return "registry_delete";
    case MsMonRegistryRename: return "registry_rename";
    case MsMonRegistryQuery: return "registry_query";
    case MsMonRegistryEnumerate: return "registry_enumerate";
    case MsMonNetworkConnect: return "network_connect";
    case MsMonNetworkAccept: return "network_accept";
    default: return "unknown";
    }
}

static std::string Timestamp(uint64_t value)
{
    FILETIME fileTime{};
    SYSTEMTIME systemTime{};
    fileTime.dwLowDateTime = static_cast<DWORD>(value & 0xffffffff);
    fileTime.dwHighDateTime = static_cast<DWORD>(value >> 32);
    if (!FileTimeToSystemTime(&fileTime, &systemTime)) return {};
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  systemTime.wYear, systemTime.wMonth, systemTime.wDay,
                  systemTime.wHour, systemTime.wMinute, systemTime.wSecond, systemTime.wMilliseconds);
    return buffer;
}

static std::string Sha256(const std::string& input)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD resultSize = 0;
    std::vector<unsigned char> object;
    unsigned char digest[32];
    std::ostringstream hex;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
                          sizeof(objectSize), &resultSize, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }
    object.resize(objectSize);
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) != 0 ||
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                       static_cast<ULONG>(input.size()), 0) != 0 ||
        BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0) {
        if (hash != nullptr) BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    hex << std::hex << std::setfill('0');
    for (unsigned char byte : digest) hex << std::setw(2) << static_cast<unsigned>(byte);
    return hex.str();
}

class JsonlWriter {
public:
    explicit JsonlWriter(std::string basePath, uint64_t maximumBytes)
        : basePath_(std::move(basePath)), maximumBytes_(maximumBytes), chain_(64, '0') {}

    bool Open()
    {
        stream_.open(basePath_, std::ios::binary | std::ios::trunc);
        bytes_ = 0;
        return static_cast<bool>(stream_);
    }

    bool Write(std::string json)
    {
        if (maximumBytes_ != 0 && bytes_ > maximumBytes_) {
            stream_.close();
            std::ostringstream rotated;
            rotated << basePath_ << "." << ++part_;
            stream_.open(rotated.str(), std::ios::binary | std::ios::trunc);
            if (!stream_) return false;
            bytes_ = 0;
        }
        std::string chainedInput = chain_ + json;
        chain_ = Sha256(chainedInput);
        if (chain_.empty()) return false;
        std::string line = json.substr(0, json.size() - 1) + ",\"chain\":\"" + chain_ + "\"}\n";
        stream_.write(line.data(), static_cast<std::streamsize>(line.size()));
        stream_.flush();
        bytes_ += line.size();
        return static_cast<bool>(stream_);
    }

private:
    std::string basePath_;
    uint64_t maximumBytes_;
    uint64_t bytes_ = 0;
    unsigned part_ = 0;
    std::ofstream stream_;
    std::string chain_;
};

static std::string EventJson(const MSMON_EVENT& event)
{
    std::ostringstream json;
    json << "{\"protocol\":" << event.Version
         << ",\"sequence\":" << event.Sequence
         << ",\"timestamp\":\"" << Timestamp(event.Timestamp)
         << "\",\"type\":\"" << EventTypeName(event.Type)
         << "\",\"type_id\":" << event.Type
         << ",\"process_id\":" << event.ProcessId
         << ",\"parent_process_id\":" << event.ParentProcessId
         << ",\"thread_id\":" << event.ThreadId
         << ",\"flags\":" << event.Flags
         << ",\"status\":" << event.Status
         << ",\"value0\":" << event.Value0
         << ",\"value1\":" << event.Value1
         << ",\"text\":\"" << JsonEscape(WideToUtf8(event.Text))
         << "\",\"detail\":\"" << JsonEscape(WideToUtf8(event.Detail)) << "\"}";
    return json.str();
}

static bool TrackPid(HANDLE device, DWORD pid)
{
    DWORD bytes = 0;
    return DeviceIoControl(device, MSMON_IOCTL_TRACK_PID, &pid, sizeof(pid), nullptr, 0, &bytes, nullptr) != 0;
}

static unsigned TrackExistingClientProcesses(HANDLE device)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry{};
    unsigned tracked = 0;
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"MapleStory.exe") == 0 ||
                _wcsicmp(entry.szExeFile, L"NGService.exe") == 0 ||
                _wcsicmp(entry.szExeFile, L"DwarfAxe.exe") == 0 ||
                _wcsicmp(entry.szExeFile, L"CrashReportClient.exe") == 0) {
                if (TrackPid(device, entry.th32ProcessID)) tracked++;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return tracked;
}

static std::string DefaultOutputPath()
{
    SYSTEMTIME time{};
    GetLocalTime(&time);
    char path[128];
    std::snprintf(path, sizeof(path), "msmon-%04u%02u%02u-%02u%02u%02u.jsonl",
                  time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
    return path;
}

static void Usage()
{
    std::cout << "Usage: msmon-agent [--output FILE] [--pid PID] [--wait-ms N] "
                 "[--max-file-mb N] [--once]\n";
}

int wmain(int argc, wchar_t** argv)
{
    std::string output = DefaultOutputPath();
    unsigned long waitMs = 500;
    uint64_t maxFileBytes = 64ull * 1024ull * 1024ull;
    bool once = false;
    std::vector<DWORD> explicitPids;

    for (int index = 1; index < argc; index++) {
        std::wstring argument = argv[index];
        if (argument == L"--help" || argument == L"-h") {
            Usage();
            return 0;
        } else if (argument == L"--once") {
            once = true;
        } else if (index + 1 < argc && argument == L"--output") {
            output = WideToUtf8(argv[++index]);
        } else if (index + 1 < argc && argument == L"--wait-ms") {
            waitMs = std::wcstoul(argv[++index], nullptr, 10);
        } else if (index + 1 < argc && argument == L"--max-file-mb") {
            maxFileBytes = std::wcstoull(argv[++index], nullptr, 10) * 1024ull * 1024ull;
        } else if (index + 1 < argc && argument == L"--pid") {
            explicitPids.push_back(std::wcstoul(argv[++index], nullptr, 10));
        } else {
            Usage();
            return 2;
        }
    }

    HANDLE device = CreateFileA(MSMON_USER_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        std::cerr << "Cannot open " << MSMON_USER_DEVICE_PATH << ": Win32 error " << GetLastError()
                  << ". Build and test-load the driver in an isolated test VM first.\n";
        return 1;
    }
    std::cout << "Registered " << TrackExistingClientProcesses(device) << " running client processes.\n";
    for (DWORD pid : explicitPids) {
        if (!TrackPid(device, pid)) std::cerr << "Could not track PID " << pid << ".\n";
    }

    JsonlWriter writer(output, maxFileBytes);
    if (!writer.Open()) {
        std::cerr << "Cannot open output log.\n";
        CloseHandle(device);
        return 1;
    }
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    std::cout << "Writing " << output << "\n";

    uint64_t previousSequence = 0;
    uint64_t totalEvents = 0;
    uint64_t totalGaps = 0;
    do {
        MSMON_READ_REQUEST request{waitMs, MSMON_READ_MAX_EVENTS};
        MSMON_EVENT events[MSMON_READ_MAX_EVENTS];
        DWORD bytes = 0;
        BOOL ok = DeviceIoControl(device, MSMON_IOCTL_READ_EVENTS, &request, sizeof(request),
                                  events, sizeof(events), &bytes, nullptr);
        if (!ok) {
            std::cerr << "Read failed: Win32 error " << GetLastError() << "\n";
            CloseHandle(device);
            return 1;
        }
        if (bytes % sizeof(MSMON_EVENT) != 0) {
            std::cerr << "Driver returned a partial event.\n";
            CloseHandle(device);
            return 1;
        }
        unsigned count = bytes / sizeof(MSMON_EVENT);
        for (unsigned index = 0; index < count; index++) {
            const MSMON_EVENT& event = events[index];
            if (event.Size != sizeof(MSMON_EVENT) || event.Version != MSMON_PROTOCOL_VERSION) {
                std::cerr << "Protocol version mismatch.\n";
                CloseHandle(device);
                return 1;
            }
            if (previousSequence != 0 && event.Sequence > previousSequence + 1) {
                uint64_t gap = event.Sequence - previousSequence - 1;
                totalGaps += gap;
                std::ostringstream json;
                json << "{\"type\":\"observer_sequence_gap\",\"after_sequence\":" << previousSequence
                     << ",\"before_sequence\":" << event.Sequence << ",\"missing_events\":" << gap << "}";
                if (!writer.Write(json.str())) return 1;
            }
            if (!writer.Write(EventJson(event))) {
                std::cerr << "Could not write log.\n";
                CloseHandle(device);
                return 1;
            }
            previousSequence = event.Sequence;
            totalEvents++;
        }
    } while (!once && !gStop.load());

    MSMON_STATISTICS statistics{};
    DWORD bytes = 0;
    if (DeviceIoControl(device, MSMON_IOCTL_STATISTICS, nullptr, 0,
                        &statistics, sizeof(statistics), &bytes, nullptr)) {
        std::cout << "Events written: " << totalEvents << "; sequence gaps: " << totalGaps
                  << "; driver drops: " << statistics.DroppedEvents << "\n";
    }
    CloseHandle(device);
    return 0;
}
