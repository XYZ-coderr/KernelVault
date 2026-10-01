/**
 * @file AtomicFileWriter.cpp
 * @brief Implementation of transactional atomic file persistence for kvault.
 */

#include "AtomicFileWriter.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <process.h>
#define getpid _getpid
#define posix_open _open
#define posix_write _write
#define posix_fsync _commit
#define posix_unlink _unlink
#ifndef O_BINARY
#define O_BINARY _O_BINARY
#endif
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#define posix_open ::open
#define posix_write ::write
#define posix_fsync ::fsync
#define posix_unlink ::unlink
#define O_BINARY 0

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#endif

#include <chrono>
#include <random>
#include <mutex>
#include <algorithm>
#include <system_error>
#include <cerrno>

namespace kvault {

namespace {

std::mutex g_registryMutex;
std::vector<std::string> g_activeTempFiles;

int callRenameat2(const char* oldpath, const char* newpath, unsigned int flags) {
#if defined(__linux__) && defined(SYS_renameat2)
    return static_cast<int>(::syscall(SYS_renameat2, AT_FDCWD, oldpath, AT_FDCWD, newpath, flags));
#else
    (void)flags;
    // Fallback: standard POSIX rename
    return ::rename(oldpath, newpath);
#endif
}

} // namespace

AtomicFileWriter::AtomicFileWriter(std::filesystem::path destinationPath, bool overwrite)
    : m_destPath(std::move(destinationPath)),
      m_overwrite(overwrite) {
    auto parent = m_destPath.parent_path();
    if (parent.empty()) {
        parent = std::filesystem::current_path();
    }

    // Generate unique temporary path in same directory
    const auto pid = getpid();
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    const uint64_t random_val = dist(gen);

    std::string tempFilename = "." + m_destPath.filename().string() +
                               ".tmp." + std::to_string(pid) +
                               "." + std::to_string(now) +
                               "." + std::to_string(random_val);

    m_tempPath = parent / tempFilename;
}

AtomicFileWriter::~AtomicFileWriter() noexcept {
    if (!m_committed) {
        abort();
    }
}

AtomicFileWriter::AtomicFileWriter(AtomicFileWriter&& other) noexcept
    : m_destPath(std::move(other.m_destPath)),
      m_tempPath(std::move(other.m_tempPath)),
      m_tempFd(std::move(other.m_tempFd)),
      m_committed(other.m_committed),
      m_overwrite(other.m_overwrite) {
    other.m_committed = true; // Prevents abort on moved-from instance
}

AtomicFileWriter& AtomicFileWriter::operator=(AtomicFileWriter&& other) noexcept {
    if (this != &other) {
        if (!m_committed) {
            abort();
        }
        m_destPath = std::move(other.m_destPath);
        m_tempPath = std::move(other.m_tempPath);
        m_tempFd = std::move(other.m_tempFd);
        m_committed = other.m_committed;
        m_overwrite = other.m_overwrite;

        other.m_committed = true;
    }
    return *this;
}

bool AtomicFileWriter::open() {
    if (m_tempFd.valid()) {
        return true;
    }

    // Ensure parent directory exists
    const auto parent = m_tempPath.parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent)) {
        std::error_code ec;
        if (!std::filesystem::create_directories(parent, ec) && ec) {
            return false;
        }
    }

    // Strictly enforce 0600 (S_IRUSR | S_IWUSR) permissions
#if defined(_WIN32) || defined(_WIN64)
    int fd = posix_open(m_tempPath.string().c_str(),
                        _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                        _S_IREAD | _S_IWRITE);
#else
    int fd = posix_open(m_tempPath.c_str(),
                        O_WRONLY | O_CREAT | O_EXCL | O_BINARY,
                        S_IRUSR | S_IWUSR);
#endif

    if (fd < 0) {
        return false;
    }

    m_tempFd.reset(fd);
    m_committed = false;
    registerTempFile();
    return true;
}

bool AtomicFileWriter::write(std::span<const uint8_t> buffer) {
    if (!m_tempFd.valid()) {
        if (!open()) {
            return false;
        }
    }

    const uint8_t* ptr = buffer.data();
    size_t remaining = buffer.size();

    while (remaining > 0) {
#if defined(_WIN32) || defined(_WIN64)
        int written = posix_write(m_tempFd.get(), ptr, static_cast<unsigned int>(remaining));
#else
        ssize_t written = posix_write(m_tempFd.get(), ptr, remaining);
#endif
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        ptr += written;
        remaining -= static_cast<size_t>(written);
    }

    return true;
}

bool AtomicFileWriter::commit() {
    if (!m_tempFd.valid()) {
        return false;
    }

    // 1. Flush volatile drive cache & write dirty pages to storage hardware
    if (posix_fsync(m_tempFd.get()) != 0) {
        abort();
        return false;
    }

    // 2. Close temporary file descriptor before renaming
    m_tempFd.reset(-1);

    // 3. Atomically rename temporary file to destination path
    unsigned int flags = m_overwrite ? 0 : RENAME_NOREPLACE;
    int res = callRenameat2(m_tempPath.string().c_str(), m_destPath.string().c_str(), flags);

    if (res != 0) {
        // Fallback to std::filesystem::rename if renameat2 returned ENOSYS
        if (errno == ENOSYS || errno == EINVAL) {
            std::error_code ec;
            std::filesystem::rename(m_tempPath, m_destPath, ec);
            if (ec) {
                abort();
                return false;
            }
        } else {
            abort();
            return false;
        }
    }

    // 4. Flush parent directory metadata so rename persists across crashes
    syncParentDirectory();

    m_committed = true;
    unregisterTempFile();
    return true;
}

void AtomicFileWriter::abort() noexcept {
    m_tempFd.reset(-1);

    if (!m_tempPath.empty()) {
        std::error_code ec;
        std::filesystem::remove(m_tempPath, ec);
    }

    unregisterTempFile();
    m_committed = true;
}

const std::filesystem::path& AtomicFileWriter::getTempPath() const noexcept {
    return m_tempPath;
}

const std::filesystem::path& AtomicFileWriter::getDestinationPath() const noexcept {
    return m_destPath;
}

void AtomicFileWriter::registerTempFile() {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    g_activeTempFiles.push_back(m_tempPath.string());
}

void AtomicFileWriter::unregisterTempFile() noexcept {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    auto it = std::find(g_activeTempFiles.begin(), g_activeTempFiles.end(), m_tempPath.string());
    if (it != g_activeTempFiles.end()) {
        g_activeTempFiles.erase(it);
    }
}

bool AtomicFileWriter::syncParentDirectory() const {
#if !defined(_WIN32) && !defined(_WIN64)
    auto parent = m_destPath.parent_path();
    if (parent.empty()) {
        parent = ".";
    }

    int dir_fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY);
    if (dir_fd >= 0) {
        ::fsync(dir_fd);
        ::close(dir_fd);
        return true;
    }
#endif
    return true;
}

void AtomicFileWriter::cleanupAllTemporaryFiles() noexcept {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    for (const auto& path : g_activeTempFiles) {
        posix_unlink(path.c_str());
    }
    g_activeTempFiles.clear();
}

} // namespace kvault
