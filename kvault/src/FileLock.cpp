/**
 * @file FileLock.cpp
 * @brief Implementation of POSIX fcntl advisory file locking for kvault.
 */

#include "FileLock.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cerrno>
#include <cstring>

namespace kvault {

FileLock::FileLock(int fd, LockType type, LockMode mode) {
    acquire(fd, type, mode);
}

FileLock::~FileLock() noexcept {
    unlock();
}

FileLock::FileLock(FileLock&& other) noexcept
    : m_fd(other.m_fd),
      m_locked(other.m_locked),
      m_type(other.m_type) {
    other.m_fd = -1;
    other.m_locked = false;
}

FileLock& FileLock::operator=(FileLock&& other) noexcept {
    if (this != &other) {
        unlock();
        m_fd = other.m_fd;
        m_locked = other.m_locked;
        m_type = other.m_type;

        other.m_fd = -1;
        other.m_locked = false;
    }
    return *this;
}

bool FileLock::acquire(int fd, LockType type, LockMode mode) {
    if (fd < 0) {
        return false;
    }

    if (m_locked) {
        unlock();
    }

#if defined(F_SETLK) && defined(F_SETLKW)
    struct flock fl{};
    fl.l_type = (type == LockType::Shared) ? F_RDLCK : F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0; /* 0 indicates lock covers entire file to EOF */

    int cmd = (mode == LockMode::Blocking) ? F_SETLKW : F_SETLK;
    int res = ::fcntl(fd, cmd, &fl);
    if (res == 0) {
        m_fd = fd;
        m_locked = true;
        m_type = type;
        return true;
    }
    return false;
#else
    // Non-POSIX mock fallback
    m_fd = fd;
    m_locked = true;
    m_type = type;
    (void)mode;
    return true;
#endif
}

bool FileLock::unlock() noexcept {
    if (!m_locked || m_fd < 0) {
        return false;
    }

#if defined(F_SETLK)
    struct flock fl{};
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    int res = ::fcntl(m_fd, F_SETLK, &fl);
    m_locked = false;
    m_fd = -1;
    return (res == 0);
#else
    m_locked = false;
    m_fd = -1;
    return true;
#endif
}

bool FileLock::isLocked() const noexcept {
    return m_locked;
}

FileLock::LockType FileLock::getType() const noexcept {
    return m_type;
}

std::optional<pid_t> FileLock::testLock(int fd, LockType type) {
    if (fd < 0) {
        return std::nullopt;
    }

#if defined(F_GETLK)
    struct flock fl{};
    fl.l_type = (type == LockType::Shared) ? F_RDLCK : F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    if (::fcntl(fd, F_GETLK, &fl) == 0) {
        if (fl.l_type != F_UNLCK) {
            return fl.l_pid;
        }
    }
#else
    (void)type;
#endif

    return std::nullopt;
}

} // namespace kvault
