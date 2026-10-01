/**
 * @file AtomicFileWriter.hpp
 * @brief Manages transactional, power-failure-safe file persistence.
 *
 * Implements atomic temporary staging, fsync hardware cache flushing,
 * POSIX 0600 permissions, renameat2 atomic replacement, and signal-safe cleanup.
 */

#ifndef ATOMIC_FILE_WRITER_HPP
#define ATOMIC_FILE_WRITER_HPP

#include "UniqueFd.hpp"

#include <filesystem>
#include <span>
#include <vector>
#include <string>

namespace kvault {

/**
 * @class AtomicFileWriter
 * @brief Transactional file writer guaranteeing all-or-nothing disk writes.
 */
class AtomicFileWriter {
public:
    /**
     * @brief Constructs an AtomicFileWriter for a specified target path.
     * @param destinationPath Final destination path for the completed file.
     * @param overwrite If true, allows replacing existing destination file.
     */
    explicit AtomicFileWriter(std::filesystem::path destinationPath, bool overwrite = true);

    /**
     * @brief Destructor. Automatically cleans up uncommitted temporary files.
     */
    ~AtomicFileWriter() noexcept;

    // Move-only semantics
    AtomicFileWriter(const AtomicFileWriter&) = delete;
    AtomicFileWriter& operator=(const AtomicFileWriter&) = delete;
    AtomicFileWriter(AtomicFileWriter&& other) noexcept;
    AtomicFileWriter& operator=(AtomicFileWriter&& other) noexcept;

    /**
     * @brief Opens the temporary staging file with 0600 permissions.
     * @return True if initialized successfully, false otherwise.
     */
    bool open();

    /**
     * @brief Appends binary data to the temporary staging file.
     * @param buffer Non-owning span of bytes to write.
     * @return True if all bytes were written successfully, false otherwise.
     */
    bool write(std::span<const uint8_t> buffer);

    /**
     * @brief Flushes hardware cache (fsync) and atomically commits the file.
     * @return True on successful atomic rename and sync, false otherwise.
     */
    bool commit();

    /**
     * @brief Aborts the write transaction and deletes the temporary file.
     */
    void abort() noexcept;

    /**
     * @brief Gets the path to the temporary staging file.
     */
    [[nodiscard]] const std::filesystem::path& getTempPath() const noexcept;

    /**
     * @brief Gets the path to the final destination file.
     */
    [[nodiscard]] const std::filesystem::path& getDestinationPath() const noexcept;

    /**
     * @brief Signal-handler hook to clean up any registered active temporary files.
     */
    static void cleanupAllTemporaryFiles() noexcept;

private:
    std::filesystem::path m_destPath;
    std::filesystem::path m_tempPath;
    UniqueFd m_tempFd;
    bool m_committed{false};
    bool m_overwrite{true};

    void registerTempFile();
    void unregisterTempFile() noexcept;
    bool syncParentDirectory() const;
};

} // namespace kvault

namespace secstore = kvault;

#endif // ATOMIC_FILE_WRITER_HPP
