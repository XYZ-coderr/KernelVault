/**
 * @file test_unique_fd.cpp
 * @brief Google Test suite for C++20 UniqueFd RAII wrapper in kvault.
 */

#include "UniqueFd.hpp"
#include <gtest/gtest.h>

#if defined(_WIN32) || defined(_WIN64)
#include <io.h>
#include <fcntl.h>
#define posix_close _close
#else
#include <unistd.h>
#include <fcntl.h>
#define posix_close ::close
#endif

using namespace kvault;

TEST(UniqueFdTest, DefaultConstructorIsInvalid) {
    UniqueFd ufd;
    EXPECT_EQ(ufd.get(), -1);
    EXPECT_FALSE(ufd.valid());
    EXPECT_FALSE(static_cast<bool>(ufd));
}

TEST(UniqueFdTest, ConstructorAdoptsDescriptor) {
#if !defined(_WIN32) && !defined(_WIN64)
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);

    UniqueFd readFd(fds[0]);
    UniqueFd writeFd(fds[1]);

    EXPECT_TRUE(readFd.valid());
    EXPECT_TRUE(writeFd.valid());
    EXPECT_EQ(readFd.get(), fds[0]);
    EXPECT_EQ(writeFd.get(), fds[1]);
#else
    UniqueFd ufd(42);
    EXPECT_EQ(ufd.get(), 42);
    EXPECT_TRUE(ufd.valid());
    ufd.release();
#endif
}

TEST(UniqueFdTest, DestructorClosesDescriptor) {
#if !defined(_WIN32) && !defined(_WIN64)
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);
    int rawRead = fds[0];

    {
        UniqueFd scopedFd(rawRead);
        EXPECT_TRUE(scopedFd.valid());
    } // scopedFd destroyed here

    // ::close should now fail with EBADF since UniqueFd already closed it
    EXPECT_EQ(::close(rawRead), -1);
    EXPECT_EQ(errno, EBADF);

    posix_close(fds[1]);
#else
    SUCCEED();
#endif
}

TEST(UniqueFdTest, MoveSemanticsTransferOwnership) {
#if !defined(_WIN32) && !defined(_WIN64)
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);

    UniqueFd ufd1(fds[0]);
    int raw = ufd1.get();

    UniqueFd ufd2(std::move(ufd1));
    EXPECT_FALSE(ufd1.valid());
    EXPECT_EQ(ufd1.get(), -1);
    EXPECT_TRUE(ufd2.valid());
    EXPECT_EQ(ufd2.get(), raw);

    UniqueFd ufd3;
    ufd3 = std::move(ufd2);
    EXPECT_FALSE(ufd2.valid());
    EXPECT_TRUE(ufd3.valid());
    EXPECT_EQ(ufd3.get(), raw);

    posix_close(fds[1]);
#else
    UniqueFd ufd1(10);
    UniqueFd ufd2(std::move(ufd1));
    EXPECT_FALSE(ufd1.valid());
    EXPECT_EQ(ufd2.get(), 10);
    ufd2.release();
#endif
}

TEST(UniqueFdTest, ReleaseRelinquishesOwnership) {
#if !defined(_WIN32) && !defined(_WIN64)
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);

    int rawRead = fds[0];
    {
        UniqueFd ufd(rawRead);
        int released = ufd.release();
        EXPECT_EQ(released, rawRead);
        EXPECT_FALSE(ufd.valid());
    } // Destruction should NOT close released descriptor

    // Closing rawRead should succeed
    EXPECT_EQ(::close(rawRead), 0);
    posix_close(fds[1]);
#else
    UniqueFd ufd(100);
    int rel = ufd.release();
    EXPECT_EQ(rel, 100);
    EXPECT_FALSE(ufd.valid());
#endif
}
