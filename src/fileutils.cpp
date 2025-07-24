/*
 *  Copyright (C) 2004-2025 Savoir-faire Linux Inc.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "fileutils.h"

#include <opendht/crypto.h>

#ifdef RING_UWP
#include <io.h> // for access and close
#endif

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include "string_utils.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#ifndef _MSC_VER
#include <libgen.h>
#endif
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <sstream>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <limits>
#include <array>
#include <filesystem>

#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstddef>
#include <ciso646>


#define ERASE_BLOCK 4096

namespace dhtnet {
namespace fileutils {

// returns true if directory exists or was created
bool
check_dir(const std::filesystem::path& path, mode_t dirmode, mode_t parentmode)
{
    if (std::filesystem::exists(path))
        return true;
    if (path.has_parent_path())
        check_dir(path.parent_path(), parentmode, parentmode);
    std::error_code ec;
    if (std::filesystem::create_directory(path, ec)) {
        std::filesystem::permissions(path, (std::filesystem::perms)dirmode);
        return true;
    }
    return false;
}

std::mutex&
getFileLock(const std::filesystem::path& path)
{
    static std::mutex fileLockLock {};
    static std::map<std::string, std::mutex> fileLocks {};

    std::lock_guard l(fileLockLock);
    return fileLocks[path.string()];
}

bool
isFile(const std::filesystem::path& path, bool resolveSymlink)
{
    auto status = resolveSymlink ? std::filesystem::status(path) : std::filesystem::symlink_status(path);
    return std::filesystem::is_regular_file(status);
}

bool
isDirectory(const std::filesystem::path& path)
{
    return std::filesystem::is_directory(path);
}

bool
hasHardLink(const std::filesystem::path& path)
{
    return std::filesystem::hard_link_count(path) > 1;
}

bool
isSymLink(const std::filesystem::path& path)
{
    return std::filesystem::is_symlink(path);
}

template <typename TP>
std::chrono::system_clock::time_point to_sysclock(TP tp)
{
    using namespace std::chrono;
    return time_point_cast<system_clock::duration>(tp - TP::clock::now() + system_clock::now());
}

bool
createSymlink(const std::string& linkFile, const std::string& target)
{
    try {
        std::filesystem::create_symlink(target, linkFile);
    } catch (const std::exception& e) {
        //JAMI_ERR("Unable to create soft link: %s", e.what());
        return false;
    }
    return true;
}

bool
createHardlink(const std::string& linkFile, const std::string& target)
{
    try {
        std::filesystem::create_hard_link(target, linkFile);
    } catch (const std::exception& e) {
        //JAMI_ERR("Unable to create hard link: %s", e.what());
        return false;
    }
    return true;
}

void
createFileLink(const std::string& linkFile, const std::string& target, bool hard)
{
    if (not hard or not createHardlink(linkFile, target))
        createSymlink(linkFile, target);
}

std::vector<uint8_t>
loadFile(const std::filesystem::path& path)
{
    std::vector<uint8_t> buffer;
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("Unable to read file: " + path.string());
    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    if (size > std::numeric_limits<unsigned>::max())
        throw std::runtime_error("File is too big: " + path.string());
    buffer.resize(size);
    file.seekg(0, std::ios::beg);
    if (!file.read((char*) buffer.data(), size))
        throw std::runtime_error("Unable to load file: " + path.string());
    return buffer;
}

void
saveFile(const std::filesystem::path& path, const uint8_t* data, size_t data_size, mode_t mode)
{
    std::ofstream file(path, std::ios::trunc | std::ios::binary);
    if (!file.is_open()) {
        //JAMI_ERR("Unable to write data to %s", path.c_str());
        return;
    }
    file.write((char*) data, data_size);
    file.close();
    std::filesystem::permissions(path, (std::filesystem::perms)mode);
}

std::vector<std::string>
readDirectory(const std::filesystem::path& dir)
{
    std::vector<std::string> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        files.emplace_back(entry.path().filename().string());
    }
    return files;
}

bool
recursive_mkdir(const std::filesystem::path& path, mode_t mode)
{
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    if (!ec)
        std::filesystem::permissions(path, (std::filesystem::perms)mode, ec);
    return !ec;
}

#ifdef _WIN32
bool
eraseFile_win32(const std::string& path, bool dosync)
{
    HANDLE h
        = CreateFileA(path.c_str(), GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) {
        // JAMI_WARN("Unable to open file %s for erasing.", path.c_str());
        return false;
    }

    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size)) {
        // JAMI_WARN("Unable to erase file %s: GetFileSizeEx() failed.", path.c_str());
        CloseHandle(h);
        return false;
    }
    if (size.QuadPart == 0) {
        CloseHandle(h);
        return false;
    }

    uint64_t size_blocks = size.QuadPart / ERASE_BLOCK;
    if (size.QuadPart % ERASE_BLOCK)
        size_blocks++;

    char* buffer;
    try {
        buffer = new char[ERASE_BLOCK];
    } catch (std::bad_alloc& ba) {
        // JAMI_WARN("Unable to allocate buffer for erasing %s.", path.c_str());
        CloseHandle(h);
        return false;
    }
    memset(buffer, 0x00, ERASE_BLOCK);

    OVERLAPPED ovlp;
    if (size.QuadPart < (1024 - 42)) { // a small file can be stored in the MFT record
        ovlp.Offset = 0;
        ovlp.OffsetHigh = 0;
        WriteFile(h, buffer, (DWORD) size.QuadPart, 0, &ovlp);
        FlushFileBuffers(h);
    }
    for (uint64_t i = 0; i < size_blocks; i++) {
        uint64_t offset = i * ERASE_BLOCK;
        ovlp.Offset = offset & 0x00000000FFFFFFFF;
        ovlp.OffsetHigh = offset >> 32;
        WriteFile(h, buffer, ERASE_BLOCK, 0, &ovlp);
    }

    delete[] buffer;

    if (dosync)
        FlushFileBuffers(h);

    CloseHandle(h);
    return true;
}

#else

bool
eraseFile_posix(const std::string& path, bool dosync)
{
    struct stat st;
    if (stat(path.c_str(), &st) == -1) {
        //JAMI_WARN("Unable to erase file %s: fstat() failed.", path.c_str());
        return false;
    }
    // Remove read-only flag if possible
    chmod(path.c_str(), st.st_mode | (S_IWGRP+S_IWUSR) );

    int fd = open(path.c_str(), O_WRONLY);
    if (fd == -1) {
        //JAMI_WARN("Unable to open file %s for erasing.", path.c_str());
        return false;
    }

    if (st.st_size == 0) {
        close(fd);
        return false;
    }

    lseek(fd, 0, SEEK_SET);

    std::array<char, ERASE_BLOCK> buffer;
    buffer.fill(0);
    decltype(st.st_size) written(0);
    while (written < st.st_size) {
        auto ret = write(fd, buffer.data(), buffer.size());
        if (ret < 0) {
            //JAMI_WARNING("Error while overriding file with zeros.");
            break;
        } else
            written += ret;
    }

    if (dosync)
        fsync(fd);

    close(fd);
    return written >= st.st_size;
}
#endif

bool
eraseFile(const std::string& path, bool dosync)
{
#ifdef _WIN32
    return eraseFile_win32(path, dosync);
#else
    return eraseFile_posix(path, dosync);
#endif
}

int
remove(const std::filesystem::path& path, bool erase)
{
    if (erase and isFile(path, false) and !hasHardLink(path))
        eraseFile(path.string(), true);

#ifdef _WIN32
    // use Win32 api since std::remove will not unlink directory in use
    if (isDirectory(path))
        return !RemoveDirectory(dhtnet::to_wstring(path.string()).c_str());
#endif

    std::error_code ec;
    std::filesystem::remove(path, ec);
    return ec.value();
}

int
removeAll(const std::filesystem::path& path, bool erase)
{
    try {
        std::error_code ec;
        if (not erase) {
            std::filesystem::remove_all(path, ec);
            return ec.value();
        }
        if (path.empty())
            return -1;

        auto status = std::filesystem::status(path, ec);
        if (!ec && std::filesystem::is_directory(status) and not std::filesystem::is_symlink(status)) {
            for (const auto& entry: std::filesystem::directory_iterator(path, ec)) {
                removeAll(entry.path(), erase);
            }
        }
        return remove(path, erase);
    } catch (const std::exception& e) {
        //JAMI_ERR("Error while removing %s: %s", path.c_str(), e.what());
        return -1;
    }
}

int
accessFile(const std::filesystem::path& file, int mode)
{
#ifdef _WIN32
    return _waccess(dhtnet::to_wstring(file.string()).c_str(), mode);
#else
    return access(file.c_str(), mode);
#endif
}

constexpr auto ID_TIMEOUT = std::chrono::hours(24);

void
IdList::load()
{
    size_t pruned = 0;
    auto now = std::chrono::system_clock::now();
    try {
        std::ifstream file(path, std::ios::binary);
        msgpack::unpacker unp;
        auto timeout = now - ID_TIMEOUT;
        while (file.is_open() && !file.eof()) {
            unp.reserve_buffer(8 * 1024);
            file.read(unp.buffer(), unp.buffer_capacity());
            unp.buffer_consumed(file.gcount());
            msgpack::unpacked result;
            while (unp.next(result)) {
                auto kv = result.get().as<std::pair<uint64_t, std::chrono::system_clock::time_point>>();
                if (kv.second > timeout)
                    ids.insert(std::move(kv));
                else
                    pruned++;
            }
        }
    } catch (const std::exception& e) {
        // discard corrupted files
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    last_maintain = now;
    if (pruned) {
        std::ofstream file(path, std::ios::trunc | std::ios::binary);
        for (auto& kv : ids)
            msgpack::pack(file, kv);
    }
}

bool
IdList::add(uint64_t id)
{
    auto now = std::chrono::system_clock::now();
    auto r = ids.emplace(id, now);
    if (r.second) {
        auto timeout = now - ID_TIMEOUT;
        if (last_maintain > timeout) {
            // append
            std::ofstream file(path, std::ios::app | std::ios::binary);
            if (file.is_open()) {
                msgpack::pack(file, *r.first);
            }
        } else {
            // maintain and save
            std::ofstream file(path, std::ios::trunc | std::ios::binary);
            for (auto it = ids.begin(); it != ids.end();) {
                if (it->second < timeout) {
                    it = ids.erase(it);
                } else {
                    msgpack::pack(file, *it);
                    ++it;
                }
            }
            last_maintain = now;
        }
        return true;
    }
    return false;
}

} // namespace fileutils
} // namespace dhtnet
