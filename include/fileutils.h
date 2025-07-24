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
#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <cstdio>
#include <ios>
#include <filesystem>
#include <map>

#ifndef _WIN32
#include <sys/stat.h>               // mode_t
#else
#define mode_t                unsigned
#endif

namespace dhtnet {
namespace fileutils {

/**
 * Check directory existence and create it with given mode if it doesn't.
 * @param path to check, relative or absolute
 * @param dir last directory creation mode
 * @param parents default mode for all created directories except the last
 */
bool check_dir(const std::filesystem::path& path, mode_t dir = 0755, mode_t parents = 0755);

bool recursive_mkdir(const std::filesystem::path& path, mode_t mode = 0755);

inline bool isPathRelative(const std::filesystem::path& path) {
    return path.is_relative();
}

bool isFile(const std::filesystem::path& path, bool resolveSymlink = true);
bool isDirectory(const std::filesystem::path& path);
bool isSymLink(const std::filesystem::path& path);
bool hasHardLink(const std::filesystem::path& path);

/**
 * Read content of the directory.
 * The result is a list of relative (to @param dir) paths of all entries
 * in the directory, without "." and "..".
 */
std::vector<std::string> readDirectory(const std::filesystem::path& dir);

/**
 * Read the full content of a file at path.
 * If path is relative, it is appended to default_dir.
 */
std::vector<uint8_t> loadFile(const std::filesystem::path& path);

void saveFile(const std::filesystem::path& path, const uint8_t* data, size_t data_size, mode_t mode = 0644);
inline void
saveFile(const std::filesystem::path& path, const std::vector<uint8_t>& data, mode_t mode = 0644)
{
    saveFile(path, data.data(), data.size(), mode);
}

std::mutex& getFileLock(const std::filesystem::path& path);

/**
 * Remove a file with optional erasing of content.
 * Return the same value as std::remove().
 */
int remove(const std::filesystem::path& path, bool erase = false);

/**
 * Prune given directory's content and remove it, symlinks are not followed.
 * Return 0 if succeed, -1 if directory is not removed (content can be removed partially).
 */
int removeAll(const std::filesystem::path& path, bool erase = false);

/**
 * Windows compatibility wrapper for checking read-only attribute
 */
int accessFile(const std::string& file, int mode);


class IdList
{
public:
    IdList(std::filesystem::path p): path(std::move(p)) {
        load();
    }
    bool add(uint64_t id);
private:
    void load();
    std::filesystem::path path;
    std::map<uint64_t, std::chrono::system_clock::time_point> ids;
    std::chrono::system_clock::time_point last_maintain;
};

} // namespace fileutils
} // namespace dhtnet
