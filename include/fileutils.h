/*
 *  Copyright (C) 2004-2023 Savoir-faire Linux Inc.
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

bool isPathRelative(const std::string& path);

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
std::vector<uint8_t> loadFile(const std::string& path);
std::string loadTextFile(const std::string& path, const std::string& default_dir = {});

void saveFile(const std::string& path, const uint8_t* data, size_t data_size, mode_t mode = 0644);
inline void
saveFile(const std::string& path, const std::vector<uint8_t>& data, mode_t mode = 0644)
{
    saveFile(path, data.data(), data.size(), mode);
}

std::mutex& getFileLock(const std::string& path);

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
 * Wrappers for fstream opening that will convert paths to wstring
 * on windows
 */
void openStream(std::ifstream& file,
                const std::string& path,
                std::ios_base::openmode mode = std::ios_base::in);
void openStream(std::ofstream& file,
                const std::string& path,
                std::ios_base::openmode mode = std::ios_base::out);
std::ifstream ifstream(const std::string& path, std::ios_base::openmode mode = std::ios_base::in);
std::ofstream ofstream(const std::string& path, std::ios_base::openmode mode = std::ios_base::out);

/**
 * Windows compatibility wrapper for checking read-only attribute
 */
int accessFile(const std::string& file, int mode);

} // namespace fileutils
} // namespace dhtnet
