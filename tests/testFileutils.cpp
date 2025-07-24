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
#include <cppunit/TestAssert.h>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include "test_runner.h"
#include "fileutils.h"

#include <string>
#include <iostream>
#include <cstdlib>
#include <unistd.h>

namespace dhtnet { namespace fileutils { namespace test {

class FileutilsTest : public CppUnit::TestFixture {
public:
    static std::string name() { return "fileutils"; }

    void setUp();
    void tearDown();

private:
    void testCheckDir();
    void testPath();
    void testReadDirectory();
    void testLoadFile();
    void testIdList();

    CPPUNIT_TEST_SUITE(FileutilsTest);
    CPPUNIT_TEST(testCheckDir);
    CPPUNIT_TEST(testPath);
    CPPUNIT_TEST(testReadDirectory);
    CPPUNIT_TEST(testLoadFile);
    CPPUNIT_TEST(testIdList);
    CPPUNIT_TEST_SUITE_END();

    static constexpr auto tmpFileName = "temp_file";

    std::filesystem::path TEST_PATH;
    std::filesystem::path NON_EXISTANT_PATH_BASE;
    std::filesystem::path NON_EXISTANT_PATH;
    std::filesystem::path EXISTANT_FILE;
};

CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(FileutilsTest, FileutilsTest::name());

void
FileutilsTest::setUp()
{
    char template_name[] = {"unit_tests_XXXXXX"};

    // Generate a temporary directory with a file inside
    auto directory = mkdtemp(template_name);
    CPPUNIT_ASSERT(directory);

    TEST_PATH = directory;
    EXISTANT_FILE = TEST_PATH / tmpFileName;
    NON_EXISTANT_PATH_BASE = TEST_PATH / "not_existing_path";
    NON_EXISTANT_PATH = NON_EXISTANT_PATH_BASE / "test";

    auto* fd = fopen(EXISTANT_FILE.c_str(), "w");
    fwrite("RING", 1, 4, fd);
    fclose(fd);
}

void
FileutilsTest::tearDown()
{
    unlink(EXISTANT_FILE.c_str());
    rmdir(TEST_PATH.c_str());
}

void
FileutilsTest::testCheckDir()
{
    // check existed directory
    CPPUNIT_ASSERT(check_dir(TEST_PATH));
    CPPUNIT_ASSERT(isDirectory(TEST_PATH));
    // check non-existent directory
    CPPUNIT_ASSERT(!isDirectory(NON_EXISTANT_PATH));
    CPPUNIT_ASSERT(check_dir(NON_EXISTANT_PATH));
    CPPUNIT_ASSERT(isDirectory(NON_EXISTANT_PATH));
    CPPUNIT_ASSERT(removeAll(NON_EXISTANT_PATH_BASE) == 0);
    CPPUNIT_ASSERT(!isDirectory(NON_EXISTANT_PATH_BASE));
    //remove an non existent directory
    CPPUNIT_ASSERT(removeAll(NON_EXISTANT_PATH_BASE) == 0);
}

void
FileutilsTest::testPath()
{
    CPPUNIT_ASSERT(isPathRelative("relativePath"));
    CPPUNIT_ASSERT(isFile(EXISTANT_FILE));
    CPPUNIT_ASSERT(!isDirectory(EXISTANT_FILE));
    CPPUNIT_ASSERT(isDirectory(TEST_PATH));
}

void
FileutilsTest::testReadDirectory()
{
    CPPUNIT_ASSERT(recursive_mkdir(TEST_PATH / "readDirectory" / "test1"));
    CPPUNIT_ASSERT(recursive_mkdir(TEST_PATH / "readDirectory" / "test2"));
    auto dirs = readDirectory(TEST_PATH / "readDirectory");
    CPPUNIT_ASSERT(dirs.size() == 2);
    CPPUNIT_ASSERT(
        (dirs.at(0).compare("test1") == 0 && dirs.at(1).compare("test2") == 0)
        || (dirs.at(1).compare("test1") == 0 && dirs.at(0).compare("test2") == 0));
    CPPUNIT_ASSERT(removeAll(TEST_PATH / "readDirectory") == 0);
}

void
FileutilsTest::testLoadFile()
{
    auto file = loadFile(EXISTANT_FILE);
    CPPUNIT_ASSERT(file.size() == 4);
    CPPUNIT_ASSERT(file.at(0) == 'R');
    CPPUNIT_ASSERT(file.at(1) == 'I');
    CPPUNIT_ASSERT(file.at(2) == 'N');
    CPPUNIT_ASSERT(file.at(3) == 'G');
}

void
FileutilsTest::testIdList()
{
    auto path = TEST_PATH / "idList";
    IdList list(path);
    list.add(1);
    list.add(2);
    IdList list2(path);
    CPPUNIT_ASSERT(!list.add(1));
    CPPUNIT_ASSERT(!list.add(2));
    CPPUNIT_ASSERT(!list2.add(1));
    CPPUNIT_ASSERT(!list2.add(2));
    CPPUNIT_ASSERT(list2.add(10));
    CPPUNIT_ASSERT(list2.add(11));
    list = {path};
    CPPUNIT_ASSERT(list.add(5));
    CPPUNIT_ASSERT(list.add(6));
    CPPUNIT_ASSERT(!list.add(1));
    CPPUNIT_ASSERT(!list.add(2));
    CPPUNIT_ASSERT(!list.add(10));
    CPPUNIT_ASSERT(!list.add(11));
    CPPUNIT_ASSERT(removeAll(path) == 0);
}


}}} // namespace dhtnet::test::fileutils

JAMI_TEST_RUNNER(dhtnet::fileutils::test::FileutilsTest::name());
