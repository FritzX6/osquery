/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <fstream>

#include <boost/filesystem.hpp>

#include <osquery/filesystem/fileops.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace {

WindowsStatFields noHandleFields() {
  WindowsStatFields fields;
  fields.handle_info = false;
  fields.owner = false;
  fields.block_size = false;
  fields.version_info = false;
  return fields;
}

// The fields platformStat fills in whatever WindowsStatFields asks for.
void expectSameBasicFields(const WINDOWS_STAT& expected,
                           const WINDOWS_STAT& actual) {
  EXPECT_EQ(expected.symlink, actual.symlink);
  EXPECT_EQ(expected.mode, actual.mode);
  EXPECT_EQ(expected.size, actual.size);
  EXPECT_EQ(expected.atime, actual.atime);
  EXPECT_EQ(expected.mtime, actual.mtime);
  EXPECT_EQ(expected.btime, actual.btime);
  EXPECT_EQ(expected.type, actual.type);
  EXPECT_EQ(expected.attributes, actual.attributes);
}

void writeFile(const fs::path& path, const std::string& content) {
  std::ofstream out(path.string(), std::ios::out | std::ios::binary);
  out << content;
}

} // namespace

class PlatformStatTests : public testing::Test {
 protected:
  fs::path test_dir_;

  void SetUp() override {
    test_dir_ = fs::temp_directory_path() /
                fs::unique_path("osquery.platform_stat.%%%%.%%%%");
    ASSERT_TRUE(fs::create_directories(test_dir_));
  }

  void TearDown() override {
    boost::system::error_code ec;
    fs::remove_all(test_dir_, ec);
  }
};

TEST_F(PlatformStatTests, test_no_handle_matches_full_stat_for_file) {
  auto path = test_dir_ / "file.txt";
  writeFile(path, "some content");

  WINDOWS_STAT full;
  ASSERT_TRUE(platformStat(path, &full).ok());

  WINDOWS_STAT partial;
  ASSERT_TRUE(platformStat(path, &partial, noHandleFields()).ok());

  expectSameBasicFields(full, partial);
  EXPECT_EQ(partial.size, 12);
  EXPECT_EQ(partial.type, "regular");
}

TEST_F(PlatformStatTests, test_no_handle_matches_full_stat_for_attributes) {
  auto path = test_dir_ / "hidden_readonly.txt";
  writeFile(path, "x");

  auto wpath = stringToWstring(path.string());
  // Without FILE_ATTRIBUTE_ARCHIVE a file is reported with the "disk" type
  ASSERT_NE(SetFileAttributesW(wpath.c_str(),
                               FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY),
            0);

  WINDOWS_STAT full;
  ASSERT_TRUE(platformStat(path, &full).ok());

  WINDOWS_STAT partial;
  ASSERT_TRUE(platformStat(path, &partial, noHandleFields()).ok());

  SetFileAttributesW(wpath.c_str(), FILE_ATTRIBUTE_NORMAL);

  expectSameBasicFields(full, partial);
  EXPECT_NE(partial.attributes.find('H'), std::string::npos);
  EXPECT_NE(partial.attributes.find('R'), std::string::npos);
  EXPECT_EQ(partial.type, "disk");
}

TEST_F(PlatformStatTests, test_no_handle_matches_full_stat_for_directory) {
  auto path = test_dir_ / "subdir";
  ASSERT_TRUE(fs::create_directory(path));

  WINDOWS_STAT full;
  ASSERT_TRUE(platformStat(path, &full).ok());

  WINDOWS_STAT partial;
  ASSERT_TRUE(platformStat(path, &partial, noHandleFields()).ok());

  expectSameBasicFields(full, partial);
  EXPECT_EQ(partial.type, "directory");
}

TEST_F(PlatformStatTests, test_no_handle_follows_symlinks) {
  auto target = test_dir_ / "target.txt";
  writeFile(target, "target content");
  auto link = test_dir_ / "link.txt";

  // Creating symlinks needs SeCreateSymbolicLinkPrivilege or developer mode
  if (CreateSymbolicLinkW(stringToWstring(link.string()).c_str(),
                          stringToWstring(target.string()).c_str(),
                          SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) == 0) {
    GTEST_SKIP() << "Cannot create symlinks: " << GetLastError();
  }

  WINDOWS_STAT full;
  ASSERT_TRUE(platformStat(link, &full).ok());

  WINDOWS_STAT partial;
  ASSERT_TRUE(platformStat(link, &partial, noHandleFields()).ok());

  // Reparse points are still opened, so the fields describe the target
  expectSameBasicFields(full, partial);
  EXPECT_EQ(partial.size, 14);
}

TEST_F(PlatformStatTests, test_missing_file) {
  auto path = test_dir_ / "does_not_exist.txt";

  WINDOWS_STAT full;
  EXPECT_FALSE(platformStat(path, &full).ok());

  WINDOWS_STAT partial;
  EXPECT_FALSE(platformStat(path, &partial, noHandleFields()).ok());
}

TEST_F(PlatformStatTests, test_exclusively_opened_file) {
  auto path = test_dir_ / "locked.txt";
  writeFile(path, "locked");

  // Another process holding a file open without sharing must not hide it
  auto handle = CreateFileW(stringToWstring(path.string()).c_str(),
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr);
  ASSERT_NE(handle, INVALID_HANDLE_VALUE);

  WINDOWS_STAT full;
  auto full_status = platformStat(path, &full);

  WINDOWS_STAT partial;
  auto partial_status = platformStat(path, &partial, noHandleFields());

  CloseHandle(handle);

  ASSERT_TRUE(full_status.ok()) << full_status.getMessage();
  ASSERT_TRUE(partial_status.ok()) << partial_status.getMessage();
  expectSameBasicFields(full, partial);
  EXPECT_EQ(full.size, 6);
}

TEST_F(PlatformStatTests, test_optional_fields_are_skipped) {
  // A system binary that always has a version resource
  auto path = getSystemRoot() / "System32" / "kernel32.dll";

  WINDOWS_STAT full;
  ASSERT_TRUE(platformStat(path, &full).ok());
  EXPECT_FALSE(full.product_version.empty());
  EXPECT_FALSE(full.file_version.empty());
  EXPECT_FALSE(full.original_filename.empty());
  EXPECT_GT(full.block_size, 0);
  EXPECT_FALSE(full.file_id.empty());
  EXPECT_FALSE(full.volume_serial.empty());
  EXPECT_NE(full.ctime, -1);

  WINDOWS_STAT partial;
  ASSERT_TRUE(platformStat(path, &partial, noHandleFields()).ok());
  expectSameBasicFields(full, partial);
  EXPECT_TRUE(partial.product_version.empty());
  EXPECT_TRUE(partial.file_version.empty());
  EXPECT_TRUE(partial.original_filename.empty());
  EXPECT_EQ(partial.block_size, -1);
  EXPECT_TRUE(partial.file_id.empty());
  EXPECT_TRUE(partial.volume_serial.empty());
  EXPECT_EQ(partial.ctime, -1);
}

TEST_F(PlatformStatTests, test_each_field_group_matches_full_stat) {
  auto path = getSystemRoot() / "System32" / "kernel32.dll";

  WINDOWS_STAT full;
  ASSERT_TRUE(platformStat(path, &full).ok());

  auto fields = noHandleFields();
  fields.handle_info = true;
  WINDOWS_STAT handle_info;
  ASSERT_TRUE(platformStat(path, &handle_info, fields).ok());
  expectSameBasicFields(full, handle_info);
  EXPECT_EQ(full.inode, handle_info.inode);
  EXPECT_EQ(full.file_id, handle_info.file_id);
  EXPECT_EQ(full.ctime, handle_info.ctime);
  EXPECT_EQ(full.hard_links, handle_info.hard_links);
  EXPECT_EQ(full.device, handle_info.device);
  EXPECT_EQ(full.volume_serial, handle_info.volume_serial);

  fields = noHandleFields();
  fields.owner = true;
  WINDOWS_STAT owner;
  ASSERT_TRUE(platformStat(path, &owner, fields).ok());
  expectSameBasicFields(full, owner);
  EXPECT_EQ(full.uid, owner.uid);
  EXPECT_EQ(full.gid, owner.gid);

  fields = noHandleFields();
  fields.block_size = true;
  WINDOWS_STAT block_size;
  ASSERT_TRUE(platformStat(path, &block_size, fields).ok());
  EXPECT_EQ(full.block_size, block_size.block_size);

  fields = noHandleFields();
  fields.version_info = true;
  WINDOWS_STAT version_info;
  ASSERT_TRUE(platformStat(path, &version_info, fields).ok());
  EXPECT_EQ(full.product_version, version_info.product_version);
  EXPECT_EQ(full.file_version, version_info.file_version);
  EXPECT_EQ(full.original_filename, version_info.original_filename);
}

} // namespace osquery
