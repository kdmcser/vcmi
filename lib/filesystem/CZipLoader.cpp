/*
 * CZipLoader.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "StdInc.h"
#include "CZipLoader.h"

#include "../ExceptionsCommon.h"
#include "../ScopeGuard.h"
#include "../texts/TextOperations.h"

#include <memory>
#include <type_traits>

#include <boost/filesystem/fstream.hpp>
#include <boost/system/error_code.hpp>

VCMI_LIB_NAMESPACE_BEGIN

CZipStream::CZipStream(const std::shared_ptr<CIOApi> & api, const boost::filesystem::path & archive, unz64_file_pos filepos)
{
	zlib_filefunc64_def zlibApi;

	zlibApi = api->getApiStructure();

	file = unzOpen2_64(archive.c_str(), &zlibApi);
	if(file == nullptr)
	{
		logGlobal->error("Failed to open zip archive %s", archive.string());
		throw DataLoadingException("Failed to open zip archive '" + archive.string() + "'");
	}

	// If these two calls fail, not a single byte of file_info is written. The original code ignored the
	// return values, so getSize() / calculateCRC32() would read garbage from the stack, and the caller
	// would then use it to resize a buffer and blow up. This must be treated as a hard error.
	unz_file_info64 file_info{};
	char filename_inzip[256]{};
	if(unzGoToFilePos64(file, &filepos) != UNZ_OK
	   || unzGetCurrentFileInfo64(file, &file_info, filename_inzip, sizeof(filename_inzip),
	                              nullptr, 0, nullptr, 0) != UNZ_OK)
	{
		logGlobal->error("Failed to locate entry in zip archive %s", archive.string());
		unzClose(file);
		throw DataLoadingException("Failed to locate entry in zip archive '" + archive.string() + "'");
	}

	if ((file_info.flag & 1) != 0)
	{
		// Encrypted entries (ZipCrypto and AES) are all handed to the protected reader: giving them to
		// minizip would require passing the plaintext password in, which is exactly what an attacker wants.
		// The path must be passed as archive.c_str(): on Windows it is wide-character, matching the IO
		// implementation's convention; passing std::string::c_str() would be interpreted as a wide string,
		// scrambling the path so it could never be opened.
		unz64_file_pos entryPosition;
		if(unzGetFilePos64(file, &entryPosition) == UNZ_OK)
			encryptedReader = std::make_unique<ModPassword::EncryptedZipReader>(
			    zlibApi, archive.c_str(), entryPosition.pos_in_zip_directory);

		// If it cannot be opened (wrong password, tampered ciphertext, corrupt archive), report it as
		// VCMI's unified "resource cannot be read" type and let the upper layer decide what to do. Note
		// that we must not throw std::runtime_error: this path (CModState::computeChecksum and the like)
		// only recognizes DataLoadingException, and any other type would escape all the way to the top
		// level and crash the client.
		if(encryptedReader == nullptr || encryptedReader->isFailed())
		{
			logGlobal->error("Failed to open encrypted entry %s in %s", filename_inzip, archive.string());
			unzCloseCurrentFile(file);
			unzClose(file);
			throw DataLoadingException("Failed to open encrypted entry '" + std::string(filename_inzip)
			                           + "' in '" + archive.string() + "'");
		}
	}
	else 
		unzOpenCurrentFile(file);
}

CZipStream::~CZipStream()
{
	// The authentication code of an encrypted entry was already verified when it was opened; if it had not passed, no data could be read at all
	unzCloseCurrentFile(file);
	unzClose(file);
}

si64 CZipStream::readMore(ui8 * data, si64 size)
{
	if (encryptedReader)
		return encryptedReader->read(data, size);

	return unzReadCurrentFile(file, data, static_cast<unsigned int>(size));
}

si64 CZipStream::getSize()
{
	unz_file_info64 info{};
	if(unzGetCurrentFileInfo64(file, &info, nullptr, 0, nullptr, 0, nullptr, 0) != UNZ_OK)
		return 0;

	return info.uncompressed_size;
}

ui32 CZipStream::calculateCRC32()
{
	unz_file_info64 info{};
	if(unzGetCurrentFileInfo64(file, &info, nullptr, 0, nullptr, 0, nullptr, 0) != UNZ_OK)
		return 0;

	return info.crc;
}

namespace
{
/// walks over all entries of the archive, in archive order
template<typename Visitor>
bool forEachZipEntry(unzFile archive, const Visitor & visitor)
{
	int result = unzGoToFirstFile(archive);

	while(result == UNZ_OK)
	{
		unz_file_info64 info{};
		unz64_file_pos position{};

		if(unzGetCurrentFileInfo64(archive, &info, nullptr, 0, nullptr, 0, nullptr, 0) != UNZ_OK)
			return false;

		std::string name(info.size_filename + 1, '\0');
		if(unzGetCurrentFileInfo64(archive, &info, name.data(), static_cast<uLong>(name.size()), nullptr, 0, nullptr, 0) != UNZ_OK)
			return false;

		if(unzGetFilePos64(archive, &position) != UNZ_OK)
			return false;

		name.resize(info.size_filename);
		if(!name.empty() && name.find('\0') == std::string::npos)
			visitor(std::move(name), info, position);

		result = unzGoToNextFile(archive);
	}
	return result == UNZ_END_OF_LIST_OF_FILE;
}

/// rejects absolute paths and paths that would escape the destination directory
bool isSafeRelativePath(const boost::filesystem::path & path)
{
	if(path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory())
		return false;

	for(const auto & part : path)
		if(part == "..")
			return false;

	return true;
}

boost::filesystem::path zipFilenameToFilesystemPath(const std::string & filename, bool isUtf8)
{
#ifdef VCMI_WINDOWS
	if (isUtf8)
		return TextOperations::Utf8TofilesystemPath(filename);

	return boost::filesystem::path(filename);
#else
	return boost::filesystem::path(filename);
#endif
}
}

///CZipLoader
CZipLoader::CZipLoader(const std::string & mountPoint, const boost::filesystem::path & archive, std::shared_ptr<CIOApi> api):
	ioApi(std::move(api)),
	zlibApi(ioApi->getApiStructure()),
	archiveName(archive),
	mountPoint(mountPoint),
	files(listFiles(mountPoint, archive))
{
	logGlobal->trace("Zip archive loaded, %d files found", files.size());
}

std::unordered_map<ResourcePath, unz64_file_pos> CZipLoader::listFiles(const std::string & mountPoint, const boost::filesystem::path & archive)
{
	std::unordered_map<ResourcePath, unz64_file_pos> ret;

	unzFile file = unzOpen2_64(archive.c_str(), &zlibApi);

	if(file == nullptr)
	{
		logGlobal->error("%s failed to open", TextOperations::filesystemPathToUtf8(archive));
		return ret;
	}

	auto closeArchive = vstd::makeScopeGuard([file]() { unzClose(file); });
	const bool success = forEachZipEntry(file, [&ret, &mountPoint](const std::string & name, const unz_file_info64 &, const unz64_file_pos & position)
	{
		ret.insert_or_assign(ResourcePath(mountPoint + name), position);
	});
	if(!success)
		logGlobal->error("Failed to read zip directory in '%s'", TextOperations::filesystemPathToUtf8(archive));

	return ret;
}

std::unique_ptr<CInputStream> CZipLoader::load(const ResourcePath & resourceName) const
{
	return std::unique_ptr<CInputStream>(new CZipStream(ioApi, archiveName, files.at(resourceName)));
}

bool CZipLoader::existsResource(const ResourcePath & resourceName) const
{
	return files.count(resourceName) != 0;
}

std::string CZipLoader::getMountPoint() const
{
	return mountPoint;
}

std::unordered_set<ResourcePath> CZipLoader::getFilteredFiles(std::function<bool(const ResourcePath &)> filter) const
{
	std::unordered_set<ResourcePath> foundID;

	for(const auto & file : files)
	{
		if (filter(file.first))
			foundID.insert(file.first);
	}
	return foundID;
}

std::string CZipLoader::getFullFileURI(const ResourcePath& resourceName) const
{
	auto relativePath = TextOperations::Utf8TofilesystemPath(resourceName.getName());
	auto path = boost::filesystem::canonical(archiveName) / relativePath;
	return TextOperations::filesystemPathToUtf8(path);
}

std::time_t CZipLoader::getLastWriteTime(const ResourcePath& resourceName) const
{
	auto path = boost::filesystem::canonical(archiveName);
	return  boost::filesystem::last_write_time(path);
}

const std::vector<ZipArchive::Entry> & ZipArchive::entries()
{
	return indexedEntries;
}

std::vector<std::string> ZipArchive::listFiles()
{
	std::vector<std::string> ret;

	for(const auto & entry : entries())
		ret.push_back(entry.name);

	return ret;
}

ZipArchive::ZipArchive(const boost::filesystem::path & from)
{
	CDefaultIOApi zipAPI;

#if MINIZIP_NEEDS_32BIT_FUNCS
	auto zipStructure = zipAPI.getApiStructure32();
	archive = unzOpen2(from.c_str(), &zipStructure);
#else
	auto zipStructure = zipAPI.getApiStructure();
	archive = unzOpen2_64(from.c_str(), &zipStructure);
#endif

	if (archive == nullptr)
		throw std::runtime_error("Failed to open file '" + from.string());

	std::unique_ptr<std::remove_pointer_t<unzFile>, decltype(&unzClose)> archiveGuard(archive, &unzClose);
	const bool success = forEachZipEntry(archive, [this](std::string name, const unz_file_info64 & info, const unz64_file_pos & position)
	{
		constexpr uLong ZIP_UTF8_FILENAME_FLAG = 1 << 11;
		const bool directory = name.back() == '/';
		const bool isUtf8Filename = (info.flag & ZIP_UTF8_FILENAME_FLAG) != 0;
		entryIndices.emplace(name, indexedEntries.size());
		indexedEntries.push_back({std::move(name), info.uncompressed_size, directory, isUtf8Filename, position});
	});
	if(!success)
		logGlobal->error("Failed to read zip directory in '%s'", TextOperations::filesystemPathToUtf8(from));
	archiveGuard.release();
}

ZipArchive::~ZipArchive()
{
	unzClose(archive);
}

bool ZipArchive::extract(const boost::filesystem::path & where, const std::vector<std::string> & what)
{
	for (const std::string & file : what)
		if (!extract(where, file))
			return false;

	return true;
}

bool ZipArchive::extract(const boost::filesystem::path & where, const std::string & file)
{
	const auto found = entryIndices.find(file);
	if(found == entryIndices.end())
		return false;

	return extractTo(where, found->second, file);
}

bool ZipArchive::extractTo(const boost::filesystem::path & where, size_t entryIndex, const std::string & relativeName, const Progress & progress)
{
	if(entryIndex >= indexedEntries.size())
		return false;

	const auto & entry = indexedEntries.at(entryIndex);
	const auto relativePath = zipFilenameToFilesystemPath(relativeName, entry.isUtf8Filename);
	if(relativePath.empty())
		return entry.directory;
	if(!isSafeRelativePath(relativePath))
		return false;

	try
	{
		const auto destination = where / relativePath;
		if(entry.directory)
		{
			boost::filesystem::create_directories(destination);
			return true;
		}

		boost::filesystem::create_directories(destination.parent_path());
		if(unzGoToFilePos64(archive, &entry.position) != UNZ_OK || unzOpenCurrentFile(archive) != UNZ_OK)
			return false;

		bool entryOpen = true;
		bool success = false;
		boost::filesystem::ofstream output(destination, std::ios::out | std::ios::binary | std::ios::trunc);
		auto cleanup = vstd::makeScopeGuard([&]()
		{
			if(entryOpen)
				unzCloseCurrentFile(archive);
			if(output.is_open())
				output.close();
			if(!success)
			{
				boost::system::error_code error;
				boost::filesystem::remove(destination, error);
			}
		});
		if(!output.good())
			return false;

		std::array<char, 64 * 1024> buffer;
		while(true)
		{
			const int count = unzReadCurrentFile(archive, buffer.data(), static_cast<unsigned int>(buffer.size()));
			if(count < 0)
				return false;
			if(count == 0)
				break;

			output.write(buffer.data(), count);
			if(!output.good())
				return false;
			if(progress && !progress(static_cast<uint64_t>(count)))
				return false;
		}

		const int closeResult = unzCloseCurrentFile(archive);
		entryOpen = false;
		output.flush();
		if(closeResult != UNZ_OK || !output.good())
			return false;
		output.close();
		if(output.fail())
			return false;

		success = true;
		return true;
	}
	catch(const std::exception & exception)
	{
		logGlobal->error("Failed to extract '%s': %s", relativeName.c_str(), exception.what());
		return false;
	}
}

VCMI_LIB_NAMESPACE_END
