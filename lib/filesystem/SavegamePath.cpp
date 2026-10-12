/*
 * SavegamePath.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "StdInc.h"
#include "SavegamePath.h"

#include <boost/algorithm/string/predicate.hpp>

#include <algorithm>
#include <cctype>

VCMI_LIB_NAMESPACE_BEGIN

namespace
{
const std::string autosavePrefix = "Autosave-";
}

std::string SavegamePath::getAutosaveFilename(int month, int week, int dayOfWeek)
{
	return autosavePrefix + std::to_string(month) + std::to_string(week) + std::to_string(dayOfWeek);
}

bool SavegamePath::isAutosaveName(const std::string & filename)
{
	const size_t separator = filename.find_last_of("/\\");
	std::string name = separator == std::string::npos ? filename : filename.substr(separator + 1);
	if(boost::iends_with(name, ".vsgm1"))
		name.resize(name.size() - 6);

	if(!boost::istarts_with(name, autosavePrefix) || name.size() == autosavePrefix.size())
		return false;

	return std::all_of(name.begin() + autosavePrefix.size(), name.end(), [](unsigned char character)
	{
		return std::isdigit(character);
	});
}

VCMI_LIB_NAMESPACE_END
