/*
 * SavegamePath.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

VCMI_LIB_NAMESPACE_BEGIN

/// Constructs names for automatically created savegames and recognizes them
class DLL_LINKAGE SavegamePath final
{
public:
	/// Constructs name for an autosave, e.g. "Autosave-112" for month 1, week 1, day of week 2
	static std::string getAutosaveFilename(int month, int week, int dayOfWeek);

	/// Checks if a savegame with such name was created by the autosave system
	static bool isAutosaveName(const std::string & filename);
};

VCMI_LIB_NAMESPACE_END
