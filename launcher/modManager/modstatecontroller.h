/*
 * modstatecontroller.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

#include <QString>
#include <QStringList>
#include <QVector>

#include <atomic>
#include <mutex>

VCMI_LIB_NAMESPACE_BEGIN
class JsonNode;
VCMI_LIB_NAMESPACE_END

class ModStateModel;

class ModStateController : public QObject, public boost::noncopyable
{
	Q_OBJECT

public:
	struct ArchiveImportResult
	{
		QStringList installedMods;
		QStringList errors;
		bool canceled = false;
		bool mapArchive = false;
	};

	struct ArchiveImportProgress
	{
		std::atomic<quint64> completedBytes{0};
		std::atomic<quint64> totalBytes{0};
		std::atomic<int> completedMods{0};
		std::atomic<int> totalMods{0};
		std::atomic<bool> canceled{false};

		void setCurrentMod(const QString & name)
		{
			std::lock_guard<std::mutex> lock(currentModMutex);
			currentModName = name;
		}

		QString getCurrentMod() const
		{
			std::lock_guard<std::mutex> lock(currentModMutex);
			return currentModName;
		}

	private:
		mutable std::mutex currentModMutex;
		QString currentModName;
	};

private:
	std::shared_ptr<ModStateModel> modList;

	// check-free version of public method
	bool doUninstallMod(QString mod);

	static QString getStagingPath(const QString & modname);
	static QString getBackupPath(const QString & modname);
	/// Returns directory of a mod located in user Mods directory, matched case-insensitively, or empty string if none
	static QString findModDirectory(const QString & modname);

	QStringList recentErrors;
	bool addError(QString modname, QString message);
	static bool removeModDir(QString mod);

public:
	ModStateController(std::shared_ptr<ModStateModel> modList);
	~ModStateController();

	void setRepositoryData(const JsonNode & repositoriesList);

	QStringList getErrors();

	/// Installs every mod found in the archive. File system only, safe to run outside the GUI thread.
	static ArchiveImportResult installArchive(const QString & archivePath, const QString & modIdHint, bool fullModExtraction, ArchiveImportProgress & progress);

	/// Derives the mod ID from the archive filename, optionally removing GitHub zip suffixes.
	static QString modIdFromArchivePath(const QString & archivePath, bool removeGithubSuffix = false);

	/// mod management functions. Return true if operation was successful

	bool uninstallMod(QString mod);
	bool enableMods(QStringList mod);
	/// Enables every mod from the list that can be enabled, skipping the rest
	void enableAvailableMods(QStringList mod);
	bool disableMod(QString mod);

	bool canInstallMod(QString mod);
	bool canUninstallMod(QString mod);
	bool canEnableMod(QString mod, bool reportError = true);
	bool canDisableMod(QString mod);
};
