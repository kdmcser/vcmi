/*
 * EntryPoint.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */

// EntryPoint.cpp : Defines the entry point for the console application.

#include "StdInc.h"
#include "../Global.h"

#include "../client/ClientCommandManager.h"
#include "../client/CMT.h"
#include "../client/CPlayerInterface.h"
#include "../client/CServerHandler.h"
#include "../client/GameEngine.h"
#include "../client/GameInstance.h"
#include "../client/gui/CursorHandler.h"
#include "../client/gui/WindowHandler.h"
#include "../client/mainmenu/CMainMenu.h"
#include "../client/render/Graphics.h"
#include "../client/render/IRenderHandler.h"
#include "../client/windows/CMessage.h"
#include "../client/windows/InfoWindows.h"

#include "../lib/AsyncRunner.h"
#include "../lib/CConsoleHandler.h"
#include "../lib/CConfigHandler.h"
#include "../lib/CThreadHelper.h"
#include "../lib/ExceptionsCommon.h"
#include "../lib/filesystem/Filesystem.h"
#include "../lib/logging/CBasicLogConfigurator.h"
#include "../lib/modding/IdentifierStorage.h"
#include "../lib/modding/CModHandler.h"
#include "../lib/modding/ModDescription.h"
#include "../lib/texts/MetaString.h"
#include "../lib/GameLibrary.h"
#include "../lib/ScopeGuard.h"
#include "../lib/VCMIDirs.h"

#include <boost/program_options.hpp>
#include <vstd/StringUtils.h>

#include <SDL_main.h>
#include <SDL.h>

#ifdef VCMI_ANDROID
#include "../lib/CAndroidVMHelper.h"
#include <SDL_system.h>
#endif

#if __MINGW32__
#undef main
#endif

namespace po = boost::program_options;
namespace po_style = boost::program_options::command_line_style;

static std::atomic<bool> headlessQuit = false;
static std::optional<std::string> criticalInitializationError;

static void init()
{
	try
	{
		CStopWatch tmh;
		LIBRARY->initializeLibrary();
		logGlobal->info("Initializing VCMI_Lib: %d ms", tmh.getDiff());
	}
	catch (const DataLoadingException & e)
	{
		criticalInitializationError = e.what();
		return;
	}

	// Debug code to load all maps on start
	//ClientCommandManager commandController;
	//commandController.processCommand("translate maps", false);
}

static void checkForModLoadingFailure()
{
	const auto & brokenMods = LIBRARY->identifiersHandler->getModsWithFailedRequests();
	if (!brokenMods.empty())
	{
		MetaString messageText;
		messageText.appendTextID("vcmi.client.errors.modLoadingFailure");

		for (const auto & modID : brokenMods)
		{
			messageText.appendRawString(LIBRARY->modh->getModInfo(modID).getName());
			messageText.appendEOL();
		}
		CInfoWindow::showInfoDialog(messageText.toString(), {});
	}
}

static void prog_version()
{
	printf("%s\n", GameConstants::VCMI_VERSION.c_str());
	std::cout << VCMIDirs::get().genHelpString();
}

static void prog_help(const po::options_description &opts)
{
	auto time = std::time(nullptr);
	printf("%s - A Heroes of Might and Magic 3 clone\n", GameConstants::VCMI_VERSION.c_str());
	printf("Copyright (C) 2007-%d VCMI dev team - see AUTHORS file\n", std::localtime(&time)->tm_year + 1900);
	printf("This is free software; see the source for copying conditions. There is NO\n");
	printf("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
	printf("\n");
	std::cout << opts;
}

#if defined(VCMI_WINDOWS) && !defined(__GNUC__) && defined(VCMI_WITH_DEBUG_CONSOLE)
int wmain(int argc, wchar_t* argv[])
#elif defined(VCMI_MOBILE)
int SDL_main(int argc, char *argv[])
#else
int main(int argc, char * argv[])
#endif
{
#ifdef VCMI_ANDROID
	CAndroidVMHelper::initClassloader(SDL_AndroidGetJNIEnv());
	// boost will crash without this
	setenv("LANG", "C", 1);
#endif

#if !defined(VCMI_MOBILE)
	// Correct working dir executable folder (not bundle folder) so we can use executable relative paths
	boost::filesystem::current_path(boost::filesystem::system_complete(argv[0]).parent_path());
#endif
	std::cout << "Starting... " << std::endl;
	po::options_description opts("Allowed options");
	po::variables_map vm;

	opts.add_options()
		("help,h", "display help and exit")
		("version,v", "display version information and exit")
		("testmap", po::value<std::string>(), "")
		("testsave", po::value<std::string>(), "")
		("logLocation", po::value<std::string>(), "new location for log files")
		("spectate,s", "enable spectator interface for AI-only games")
		("spectate-ignore-hero", "wont follow heroes on adventure map")
		("spectate-hero-speed", po::value<int>(), "hero movement speed on adventure map")
		("spectate-battle-speed", po::value<int>(), "battle animation speed for spectator")
		("spectate-skip-battle", "skip battles in spectator view")
		("spectate-skip-battle-result", "skip battle result window")
		("onlyAI", "allow one to run without human player, all players will be default AI")
		("headless", "runs without GUI, implies --onlyAI")
		("ai", po::value<std::vector<std::string>>(), "AI to be used for the player, can be specified several times for the consecutive players")
		("oneGoodAI", "puts one default AI and the rest will be EmptyAI")
		("autoSkip", "automatically skip turns in GUI")
		("disable-video", "disable video player")
		("nointro,i", "skips intro movies")
		("donotstartserver,d","do not attempt to start server and just connect to it instead server")
		("serverport", po::value<si64>(), "override port specified in config file")
		("savefrequency", po::value<si64>(), "limit auto save creation to each N days");

	if(argc > 1)
	{
		try
		{
			po::store(po::parse_command_line(argc, argv, opts, po_style::unix_style|po_style::case_insensitive), vm);
		}
		catch(boost::program_options::error &e)
		{
			std::cerr << "Failure during parsing command-line options:\n" << e.what() << std::endl;
		}
	}

	po::notify(vm);
	if(vm.count("help"))
	{
		prog_help(opts);
#ifdef VCMI_IOS
		exit(0);
#else
		return 0;
#endif
	}
	if(vm.count("version"))
	{
		prog_version();
#ifdef VCMI_IOS
		exit(0);
#else
		return 0;
#endif
	}

	// Init old logging system and new (temporary) logging system
	CStopWatch total;
	CStopWatch pomtime;
	std::cout.flags(std::ios::unitbuf);

	setThreadNameLoggingOnly("MainGUI");
	boost::filesystem::path logPath = VCMIDirs::get().userLogsPath() / "VCMI_Client_log.txt";
	if(vm.count("logLocation"))
		logPath = vm["logLocation"].as<std::string>() + "/VCMI_Client_log.txt";

#ifndef VCMI_IOS

	auto callbackFunction = [](std::string buffer, bool calledFromIngameConsole)
	{
		ClientCommandManager commandController;
		commandController.processCommand(buffer, calledFromIngameConsole);
	};

	CConsoleHandler console(callbackFunction);
	console.start();

	CBasicLogConfigurator logConfigurator(logPath, &console);
#else
	CBasicLogConfigurator logConfigurator(logPath, nullptr);
#endif

	logConfigurator.configureDefault();
	logGlobal->info("Starting client of '%s'", GameConstants::VCMI_VERSION);
	logGlobal->info("Creating console and configuring logger: %d ms", pomtime.getDiff());
	logGlobal->info("The log file will be saved to %s", logPath);

	// Init filesystem and settings
	try
	{
		LIBRARY = new GameLibrary;
		LIBRARY->initializeFilesystem(false);
	}
	catch (const DataLoadingException & e)
	{
		handleFatalError(e.what(), true);
	}

	Settings session = settings.write["session"];
	auto setSettingBool = [&](const std::string & key, const std::string & arg) {
		Settings s = settings.write(vstd::split(key, "/"));
		if(vm.count(arg))
			s->Bool() = true;
		else if(s->isNull())
			s->Bool() = false;
	};
	auto setSettingInteger = [&](const std::string & key, const std::string & arg, si64 defaultValue) {
		Settings s = settings.write(vstd::split(key, "/"));
		if(vm.count(arg))
			s->Integer() = vm[arg].as<si64>();
		else if(s->isNull())
			s->Integer() = defaultValue;
	};

	setSettingBool("session/onlyai", "onlyAI");
	setSettingBool("session/disableVideo", "disable-video");
	if(vm.count("headless"))
	{
		session["headless"].Bool() = true;
		session["onlyai"].Bool() = true;
	}
	else if(vm.count("spectate"))
	{
		session["spectate"].Bool() = true;
		session["spectate-ignore-hero"].Bool() = vm.count("spectate-ignore-hero");
		session["spectate-skip-battle"].Bool() = vm.count("spectate-skip-battle");
		session["spectate-skip-battle-result"].Bool() = vm.count("spectate-skip-battle-result");
		if(vm.count("spectate-hero-speed"))
			session["spectate-hero-speed"].Integer() = vm["spectate-hero-speed"].as<int>();
		if(vm.count("spectate-battle-speed"))
			session["spectate-battle-speed"].Float() = vm["spectate-battle-speed"].as<int>();
	}
	// Server settings
	setSettingBool("session/donotstartserver", "donotstartserver");

	// Init special testing settings
	setSettingInteger("session/serverport", "serverport", 0);
	setSettingInteger("general/saveFrequency", "savefrequency", 1);

	// Initialize logging based on settings
	logConfigurator.configure();
	logGlobal->debug("settings = %s", settings.toJsonNode().toString());

	try
	{
		// Some basic data validation to produce better error messages in cases of incorrect install
		auto testFile = [](const std::string & filename, const std::string & message)
		{
			if (!CResourceHandler::get()->existsResource(ResourcePath(filename)))
				handleFatalError(message, false);
		};

		testFile("DATA/HELP.TXT", "VCMI requires Heroes III: Shadow of Death or Heroes III: Complete data files to run!");
		testFile("DATA/TENTCOLR.TXT", "Heroes III: Restoration of Erathia (including HD Edition) data files are not supported!");
		testFile("MODS/VCMI/MOD.JSON", "VCMI installation is corrupted!\nBuilt-in mod was not found!");
		testFile("DATA/NOTOSERIF-MEDIUM.TTF", "VCMI installation is corrupted!\nBuilt-in font was not found!\nManually deleting '" + VCMIDirs::get().userDataPath().string() + "/Mods/VCMI' directory (if it exists)\nor clearing app data and reimporting Heroes III files may fix this problem.");
		testFile("DATA/PLAYERS.PAL", "Heroes III data files (Data/H3Bitmap.lod) are incomplete or corruped!\n Please reinstall them.");
		testFile("SPRITES/DEFAULT.DEF", "Heroes III data files (Data/H3Sprite.lod) are incomplete or corruped!\n Please reinstall them.");

		if(!settings["session"]["headless"].Bool())
			ENGINE = std::make_unique<GameEngine>();

		GAME = std::make_unique<GameInstance>();

		if (ENGINE)
			ENGINE->setEngineUser(GAME.get());
	
#ifndef VCMI_NO_THREADED_LOAD
		//we can properly play intro only in the main thread, so we have to move loading to the separate thread
		std::thread loading([]()
		{
			setThreadName("initialize");
			init();
		});
#else
		init();
#endif

#ifndef VCMI_NO_THREADED_LOAD
	#ifdef VCMI_ANDROID // android loads the data quite slowly so we display native progressbar to prevent having only black screen for few seconds
		{
			CAndroidVMHelper vmHelper;
			vmHelper.callStaticVoidMethod(CAndroidVMHelper::NATIVE_METHODS_DEFAULT_CLASS, "showProgress");
	#endif // ANDROID
			loading.join();
	#ifdef VCMI_ANDROID
			vmHelper.callStaticVoidMethod(CAndroidVMHelper::NATIVE_METHODS_DEFAULT_CLASS, "hideProgress");
		}
	#endif // ANDROID
#endif // THREADED

		if (criticalInitializationError.has_value())
		{
			handleFatalError(criticalInitializationError.value(), false);
		}

		if (ENGINE)
		{
			pomtime.getDiff();
			graphics = new Graphics(); // should be before curh
			ENGINE->renderHandler().onLibraryLoadingFinished(LIBRARY);

			CMessage::init();
			logGlobal->info("Message handler: %d ms", pomtime.getDiff());

			ENGINE->cursor().init();
			ENGINE->cursor().show();
		}

		logGlobal->info("Initialization of VCMI (together): %d ms", total.getDiff());

		session["autoSkip"].Bool()  = vm.count("autoSkip");
		session["oneGoodAI"].Bool() = vm.count("oneGoodAI");
		session["aiSolo"].Bool() = false;
	
		if(vm.count("testmap"))
		{
			session["testmap"].String() = vm["testmap"].as<std::string>();
			session["onlyai"].Bool() = true;
			GAME->server().debugStartTest(session["testmap"].String(), false);
		}
		else if(vm.count("testsave"))
		{
			session["testsave"].String() = vm["testsave"].as<std::string>();
			session["onlyai"].Bool() = true;
			GAME->server().debugStartTest(session["testsave"].String(), true);
		}
		else if (!settings["session"]["headless"].Bool())
		{
			GAME->mainmenu()->makeActiveInterface();

			bool playIntroVideo = !vm.count("battle") && !vm.count("nointro") && settings["video"]["showIntro"].Bool();
			if(playIntroVideo)
				GAME->mainmenu()->playIntroVideos();
			else
				GAME->mainmenu()->playMusic();
		}
	
#ifndef VCMI_UNIX
		// on Linux, name of main thread is also name of our process. Which we don't want to change
		setThreadName("MainGUI");
#endif

		const auto & runMainLoop = []()
		{
			try
			{
				if (ENGINE)
				{
					checkForModLoadingFailure();
					std::string content = R"({关于后续贴吧发布的声明}

因本人在英雄无敌3吧遭遇多轮封禁，此前发布的“英雄无敌3增强版VCMI”及“英雄无敌3亚山之泪”相关资源帖也已被删除。鉴于目前的情况，后续恐难以继续在该吧正常发布相关内容（事情经过详见B站凤凰如梦UP主发布的图文帖：“关于我被英雄无敌3吧吧务封禁+删贴情况说明”）。因此，今后上述模组合集及更新内容，将移步至VCMI吧发布。还请各位贴吧的朋友关注VCMI吧，也恳请大家为相关模组更新帖点赞、互动，以便让内容能够被贴吧算法推荐给更多未关注VCMI吧的玩家。感谢大家一直以来的关注与支持。

凤凰如梦
2026年8月18日
                    
{英雄无敌3增强版VCMI团队声明}

英雄无敌3增强版VCMI团队（以下简称“本团队”）对英雄无敌3增强版VCMI（以下简称“本Mod”）郑重声明如下：
本团队对本Mod原创内容依法享有著作权。在本团队未书面授权的情况下，不得对本Mod进行商业化使用，包括但不限于以下形式：
1.利用本Mod制作宣传素材（包括视频、图像、音频等），并在宣传素材内对收费群聊或付费网站进行引流。
2.分享本Mod的同时接受捐赠或定向红包，或在收费群聊内分享本Mod（设定达到一定活跃度或其他门槛，但可直接付费跳过门槛的群聊也属于收费群聊）。
3.分享本Mod时隐匿原作者信息，或制作宣传素材时未标明原作者信息。
4.在电商平台（淘宝、闲鱼、拼多多、抖音等）上售卖本Mod。
5.其他形式利用本Mod进行的商业化行为。

本团队花费巨量精力制作本Mod，旨在为英雄无敌3玩家提供更多的游玩乐趣。如果有人利用本团队的辛苦劳动成果获取商业利益，将对我们的创作积极性造成巨大打击。如果你喜欢本Mod，愿意支持我们，请对违反上述许可的行为进行如下操作：
1.举报侵权平台。如果你在QQ群、微信群里发现侵权行为，请举报群聊，说明群聊内存在涉嫌侵犯著作权行为（举报是完全匿名的，群主、管理和其他群员无法得知）；如果你在电商网站上发现本Mod被售卖，请直接向电商平台举报店铺的涉嫌侵权行为（举报也是完全匿名的，店主无法得知）。
2.百度搜索国家版权局举报，或访问网站（www.ncac.gov.cn/bsfw/zxjb）对通过QQ群、店铺或其他途径的涉嫌侵权行为进行举报。
3.如果你已付费，可以将此界面截图并到12315（www.12315.cn）举报商家的涉嫌侵权行为。若商家在销售过程中存在欺诈行为（如冒充正版、虚假宣传），你可以依据《消费者权益保护法》第五十五条主张退款并要求{#FF0000|三倍价款}赔偿（增加赔偿的金额不足{#FF0000|五百元}的，按{#FF0000|五百元}计算）；即使不构成欺诈，你也可以要求商家退还货款。如果你无法获得商家信息，可以直接向12315投诉平台反映。你获得的赔偿数额将取决于你提交的证据，并由相关执法机关依法认定。
4.将侵权行为告知本团队作者（在制作组中可以查看英雄无敌3增强版VCMI作者信息）。
本团队拥有2名执业律师，将依法维护本团队的著作权。本声明不影响原游戏及相关权利人依法享有的合法权益。

英雄无敌3增强版VCMI团队
2026年2月19日)";
					CInfoWindow::CInfoWindow::showInfoDialog(content, {});
					ENGINE->mainLoop();
				}
				else
				{
					while(!headlessQuit)
						std::this_thread::sleep_for(std::chrono::milliseconds(200));

					std::this_thread::sleep_for(std::chrono::milliseconds(500));
				}
			}
			catch (const GameShutdownException & )
			{
				// no-op - just break out of main loop
				logGlobal->info("Main loop termination requested");
			}
		};

		const auto & cleanupEngine = [&logConfigurator]()
		{
			GAME->server().endNetwork();

			if(!settings["session"]["headless"].Bool())
			{
				if(GAME->server().client)
					GAME->server().endGameplay();

				if (ENGINE)
					ENGINE->windows().clear();
			}

			GAME.reset();

			if(!settings["session"]["headless"].Bool())
			{
				CMessage::dispose();
				delete graphics;
				graphics = nullptr;
			}

			// must be executed before reset - since unique_ptr resets pointer to null before calling destructor
			ENGINE->async().wait();

			ENGINE.reset();

			delete LIBRARY;
			LIBRARY = nullptr;
			logConfigurator.deconfigure();

			std::cout << "Ending...\n";
		};

		auto onExit = vstd::makeScopeGuard(cleanupEngine);
		runMainLoop();
	}
	catch (const GameShutdownException &)
	{
		logGlobal->info("Shutdown requested during initialization");
	}
	return 0;
}

/// Notify user about encountered fatal error and terminate the game
/// TODO: decide on better location for this method
void handleFatalError(const std::string & message, bool terminate)
{
	logGlobal->error("FATAL ERROR ENCOUNTERED, VCMI WILL NOW TERMINATE");
	logGlobal->error("Reason: %s", message);

	std::string messageToShow = "Fatal error! " + message;

	SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Fatal error!", messageToShow.c_str(), nullptr);

	if (terminate)
		throw std::runtime_error(message);
	else
		throw GameShutdownException();
}
