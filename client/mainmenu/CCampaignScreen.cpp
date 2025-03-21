/*
 * CCampaignScreen.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */

#include "StdInc.h"
#include "CCampaignScreen.h"

#include "CMainMenu.h"

#include "../CPlayerInterface.h"
#include "../CServerHandler.h"
#include "../GameEngine.h"
#include "../gui/Shortcut.h"
#include "../media/IMusicPlayer.h"
#include "../render/Canvas.h"
#include "../widgets/CComponent.h"
#include "../widgets/Buttons.h"
#include "../widgets/MiscWidgets.h"
#include "../widgets/ObjectLists.h"
#include "../widgets/TextControls.h"
#include "../widgets/VideoWidget.h"
#include "../windows/GUIClasses.h"
#include "../windows/InfoWindows.h"
#include "../windows/CWindowObject.h"

#include "../../lib/filesystem/Filesystem.h"
#include "../../lib/texts/CGeneralTextHandler.h"

#include "../../lib/CArtHandler.h"
#include "../../lib/spells/CSpellHandler.h"
#include "../../lib/CConfigHandler.h"
#include "../../lib/CSkillHandler.h"
#include "../../lib/CCreatureHandler.h"

#include "../../lib/campaign/CampaignHandler.h"
#include "../../lib/mapping/CMapService.h"

#include "../../lib/mapObjects/CGHeroInstance.h"

CCampaignScreen::CCampaignScreen(const JsonNode & config, std::string name)
	: CWindowObject(BORDERED), campaignSet(name)
{
	OBJECT_CONSTRUCTION;

	for(const JsonNode & node : config[name]["images"].Vector())
		images.push_back(CMainMenu::createPicture(node));

	if(!images.empty())
	{
		images[0]->center(); // move background to center
		moveTo(images[0]->pos.topLeft()); // move everything else to center
		images[0]->moveTo(pos.topLeft()); // restore moved twice background
		pos = images[0]->pos; // fix height\width of this window
	}

	if(!config[name]["exitbutton"].isNull())
	{
		buttonBack = createExitButton(config[name]["exitbutton"]);
		buttonBack->setHoverable(true);
	}

	for(const JsonNode & node : config[name]["items"].Vector())
		if(CResourceHandler::get()->existsResource(ResourcePath(node["file"].String(), EResType::CAMPAIGN)))
			campButtons.push_back(std::make_shared<CCampaignButton>(node, config, campaignSet));
}

void CCampaignScreen::activate()
{
	ENGINE->music().playMusic(AudioPath::builtin("Music/MainMenu"), true, false);

	CWindowObject::activate();
}

std::shared_ptr<CButton> CCampaignScreen::createExitButton(const JsonNode & button)
{
	std::pair<std::string, std::string> help;
	if(!button["help"].isNull() && button["help"].Float() > 0)
		help = LIBRARY->generaltexth->zelp[(size_t)button["help"].Float()];

	return std::make_shared<CButton>(Point((int)button["x"].Float(), (int)button["y"].Float()), AnimationPath::fromJson(button["name"]), help, [this](){ close();}, EShortcut::GLOBAL_CANCEL);
}

CCampaignScreen::CCampaignButton::CCampaignButton(const JsonNode & config, const JsonNode & parentConfig, std::string campaignSet)
	: campaignSet(campaignSet)
{
	OBJECT_CONSTRUCTION;

	pos.x += static_cast<int>(config["x"].Float());
	pos.y += static_cast<int>(config["y"].Float());
	pos.w = 200;
	pos.h = 116;

	campFile = config["file"].String();
	videoPath = VideoPath::fromJson(config["video"]);

	status = CCampaignScreen::ENABLED;

	auto header = CampaignHandler::getHeader(campFile);
	hoverText = header->getNameTranslated();

	if(persistentStorage["completedCampaigns"][header->getFilename()].Bool())
		status = CCampaignScreen::COMPLETED;

	for(const JsonNode & node : parentConfig[campaignSet]["items"].Vector())
	{
		for(const JsonNode & requirement : config["requires"].Vector())
		{
			if(node["id"].Integer() == requirement.Integer())
				if(!persistentStorage["completedCampaigns"][node["file"].String()].Bool())
					status = CCampaignScreen::DISABLED;
		}
	}

	if(persistentStorage["unlockAllCampaigns"].Bool())
		status = CCampaignScreen::ENABLED;

	if(status != CCampaignScreen::DISABLED)
	{
		addUsedEvents(LCLICK | HOVER);
		graphicsImage = std::make_shared<CPicture>(ImagePath::fromJson(config["image"]));
		hoverLabel = std::make_shared<CLabel>(pos.w / 2, pos.h + 20, FONT_MEDIUM, ETextAlignment::CENTER, Colors::YELLOW, "");
		parent->addChild(hoverLabel.get());
	}

	if(status == CCampaignScreen::COMPLETED)
		graphicsCompleted = std::make_shared<CPicture>(ImagePath::builtin("CAMPCHK"));
}

void CCampaignScreen::CCampaignButton::clickReleased(const Point & cursorPosition)
{
	CMainMenu::openCampaignLobby(campFile, campaignSet);
}

void CCampaignScreen::CCampaignButton::hover(bool on)
{
	OBJECT_CONSTRUCTION;

	if (on && !videoPath.empty())
		videoPlayer = std::make_shared<VideoWidget>(Point(), videoPath, false);
	else
		videoPlayer.reset();

	if(hoverLabel)
	{
		if(on)
			hoverLabel->setText(hoverText); // Shows the name of the campaign when you get into the bounds of the button
		else
			hoverLabel->setText(" ");
	}
}
