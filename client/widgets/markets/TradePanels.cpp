/*
 * TradePanels.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "StdInc.h"
#include "TradePanels.h"

#include "../../gui/CGuiHandler.h"
#include "../../render/Canvas.h"
#include "../../widgets/TextControls.h"
#include "../../windows/InfoWindows.h"

#include "../../CGameInfo.h"
#include "../../CPlayerInterface.h"

#include "../../../CCallback.h"

#include "../../../lib/CGeneralTextHandler.h"
#include "../../../lib/mapObjects/CGHeroInstance.h"

CTradeableItem::CTradeableItem(const Rect & area, EType Type, int ID, int Serial)
	: SelectableSlot(area, Point(1, 2))
	, artInstance(nullptr)
	, type(EType(-1)) // set to invalid, will be corrected in setType
	, id(ID)
	, serial(Serial)
{
	OBJECT_CONSTRUCTION_CAPTURING(255 - DISPOSE);

	addUsedEvents(LCLICK);
	addUsedEvents(HOVER);
	addUsedEvents(SHOW_POPUP);
	
	subtitle = std::make_shared<CLabel>(0, 0, FONT_SMALL, ETextAlignment::CENTER, Colors::WHITE);
	setType(Type);

	this->pos.w = area.w;
	this->pos.h = area.h;
}

void CTradeableItem::setType(EType newType)
{
	if(type != newType)
	{
		OBJECT_CONSTRUCTION_CUSTOM_CAPTURING(255 - DISPOSE);
		type = newType;

		if(getIndex() < 0)
		{
			image = std::make_shared<CAnimImage>(getFilename(), 0);
			image->disable();
		}
		else
		{
			image = std::make_shared<CAnimImage>(getFilename(), getIndex());
		}

		switch(type)
		{
		case EType::RESOURCE:
			subtitle->moveTo(pos.topLeft() + Point(35, 55));
			image->moveTo(pos.topLeft() + Point(19, 8));
			break;
		case EType::CREATURE_PLACEHOLDER:
		case EType::CREATURE:
			subtitle->moveTo(pos.topLeft() + Point(30, 77));
			break;
		case EType::PLAYER:
			subtitle->moveTo(pos.topLeft() + Point(31, 76));
			break;
		case EType::ARTIFACT_PLACEHOLDER:
		case EType::ARTIFACT_INSTANCE:
			break;
		case EType::ARTIFACT_TYPE:
			subtitle->moveTo(pos.topLeft() + Point(35, 57));
			image->moveTo(pos.topLeft() + Point(13, 0));
			break;
		}
	}
}

void CTradeableItem::setID(int newID)
{
	if(id != newID)
	{
		id = newID;
		if(image)
		{
			int index = getIndex();
			if(index < 0)
				image->disable();
			else
			{
				image->enable();
				image->setFrame(index);
			}
		}
	}
}

AnimationPath CTradeableItem::getFilename()
{
	switch(type)
	{
	case EType::RESOURCE:
		return AnimationPath::builtin("RESOURCE");
	case EType::PLAYER:
		return AnimationPath::builtin("CREST58");
	case EType::ARTIFACT_TYPE:
	case EType::ARTIFACT_PLACEHOLDER:
	case EType::ARTIFACT_INSTANCE:
		return AnimationPath::builtin("artifact");
	case EType::CREATURE:
		return AnimationPath::builtin("TWCRPORT");
	default:
		return {};
	}
}

int CTradeableItem::getIndex()
{
	if(id < 0)
		return -1;

	switch(type)
	{
	case EType::RESOURCE:
	case EType::PLAYER:
		return id;
	case EType::ARTIFACT_TYPE:
	case EType::ARTIFACT_INSTANCE:
	case EType::ARTIFACT_PLACEHOLDER:
		return CGI->artifacts()->getByIndex(id)->getIconIndex();
	case EType::CREATURE:
		return CGI->creatures()->getByIndex(id)->getIconIndex();
	default:
		return -1;
	}
}

void CTradeableItem::clickPressed(const Point & cursorPosition)
{
	if(clickPressedCallback)
		clickPressedCallback(shared_from_this());
}

void CTradeableItem::hover(bool on)
{
	if(!on)
	{
		GH.statusbar()->clear();
		return;
	}

	switch(type)
	{
	case EType::CREATURE:
	case EType::CREATURE_PLACEHOLDER:
		GH.statusbar()->write(boost::str(boost::format(CGI->generaltexth->allTexts[481]) % CGI->creh->objects[id]->getNamePluralTranslated()));
		break;
	case EType::ARTIFACT_TYPE:
	case EType::ARTIFACT_PLACEHOLDER:
		if(id < 0)
			GH.statusbar()->write(CGI->generaltexth->zelp[582].first);
		else
			GH.statusbar()->write(CGI->artifacts()->getByIndex(id)->getNameTranslated());
		break;
	case EType::RESOURCE:
		GH.statusbar()->write(CGI->generaltexth->restypes[id]);
		break;
	case EType::PLAYER:
		GH.statusbar()->write(CGI->generaltexth->capColors[id]);
		break;
	}
}

void CTradeableItem::showPopupWindow(const Point & cursorPosition)
{
	switch(type)
	{
	case EType::CREATURE:
	case EType::CREATURE_PLACEHOLDER:
		break;
	case EType::ARTIFACT_TYPE:
	case EType::ARTIFACT_PLACEHOLDER:
		//TODO: it's would be better for market to contain actual CArtifactInstance and not just ids of certain artifact type so we can use getEffectiveDescription.
		if (id >= 0)
			CRClickPopup::createAndPush(CGI->artifacts()->getByIndex(id)->getDescriptionTranslated());
		break;
	}
}

const CArtifactInstance* CTradeableItem::getArtInstance() const
{
	switch(type)
	{
	case EType::ARTIFACT_PLACEHOLDER:
	case EType::ARTIFACT_INSTANCE:
		return artInstance;
	default:
		return nullptr;
	}
}

void CTradeableItem::setArtInstance(const CArtifactInstance * art)
{
	assert(type == EType::ARTIFACT_PLACEHOLDER || type == EType::ARTIFACT_INSTANCE);
	artInstance = art;
	if(art)
		setID(art->getTypeId());
	else
		setID(-1);
}

void TradePanelBase::updateSlots()
{
	if(deleteSlotsCheck)
		slots.erase(std::remove_if(slots.begin(), slots.end(), deleteSlotsCheck), slots.end());

	if(updateSlotsCallback)
		updateSlotsCallback();
}

void TradePanelBase::deselect()
{
	for(const auto & slot : slots)
		slot->selectSlot(false);
}

void TradePanelBase::clearSubtitles()
{
	for(const auto & slot : slots)
		slot->subtitle->clear();
}

void TradePanelBase::updateOffer(CTradeableItem & slot, int cost, int qty)
{
	std::string subtitle = std::to_string(qty);
	if(cost != 1)
	{
		subtitle.append("/");
		subtitle.append(std::to_string(cost));
	}
	slot.subtitle->setText(subtitle);
}

void TradePanelBase::setSelectedFrameIndex(const std::optional<size_t> & index)
{
	if(index.has_value())
	{
		selectedSlot->image->enable();
		selectedSlot->image->setFrame(index.value());
	}
	else
	{
		selectedSlot->image->disable();
		selectedSlot->image->setFrame(0);
	}
}

void TradePanelBase::setSelectedSubtitleText(const std::string & text)
{
	selectedSlot->subtitle->setText(text);
}

void TradePanelBase::clearSelectedSubtitleText()
{
	selectedSlot->subtitle->clear();
}

ResourcesPanel::ResourcesPanel(const CTradeableItem::ClickPressedFunctor & clickPressedCallback,
	const UpdateSlotsFunctor & updateSubtitles)
{
	assert(resourcesForTrade.size() == slotsPos.size());
	OBJECT_CONSTRUCTION_CUSTOM_CAPTURING(255 - DISPOSE);

	for(const auto & res : resourcesForTrade)
	{
		auto slot = slots.emplace_back(std::make_shared<CTradeableItem>(Rect(slotsPos[res.num], slotDimension), EType::RESOURCE, res.num, res.num));
		slot->clickPressedCallback = clickPressedCallback;
		slot->setSelectionWidth(selectionWidth);
	}
	updateSlotsCallback = updateSubtitles;
	selectedSlot = std::make_shared<CTradeableItem>(Rect(selectedPos, slotDimension), EType::RESOURCE, 0, 0);
}

ArtifactsPanel::ArtifactsPanel(const CTradeableItem::ClickPressedFunctor & clickPressedCallback,
	const UpdateSlotsFunctor & updateSubtitles, const std::vector<TradeItemBuy> & arts)
{
	assert(slotsForTrade == slotsPos.size());
	assert(slotsForTrade == arts.size());
	OBJECT_CONSTRUCTION_CUSTOM_CAPTURING(255 - DISPOSE);

	for(auto slotIdx = 0; slotIdx < slotsForTrade; slotIdx++)
	{
		auto artType = arts[slotIdx].getNum();
		if(artType != ArtifactID::NONE)
		{
			auto slot = slots.emplace_back(std::make_shared<CTradeableItem>(Rect(slotsPos[slotIdx], slotDimension),
				EType::ARTIFACT_TYPE, artType, slotIdx));
			slot->clickPressedCallback = clickPressedCallback;
			slot->setSelectionWidth(selectionWidth);
		}
	}
	updateSlotsCallback = updateSubtitles;
	selectedSlot = std::make_shared<CTradeableItem>(Rect(selectedPos, slotDimension), EType::ARTIFACT_TYPE, 0, 0);
}

PlayersPanel::PlayersPanel(const CTradeableItem::ClickPressedFunctor & clickPressedCallback)
{
	assert(PlayerColor::PLAYER_LIMIT_I <= slotsPos.size() + 1);
	OBJECT_CONSTRUCTION_CUSTOM_CAPTURING(255 - DISPOSE);

	std::vector<PlayerColor> players;
	for(auto player = PlayerColor(0); player < PlayerColor::PLAYER_LIMIT_I; player++)
	{
		if(player != LOCPLINT->playerID && LOCPLINT->cb->getPlayerStatus(player) == EPlayerStatus::INGAME)
			players.emplace_back(player);
	}

	slots.resize(players.size());
	int slotNum = 0;
	for(auto & slot : slots)
	{
		slot = std::make_shared<CTradeableItem>(Rect(slotsPos[slotNum], slotDimension), EType::PLAYER, players[slotNum].num, slotNum);
		slot->clickPressedCallback = clickPressedCallback;
		slot->setSelectionWidth(selectionWidth);
		slot->subtitle->setText(CGI->generaltexth->capColors[players[slotNum].num]);
		slotNum++;
	}
	selectedSlot = std::make_shared<CTradeableItem>(Rect(selectedPos, slotDimension), EType::PLAYER, 0, 0);
}

CreaturesPanel::CreaturesPanel(const CTradeableItem::ClickPressedFunctor & clickPressedCallback, const slotsData & initialSlots)
{
	assert(initialSlots.size() <= GameConstants::ARMY_SIZE);
	assert(slotsPos.size() <= GameConstants::ARMY_SIZE);
	OBJECT_CONSTRUCTION_CUSTOM_CAPTURING(255 - DISPOSE);

	for(const auto & [creatureId, slotId, creaturesNum] : initialSlots)
	{
		auto slot = slots.emplace_back(std::make_shared<CTradeableItem>(Rect(slotsPos[slotId.num], slotDimension),
			creaturesNum == 0 ? EType::CREATURE_PLACEHOLDER : EType::CREATURE, creatureId.num, slotId));
		slot->clickPressedCallback = clickPressedCallback;
		if(creaturesNum != 0)
			slot->subtitle->setText(std::to_string(creaturesNum));
		slot->setSelectionWidth(selectionWidth);
	}
	selectedSlot = std::make_shared<CTradeableItem>(Rect(selectedPos, slotDimension), EType::CREATURE, 0, 0);
}

CreaturesPanel::CreaturesPanel(const CTradeableItem::ClickPressedFunctor & clickPressedCallback,
	const std::vector<std::shared_ptr<CTradeableItem>> & srcSlots, bool emptySlots)
{
	assert(slots.size() <= GameConstants::ARMY_SIZE);
	OBJECT_CONSTRUCTION_CUSTOM_CAPTURING(255 - DISPOSE);

	for(const auto & srcSlot : srcSlots)
	{
		auto slot = slots.emplace_back(std::make_shared<CTradeableItem>(Rect(slotsPos[srcSlot->serial], srcSlot->pos.dimensions()),
			emptySlots ? EType::CREATURE_PLACEHOLDER : EType::CREATURE, srcSlot->id, srcSlot->serial));
		slot->clickPressedCallback = clickPressedCallback;
		slot->subtitle->setText(emptySlots ? "" : srcSlot->subtitle->getText());
		slot->setSelectionWidth(selectionWidth);
	}
	selectedSlot = std::make_shared<CTradeableItem>(Rect(selectedPos, slotDimension), EType::CREATURE, 0, 0);
}
