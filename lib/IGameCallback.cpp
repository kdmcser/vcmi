/*
 * IGameCallback.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#include "StdInc.h"
#include "IGameCallback.h"

#include "spells/CSpellHandler.h"// for CSpell
#include "CSkillHandler.h"// for CSkill
#include "CBonusTypeHandler.h"
#include "BattleFieldHandler.h"
#include "ObstacleHandler.h"
#include "bonuses/Limiters.h"
#include "bonuses/Propagators.h"
#include "bonuses/Updaters.h"
#include "entities/building/CBuilding.h"
#include "entities/hero/CHero.h"
#include "networkPacks/ArtifactLocation.h"
#include "serializer/CLoadFile.h"
#include "serializer/CSaveFile.h"
#include "rmg/CMapGenOptions.h"
#include "mapObjectConstructors/AObjectTypeHandler.h"
#include "mapObjectConstructors/CObjectClassesHandler.h"
#include "mapObjects/CGMarket.h"
#include "mapObjects/TownBuildingInstance.h"
#include "mapObjects/CGTownInstance.h"
#include "mapObjects/CObjectHandler.h"
#include "mapObjects/CQuest.h"
#include "mapObjects/MiscObjects.h"
#include "mapObjects/ObjectTemplate.h"
#include "campaign/CampaignState.h"
#include "StartInfo.h"
#include "gameState/CGameState.h"
#include "gameState/CGameStateCampaign.h"
#include "gameState/TavernHeroesPool.h"
#include "gameState/QuestInfo.h"
#include "mapping/CMap.h"
#include "modding/CModHandler.h"
#include "modding/IdentifierStorage.h"
#include "modding/CModVersion.h"
#include "modding/ActiveModsInSaveList.h"
#include "CPlayerState.h"
#include "GameSettings.h"
#include "ScriptHandler.h"
#include "RoadHandler.h"
#include "RiverHandler.h"
#include "TerrainHandler.h"

#include <vstd/RNG.h>

VCMI_LIB_NAMESPACE_BEGIN

void CPrivilegedInfoCallback::getFreeTiles(std::vector<int3> & tiles) const
{
	std::vector<int> floors;
	floors.reserve(gs->getMap().levels());
	for(int b = 0; b < gs->getMap().levels(); ++b)
	{
		floors.push_back(b);
	}
	const TerrainTile * tinfo = nullptr;
	for (auto zd : floors)
	{
		for (int xd = 0; xd < gs->getMap().width; xd++)
		{
			for (int yd = 0; yd < gs->getMap().height; yd++)
			{
				tinfo = getTile(int3 (xd,yd,zd));
				if (tinfo->isLand() && tinfo->getTerrain()->isPassable() && !tinfo->blocked()) //land and free
					tiles.emplace_back(xd, yd, zd);
			}
		}
	}
}

void CPrivilegedInfoCallback::getTilesInRange(std::unordered_set<int3> & tiles,
											  const int3 & pos,
											  int radious,
											  ETileVisibility mode,
											  std::optional<PlayerColor> player,
											  int3::EDistanceFormula distanceFormula) const
{
	if(!!player && !player->isValidPlayer())
	{
		logGlobal->error("Illegal call to getTilesInRange!");
		return;
	}
	if(radious == CBuilding::HEIGHT_SKYSHIP) //reveal entire map
		getAllTiles (tiles, player, -1, [](auto * tile){return true;});
	else
	{
		const TeamState * team = !player ? nullptr : gs->getPlayerTeam(*player);
		for (int xd = std::max<int>(pos.x - radious , 0); xd <= std::min<int>(pos.x + radious, gs->getMap().width - 1); xd++)
		{
			for (int yd = std::max<int>(pos.y - radious, 0); yd <= std::min<int>(pos.y + radious, gs->getMap().height - 1); yd++)
			{
				int3 tilePos(xd,yd,pos.z);
				int distance = pos.dist(tilePos, distanceFormula);

				if(distance <= radious)
				{
					if(!player
						|| (mode == ETileVisibility::HIDDEN  && team->fogOfWarMap[pos.z][xd][yd] == 0)
						|| (mode == ETileVisibility::REVEALED && team->fogOfWarMap[pos.z][xd][yd] == 1)
					)
						tiles.insert(int3(xd,yd,pos.z));
				}
			}
		}
	}
}

void CPrivilegedInfoCallback::getAllTiles(std::unordered_set<int3> & tiles, std::optional<PlayerColor> Player, int level, std::function<bool(const TerrainTile *)> filter) const
{
	if(!!Player && !Player->isValidPlayer())
	{
		logGlobal->error("Illegal call to getAllTiles !");
		return;
	}

	std::vector<int> floors;
	if(level == -1)
	{
		for(int b = 0; b < gs->getMap().levels(); ++b)
		{
			floors.push_back(b);
		}
	}
	else
		floors.push_back(level);

	for(auto zd: floors)
	{
		for(int xd = 0; xd < gs->getMap().width; xd++)
		{
			for(int yd = 0; yd < gs->getMap().height; yd++)
			{
				int3 coordinates(xd, yd, zd);
				if (filter(getTile(coordinates)))
					tiles.insert(coordinates);
			}
		}
	}
}

void CPrivilegedInfoCallback::pickAllowedArtsSet(std::vector<ArtifactID> & out, vstd::RNG & rand)
{
	for (int j = 0; j < 3 ; j++)
		out.push_back(gameState()->pickRandomArtifact(rand, CArtifact::ART_TREASURE));
	for (int j = 0; j < 3 ; j++)
		out.push_back(gameState()->pickRandomArtifact(rand, CArtifact::ART_MINOR));

	out.push_back(gameState()->pickRandomArtifact(rand, CArtifact::ART_MAJOR));
}

void CPrivilegedInfoCallback::getAllowedSpells(std::vector<SpellID> & out, std::optional<ui16> level)
{
	for (auto const & spellID : gs->getMap().allowedSpells)
	{
		const auto * spell = spellID.toEntity(LIBRARY);

		if (!isAllowed(spellID))
			continue;

		if (level.has_value() && spell->getLevel() != level)
			continue;

		out.push_back(spellID);
	}
}

CGameState * CPrivilegedInfoCallback::gameState()
{
	return gs;
}

void CPrivilegedInfoCallback::loadCommonState(CLoadFile & in)
{
	logGlobal->info("Loading lib part of game...");
	in.checkMagicBytes(SAVEGAME_MAGIC);

	CMapHeader dum;
	StartInfo * si = nullptr;
	ActiveModsInSaveList activeMods;

	logGlobal->info("\tReading header");
	in.serializer & dum;

	logGlobal->info("\tReading options");
	in.serializer & si;

	logGlobal->info("\tReading mod list");
	in.serializer & activeMods;

	logGlobal->info("\tReading gamestate");
	in.serializer & gs;
}

void CPrivilegedInfoCallback::saveCommonState(CSaveFile & out) const
{
	ActiveModsInSaveList activeMods;

	logGlobal->info("Saving lib part of game...");
	out.putMagicBytes(SAVEGAME_MAGIC);
	logGlobal->info("\tSaving header");
	out.serializer & static_cast<CMapHeader&>(gs->getMap());
	logGlobal->info("\tSaving options");
	out.serializer & gs->getStartInfo();
	logGlobal->info("\tSaving mod list");
	out.serializer & activeMods;
	logGlobal->info("\tSaving gamestate");
	out.serializer & gs;
}

TerrainTile * CNonConstInfoCallback::getTile(const int3 & pos)
{
	if(!gs->getMap().isInTheMap(pos))
		return nullptr;
	return &gs->getMap().getTile(pos);
}

CGHeroInstance * CNonConstInfoCallback::getHero(const ObjectInstanceID & objid)
{
	return const_cast<CGHeroInstance*>(CGameInfoCallback::getHero(objid));
}

CGTownInstance * CNonConstInfoCallback::getTown(const ObjectInstanceID & objid)
{
	return const_cast<CGTownInstance*>(CGameInfoCallback::getTown(objid));
}

TeamState * CNonConstInfoCallback::getTeam(const TeamID & teamID)
{
	return const_cast<TeamState*>(CGameInfoCallback::getTeam(teamID));
}

TeamState * CNonConstInfoCallback::getPlayerTeam(const PlayerColor & color)
{
	return const_cast<TeamState*>(CGameInfoCallback::getPlayerTeam(color));
}

PlayerState * CNonConstInfoCallback::getPlayerState(const PlayerColor & color, bool verbose)
{
	return const_cast<PlayerState*>(CGameInfoCallback::getPlayerState(color, verbose));
}

CArtifactInstance * CNonConstInfoCallback::getArtInstance(const ArtifactInstanceID & aid)
{
	return gs->getMap().artInstances.at(aid.num);
}

CGObjectInstance * CNonConstInfoCallback::getObjInstance(const ObjectInstanceID & oid)
{
	return gs->getMap().objects.at(oid.num);
}

CArmedInstance * CNonConstInfoCallback::getArmyInstance(const ObjectInstanceID & oid)
{
	return dynamic_cast<CArmedInstance *>(getObjInstance(oid));
}

CArtifactSet * CNonConstInfoCallback::getArtSet(const ArtifactLocation & loc)
{
	if(auto hero = getHero(loc.artHolder))
	{
		if(loc.creature.has_value())
		{
			if(loc.creature.value() == SlotID::COMMANDER_SLOT_PLACEHOLDER)
				return hero->commander;
			else
				return hero->getStackPtr(loc.creature.value());
		}
		else
		{
			return hero;
		}
	}
	else if(auto market = getMarket(loc.artHolder))
	{
		if(auto artSet = market->getArtifactsStorage())
			return artSet;
	}
	else if(auto army = getArmyInstance(loc.artHolder))
	{
		return army->getStackPtr(loc.creature.value());
	}
	return nullptr;
}

bool IGameCallback::isVisitCoveredByAnotherQuery(const CGObjectInstance *obj, const CGHeroInstance *hero)
{
	//only server knows
	logGlobal->error("isVisitCoveredByAnotherQuery call on client side");
	return false;
}

VCMI_LIB_NAMESPACE_END
