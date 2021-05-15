/*
* AIPathfinderConfig.h, part of VCMI engine
*
* Authors: listed in file AUTHORS in main folder
*
* License: GNU General Public License v2.0 or later
* Full text of license available in license.txt file, in main folder
*
*/

#pragma once

#include "AINodeStorage.h"
#include "../VCAI.h"

namespace AIPathfinding
{
	class AIPathfinderConfig : public PathfinderConfig
	{
	private:
		std::unique_ptr<CPathfinderHelper> pathfindingHelper;
		std::shared_ptr<AINodeStorage> aiNodeStorage;

	public:
		AIPathfinderConfig(
			CPlayerSpecificInfoCallback * cb,
			VCAI * ai,
			std::shared_ptr<AINodeStorage> nodeStorage);

		virtual CPathfinderHelper * getOrCreatePathfinderHelper(const PathNodeInfo & source, CGameState * gs) override;
	};
}