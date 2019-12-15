/*
* ExecuteHeroChain.cpp, part of VCMI engine
*
* Authors: listed in file AUTHORS in main folder
*
* License: GNU General Public License v2.0 or later
* Full text of license available in license.txt file, in main folder
*
*/
#include "StdInc.h"
#include "ExecuteHeroChain.h"
#include "VisitTile.h"
#include "../VCAI.h"
#include "../FuzzyHelper.h"
#include "../AIhelper.h"
#include "../../../lib/mapping/CMap.h" //for victory conditions
#include "../../../lib/CPathfinder.h"
#include "../Engine/Nullkiller.h"

extern boost::thread_specific_ptr<CCallback> cb;
extern boost::thread_specific_ptr<VCAI> ai;
extern FuzzyHelper * fh;

using namespace Goals;

ExecuteHeroChain::ExecuteHeroChain(const AIPath & path, const CGObjectInstance * obj)
	:CGoal(Goals::EXECUTE_HERO_CHAIN), chainPath(path)
{
	evaluationContext.danger = path.getTotalDanger();
	evaluationContext.movementCost = path.movementCost();
	evaluationContext.armyLoss = path.getTotalArmyLoss();
	evaluationContext.heroStrength = path.getHeroStrength();

	hero = path.targetHero;
	tile = path.targetTile();

	for(auto & node : path.nodes)
	{
		auto role = ai->ah->getHeroRole(node.targetHero);

		evaluationContext.movementCostByRole[role] += node.cost;
	}

	if(obj)
	{
		objid = obj->id.getNum();
		targetName = obj->getObjectName() + tile.toString();
	}
	else
	{
		targetName = "tile" + tile.toString();
	}
}

bool ExecuteHeroChain::operator==(const ExecuteHeroChain & other) const
{
	return false;
}

TSubgoal ExecuteHeroChain::whatToDoToAchieve()
{
	return iAmElementar();
}

void ExecuteHeroChain::accept(VCAI * ai)
{
	logAi->debug("Executing hero chain towards %s. Path %s", targetName, chainPath.toString());

	std::set<int> blockedIndexes;

	for(int i = chainPath.nodes.size() - 1; i >= 0; i--)
	{
		auto & node = chainPath.nodes[i];

		const CGHeroInstance * hero = node.targetHero;
		HeroPtr heroPtr = hero;

		if(vstd::contains(blockedIndexes, i))
		{
			blockedIndexes.insert(node.parentIndex);
			ai->nullkiller->lockHero(hero, HeroLockedReason::HERO_CHAIN);

			continue;
		}

		logAi->debug("Executing chain node %d. Moving hero %s to %s", i, hero->name, node.coord.toString());

		try
		{
			if(hero->movement)
			{

				ai->nullkiller->setActive(hero, node.coord);

				if(node.specialAction)
				{
					if(node.specialAction->canAct(hero))
					{
						auto specialGoal = node.specialAction->whatToDo(hero);

						specialGoal->accept(ai);
					}
					else
					{
						throw cannotFulfillGoalException("Path is nondeterministic.");
					}
					
					if(!heroPtr.validAndSet())
					{
						logAi->error("Hero %s was lost trying to execute special action. Exit hero chain.", heroPtr.name);

						return;
					}
				}

				if(node.turns == 0 && node.coord != hero->visitablePos())
				{
					auto targetNode = cb->getPathsInfo(hero)->getPathInfo(node.coord);

					if(targetNode->accessible == CGPathNode::EAccessibility::NOT_SET
						|| targetNode->accessible == CGPathNode::EAccessibility::BLOCKED
						|| targetNode->accessible == CGPathNode::EAccessibility::FLYABLE
						|| targetNode->turns != 0)
					{
						logAi->error(
							"Enable to complete chain. Expected hero %s to arive to %s in 0 turns but he can not do this",
							hero->name,
							node.coord.toString());

						return;
					}
				}

				if(hero->movement)
				{
					try
					{
						Goals::VisitTile(node.coord).sethero(hero).accept(ai);
					}
					catch(cannotFulfillGoalException)
					{
						if(!heroPtr.validAndSet())
						{
							logAi->error("Hero %s was lost. Exit hero chain.", heroPtr.name);

							return;
						}

						if(hero->movement > 0)
						{
							CGPath path;
							bool isOk = cb->getPathsInfo(hero)->getPath(path, node.coord);

							if(isOk && path.nodes.back().turns > 0)
							{
								logAi->warn("Hero %s has %d mp which is not enough to continue his way towards %s.", hero->name, hero->movement, node.coord.toString());

								ai->nullkiller->lockHero(hero, HeroLockedReason::HERO_CHAIN);
								return;
							}
						}

						throw;
					}
				}
			}

			if(node.coord == hero->visitablePos())
				continue;

			if(node.turns == 0)
			{
				logAi->error(
					"Enable to complete chain. Expected hero %s to arive to %s but he is at %s", 
					hero->name, 
					node.coord.toString(),
					hero->visitablePos().toString());

				return;
			}
			
			// no exception means we were not able to rich the tile
			ai->nullkiller->lockHero(hero, HeroLockedReason::HERO_CHAIN);
			blockedIndexes.insert(node.parentIndex);
		}
		catch(goalFulfilledException)
		{
			if(!heroPtr.validAndSet())
			{
				logAi->debug("Hero %s was killed while attempting to rich %s", heroPtr.name, node.coord.toString());

				return;
			}
		}
	}
}

std::string ExecuteHeroChain::name() const
{
	return "ExecuteHeroChain " + targetName + " by " + chainPath.targetHero->name;
}