/*
* DigAtTile.cpp, part of VCMI engine
*
* Authors: listed in file AUTHORS in main folder
*
* License: GNU General Public License v2.0 or later
* Full text of license available in license.txt file, in main folder
*
*/
#include "StdInc.h"
#include "DigAtTile.h"
#include "../AIGateway.h"
#include "../AIUtility.h"


namespace NKAI
{

using namespace Goals;

bool DigAtTile::operator==(const DigAtTile & other) const
{
	return other.hero == hero && other.tile == tile;
}
//
//TSubgoal DigAtTile::decomposeSingle() const
//{
//	const CGObjectInstance * firstObj = vstd::frontOrNull(cb->getVisitableObjs(tile));
//	if(firstObj && firstObj->ID == Obj::HERO && firstObj->tempOwner == ai->playerID) //we have hero at dest
//	{
//		const CGHeroInstance * h = dynamic_cast<const CGHeroInstance *>(firstObj);
//		sethero(h).setisElementar(true);
//		return sptr(*this);
//	}
//
//	return sptr(VisitTile(tile));
//}

}
