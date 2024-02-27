/*
 * CArtifactsSelling.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

#include "../CArtifactsOfHeroMarket.h"
#include "CTradeBase.h"

class CArtifactsSelling : public CResourcesBuying, public CMarketMisc
{
public:
	CArtifactsSelling(const IMarket * market, const CGHeroInstance * hero);
	void makeDeal() override;
	void updateSelected();
	std::shared_ptr<CArtifactsOfHeroMarket> getAOHset() const;

private:
	std::shared_ptr<CArtifactsOfHeroMarket> heroArts;
	std::shared_ptr<CLabel> bidSelectedSubtitle;
	std::shared_ptr<CTradeableItem> bidSelectedSlot;

	CMarketMisc::SelectionParams getSelectionParams();
	void onSlotClickPressed(const std::shared_ptr<CTradeableItem> & newSlot, std::shared_ptr<CTradeableItem> & hCurSlot) override;
};
