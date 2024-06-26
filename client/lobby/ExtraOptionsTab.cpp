/*
 * ExtraOptionsTab.cpp, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */

#include "StdInc.h"
#include "ExtraOptionsTab.h"
#include "../widgets/Images.h"

ExtraOptionsTab::ExtraOptionsTab()
	: OptionsTabBase(JsonPath::builtin("config/widgets/extraOptionsTab.json"))
{
	if(auto textureCampaignOverdraw = widget<CFilledTexture>("textureCampaignOverdraw"))
		textureCampaignOverdraw->disable();
}
