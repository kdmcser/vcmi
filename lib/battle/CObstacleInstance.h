/*
 * CObstacleInstance.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once
#include "BattleHexArray.h"

#include "../constants/EntityIdentifiers.h"
#include "../filesystem/ResourcePath.h"
#include "../networkPacks/BattleChanges.h"
#include "../serializer/Serializeable.h"

VCMI_LIB_NAMESPACE_BEGIN

class ObstacleInfo;
class ObstacleChanges;
class JsonSerializeFormat;
class SpellID;

struct DLL_LINKAGE CObstacleInstance : public Serializeable
{
	enum EObstacleType : ui8
	{
		//ABSOLUTE needs an underscore because it's a Win
		USUAL, ABSOLUTE_OBSTACLE, SPELL_CREATED, MOAT
	};

	BattleHex pos; //position on battlefield, typically left bottom corner
	EObstacleType obstacleType = USUAL;
	si32 uniqueID = -1;
	si32 ID = -1; //ID of obstacle (defines type of it)

	virtual ~CObstacleInstance() = default;

	const ObstacleInfo &getInfo() const; //allowed only when not generated by spell (usual or absolute)

	BattleHexArray getBlockedTiles() const;
	BattleHexArray getStoppingTile() const; //hexes that will stop stack move

	//The two functions below describe how the obstacle affects affected tiles
	//additional effects (like hurting stack or disappearing) are hardcoded for appropriate obstacleTypes
	virtual bool blocksTiles() const;
	virtual bool stopsMovement() const; //if unit stepping onto obstacle, can't continue movement (in general, doesn't checks for the side)
	virtual bool triggersEffects() const;
	virtual SpellID getTrigger() const;

	virtual BattleHexArray getAffectedTiles() const;
	virtual bool visibleForSide(BattleSide side, bool hasNativeStack) const; //0 attacker

	virtual void battleTurnPassed(){};

	//Client helper functions, make it easier to render animations
	virtual const AnimationPath & getAnimation() const;
	virtual const AnimationPath & getAppearAnimation() const;
	virtual const AudioPath & getAppearSound() const;

	virtual int getAnimationYOffset(int imageHeight) const;

	void toInfo(ObstacleChanges & info, BattleChanges::EOperation operation = BattleChanges::EOperation::ADD);
	
	virtual void serializeJson(JsonSerializeFormat & handler);

	template <typename Handler> void serialize(Handler &h)
	{
		h & ID;
		h & pos;
		h & obstacleType;
		h & uniqueID;
	}
};

struct DLL_LINKAGE SpellCreatedObstacle : CObstacleInstance
{
	int32_t turnsRemaining;
	int32_t casterSpellPower;
	int32_t spellLevel;
	int32_t minimalDamage; //How many damage should it do regardless of power and level of caster
	BattleSide casterSide;

	SpellID trigger;

	bool hidden;
	bool passable;
	bool trap;
	bool removeOnTrigger;
	bool revealed;
	bool nativeVisible; //Should native terrain creatures reveal obstacle

	AudioPath appearSound;
	AnimationPath appearAnimation;
	AnimationPath animation;

	int animationYOffset;

	BattleHexArray customSize;

	SpellCreatedObstacle();

	BattleHexArray getAffectedTiles() const override;
	bool visibleForSide(BattleSide side, bool hasNativeStack) const override;

	bool blocksTiles() const override;
	bool stopsMovement() const override;
	SpellID getTrigger() const override;

	void battleTurnPassed() override;

	//Client helper functions, make it easier to render animations
	const AnimationPath & getAnimation() const override;
	const AnimationPath & getAppearAnimation() const override;
	const AudioPath & getAppearSound() const override;
	int getAnimationYOffset(int imageHeight) const override;

	void fromInfo(const ObstacleChanges & info);

	void serializeJson(JsonSerializeFormat & handler) override;

	template <typename Handler> void serialize(Handler &h)
	{
		h & static_cast<CObstacleInstance&>(*this);
		h & turnsRemaining;
		h & casterSpellPower;
		h & spellLevel;
		h & casterSide;

		h & hidden;
		h & nativeVisible;
		h & passable;
		h & trigger;
		h & minimalDamage;
		h & trap;

		h & customSize;
	}
};

VCMI_LIB_NAMESPACE_END
