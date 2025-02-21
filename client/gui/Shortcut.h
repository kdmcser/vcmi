/*
 * Shortcut.h, part of VCMI engine
 *
 * Authors: listed in file AUTHORS in main folder
 *
 * License: GNU General Public License v2.0 or later
 * Full text of license available in license.txt file, in main folder
 *
 */
#pragma once

enum class EShortcut
{
	NONE,

	// preudo-shortcuts that trigger mouse events
	MOUSE_LEFT,
	MOUSE_RIGHT,
	MOUSE_CURSOR_X,
	MOUSE_CURSOR_Y,
	MOUSE_SWIPE_X,
	MOUSE_SWIPE_Y,

	// Global hotkeys that are available in multiple dialogs
	GLOBAL_ACCEPT,     // Return - Accept query
	GLOBAL_CANCEL,     // Escape - Cancel query
	GLOBAL_RETURN,     // Enter, Escape - Close current window and return to previous view
	GLOBAL_FULLSCREEN, // F4 - TODO: remove hardcoded check for key
	GLOBAL_OPTIONS,    // 'O' - Open System Options dialog
	GLOBAL_BACKSPACE,  // Backspace - erase last symbol in text input
	GLOBAL_MOVE_FOCUS, // Tab - move focus to next text input

	// Movement hotkeys, usually - for moving through lists with slider
	MOVE_LEFT,
	MOVE_RIGHT,
	MOVE_UP,
	MOVE_DOWN,
	MOVE_FIRST,
	MOVE_LAST,
	MOVE_PAGE_UP,
	MOVE_PAGE_DOWN,

	// Element selection - for multiple choice dialog popups
	SELECT_INDEX_1,
	SELECT_INDEX_2,
	SELECT_INDEX_3,
	SELECT_INDEX_4,
	SELECT_INDEX_5,
	SELECT_INDEX_6,
	SELECT_INDEX_7,
	SELECT_INDEX_8,

	// Main menu hotkeys - for navigation between main menu windows
	MAIN_MENU_NEW_GAME,
	MAIN_MENU_LOAD_GAME,
	MAIN_MENU_HIGH_SCORES,
	MAIN_MENU_CREDITS,
	MAIN_MENU_BACK,
	MAIN_MENU_QUIT,
	MAIN_MENU_SINGLEPLAYER,
	MAIN_MENU_MULTIPLAYER,
	MAIN_MENU_CAMPAIGN,
	MAIN_MENU_TUTORIAL,
	MAIN_MENU_CAMPAIGN_SOD,
	MAIN_MENU_CAMPAIGN_ROE,
	MAIN_MENU_CAMPAIGN_AB,
	MAIN_MENU_CAMPAIGN_CUSTOM,

	MAIN_MENU_HOTSEAT,
	MAIN_MENU_LOBBY,
	MAIN_MENU_HOST_GAME,
	MAIN_MENU_JOIN_GAME,

	HIGH_SCORES_CAMPAIGNS,
	HIGH_SCORES_SCENARIOS,
	HIGH_SCORES_RESET,
	HIGH_SCORES_STATISTICS,

	// Game lobby / scenario selection
	LOBBY_BEGIN_STANDARD_GAME, // b
	LOBBY_BEGIN_CAMPAIGN, // Return
	LOBBY_LOAD_GAME,  // l, Return
	LOBBY_SAVE_GAME,  // s, Return
	LOBBY_RANDOM_MAP, // Open random map tab
	LOBBY_TOGGLE_CHAT,
	LOBBY_ADDITIONAL_OPTIONS, // Open additional options tab
	LOBBY_SELECT_SCENARIO,    // Open map list tab
	LOBBY_REPLAY_VIDEO,
	LOBBY_EXTRA_OPTIONS,
	LOBBY_TURN_OPTIONS,
	LOBBY_INVITE_PLAYERS,
	LOBBY_FLIP_COIN,
	LOBBY_RANDOM_TOWN,
	LOBBY_RANDOM_TOWN_VS,
	LOBBY_HANDICAP,

	MAPS_SIZE_S,
	MAPS_SIZE_M,
	MAPS_SIZE_L,
	MAPS_SIZE_XL,
	MAPS_SIZE_ALL,

	MAPS_SORT_PLAYERS,
	MAPS_SORT_SIZE,
	MAPS_SORT_FORMAT,
	MAPS_SORT_NAME,
	MAPS_SORT_VICTORY,
	MAPS_SORT_DEFEAT,
	MAPS_SORT_MAPS,
	MAPS_SORT_CHANGEDATE,

	SETTINGS_LOAD_GAME,
	SETTINGS_SAVE_GAME,
	SETTINGS_NEW_GAME,
	SETTINGS_RESTART_GAME,
	SETTINGS_TO_MAIN_MENU,
	SETTINGS_QUIT_GAME,

	// In-game hotkeys, require game state but may be available in windows other than adventure map
	GAME_ACTIVATE_CONSOLE, // Tab, activates in-game console

	// Adventure map screen
	ADVENTURE_GAME_OPTIONS, // 'o', Open CAdventureOptions window
	ADVENTURE_TOGGLE_GRID,  // F6, Toggles map grid
	ADVENTURE_TOGGLE_VISITABLE,  // Toggles visitable tiles overlay
	ADVENTURE_TOGGLE_BLOCKED,  // Toggles blocked tiles overlay
	ADVENTURE_TOGGLE_SLEEP, // Toggles hero sleep status
	ADVENTURE_SET_HERO_ASLEEP, // Moves hero to sleep state
	ADVENTURE_SET_HERO_AWAKE, // Move hero to awake state
	ADVENTURE_MOVE_HERO,    // Moves hero alongside set path
	ADVENTURE_VISIT_OBJECT, // Revisits object hero is standing on
	ADVENTURE_VIEW_SELECTED,// Open window with currently selected hero/town
	ADVENTURE_NEXT_TOWN,
	ADVENTURE_NEXT_HERO,
	ADVENTURE_NEXT_OBJECT,  // context-sensitive next object - select next hero/town, depending on current selection
	ADVENTURE_FIRST_TOWN,   // select first available town in the list
	ADVENTURE_FIRST_HERO,   // select first available hero in the list
	ADVENTURE_VIEW_SCENARIO,// View Scenario Information window
	ADVENTURE_REPLAY_TURN,
	ADVENTURE_DIG_GRAIL,
	ADVENTURE_VIEW_PUZZLE,
	ADVENTURE_VIEW_WORLD,
	ADVENTURE_VIEW_WORLD_X1,
	ADVENTURE_VIEW_WORLD_X2,
	ADVENTURE_VIEW_WORLD_X4,
	ADVENTURE_TRACK_HERO,
	ADVENTURE_TOGGLE_MAP_LEVEL,
	ADVENTURE_KINGDOM_OVERVIEW,
	ADVENTURE_QUEST_LOG,
	ADVENTURE_CAST_SPELL,
	ADVENTURE_MARKETPLACE,
	ADVENTURE_THIEVES_GUILD,
	ADVENTURE_EXIT_WORLD_VIEW,
	ADVENTURE_ZOOM_IN,
	ADVENTURE_ZOOM_OUT,
	ADVENTURE_ZOOM_RESET,
	ADVENTURE_END_TURN,
	ADVENTURE_LOAD_GAME,
	ADVENTURE_SAVE_GAME,
	ADVENTURE_NEW_GAME,
	ADVENTURE_RESTART_GAME,
	ADVENTURE_TO_MAIN_MENU,
	ADVENTURE_QUIT_GAME,
	ADVENTURE_SEARCH,
	ADVENTURE_SEARCH_CONTINUE,

	// Move hero one tile in specified direction. Bound to cursors & numpad buttons
	ADVENTURE_MOVE_HERO_SW,
	ADVENTURE_MOVE_HERO_SS,
	ADVENTURE_MOVE_HERO_SE,
	ADVENTURE_MOVE_HERO_WW,
	ADVENTURE_MOVE_HERO_EE,
	ADVENTURE_MOVE_HERO_NW,
	ADVENTURE_MOVE_HERO_NN,
	ADVENTURE_MOVE_HERO_NE,

	// Battle screen
	BATTLE_TOGGLE_QUEUE,
	BATTLE_USE_CREATURE_SPELL,
	BATTLE_SURRENDER,
	BATTLE_RETREAT,
	BATTLE_AUTOCOMBAT,
	BATTLE_END_WITH_AUTOCOMBAT,
	BATTLE_CAST_SPELL,
	BATTLE_WAIT,
	BATTLE_DEFEND,
	BATTLE_CONSOLE_UP,
	BATTLE_CONSOLE_DOWN,
	BATTLE_TACTICS_NEXT,
	BATTLE_TACTICS_END,
	BATTLE_SELECT_ACTION, // Alternative actions toggle
	BATTLE_TOGGLE_HEROES_STATS,
	BATTLE_OPEN_ACTIVE_UNIT,
	BATTLE_OPEN_HOVERED_UNIT,
	BATTLE_TOGGLE_QUICKSPELL,
	BATTLE_SPELL_SHORTCUT_0,
	BATTLE_SPELL_SHORTCUT_1,
	BATTLE_SPELL_SHORTCUT_2,
	BATTLE_SPELL_SHORTCUT_3,
	BATTLE_SPELL_SHORTCUT_4,
	BATTLE_SPELL_SHORTCUT_5,
	BATTLE_SPELL_SHORTCUT_6,
	BATTLE_SPELL_SHORTCUT_7,
	BATTLE_SPELL_SHORTCUT_8,
	BATTLE_SPELL_SHORTCUT_9,
	BATTLE_SPELL_SHORTCUT_10,
	BATTLE_SPELL_SHORTCUT_11,

	MARKET_DEAL,
	MARKET_MAX_AMOUNT,
	MARKET_SACRIFICE_ALL,
	MARKET_SACRIFICE_BACKPACK,
	MARKET_RESOURCE_PLAYER,
	MARKET_ARTIFACT_RESOURCE,
	MARKET_RESOURCE_ARTIFACT,
	MARKET_CREATURE_RESOURCE,
	MARKET_RESOURCE_RESOURCE,
	MARKET_CREATURE_EXPERIENCE,
	MARKET_ARTIFACT_EXPERIENCE,

	SPECTATE_TRACK_HERO,
	SPECTATE_SKIP_BATTLE,
	SPECTATE_SKIP_BATTLE_RESULT,

	// Town screen
	TOWN_OPEN_TAVERN,
	TOWN_OPEN_HALL,
	TOWN_OPEN_FORT,
	TOWN_OPEN_MARKET,
	TOWN_OPEN_MAGE_GUILD,
	TOWN_OPEN_THIEVES_GUILD,
	TOWN_OPEN_RECRUITMENT,
	TOWN_OPEN_HERO_EXCHANGE,
	TOWN_OPEN_HERO,
	TOWN_OPEN_VISITING_HERO,
	TOWN_OPEN_GARRISONED_HERO,
	TOWN_SWAP_ARMIES, // Swap garrisoned and visiting armies

	// Creature & creature recruitment screen
	RECRUITMENT_MAX, // Set number of creatures to recruit to max
	RECRUITMENT_MIN, // Set number of creatures to recruit to min (1)
	RECRUITMENT_SWITCH_LEVEL,
	RECRUITMENT_UPGRADE, // Upgrade current creature
	RECRUITMENT_UPGRADE_ALL, // Upgrade all creatures (Hill Fort / Skeleton Transformer)

	// Kingdom Overview window
	KINGDOM_HEROES_TAB,
	KINGDOM_TOWNS_TAB,

	// Hero screen
	HERO_DISMISS,
	HERO_COMMANDER,
	HERO_LOOSE_FORMATION,
	HERO_TIGHT_FORMATION,
	HERO_TOGGLE_TACTICS, // b
	HERO_ARMY_SPLIT,
	HERO_BACKPACK,
	HERO_COSTUME_SAVE_0,
	HERO_COSTUME_SAVE_1,
	HERO_COSTUME_SAVE_2,
	HERO_COSTUME_SAVE_3,
	HERO_COSTUME_SAVE_4,
	HERO_COSTUME_SAVE_5,
	HERO_COSTUME_SAVE_6,
	HERO_COSTUME_SAVE_7,
	HERO_COSTUME_SAVE_8,
	HERO_COSTUME_SAVE_9,

	HERO_COSTUME_LOAD_0,
	HERO_COSTUME_LOAD_1,
	HERO_COSTUME_LOAD_2,
	HERO_COSTUME_LOAD_3,
	HERO_COSTUME_LOAD_4,
	HERO_COSTUME_LOAD_5,
	HERO_COSTUME_LOAD_6,
	HERO_COSTUME_LOAD_7,
	HERO_COSTUME_LOAD_8,
	HERO_COSTUME_LOAD_9,

	EXCHANGE_ARMY_TO_LEFT,
	EXCHANGE_ARMY_TO_RIGHT,
	EXCHANGE_ARMY_SWAP,
	EXCHANGE_ARTIFACTS_TO_LEFT,
	EXCHANGE_ARTIFACTS_TO_RIGHT,
	EXCHANGE_ARTIFACTS_SWAP,
	EXCHANGE_EQUIPPED_TO_LEFT,
	EXCHANGE_EQUIPPED_TO_RIGHT,
	EXCHANGE_EQUIPPED_SWAP,
	EXCHANGE_BACKPACK_TO_LEFT,
	EXCHANGE_BACKPACK_TO_RIGHT,
	EXCHANGE_BACKPACK_SWAP,
	EXCHANGE_BACKPACK_LEFT,
	EXCHANGE_BACKPACK_RIGHT,

	// Spellbook screen
	SPELLBOOK_TAB_ADVENTURE,
	SPELLBOOK_TAB_COMBAT,
	SPELLBOOK_SEARCH_FOCUS,

	LIST_HERO_UP,
	LIST_HERO_DOWN,
	LIST_HERO_TOP,
	LIST_HERO_BOTTOM,
	LIST_HERO_DISMISS,
	LIST_TOWN_UP,
	LIST_TOWN_DOWN,
	LIST_TOWN_TOP,
	LIST_TOWN_BOTTOM,

	AFTER_LAST
};
