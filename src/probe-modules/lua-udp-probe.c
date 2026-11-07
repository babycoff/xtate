#include "probe-modules.h"

#include <string.h>

#include "../xconf.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"
#include "../stub/stub-lua.h"

#define LUA_PROBE_NAME "LuaUdpProbe"
#define LUA_PROBE_TYPE "udp"
#define LUA_PROBE_EG   "udp-example.lua"

#define LUA_PROBE_VAR_PROBENAME "ProbeName"
#define LUA_PROBE_VAR_PROBETYPE "ProbeType"
#define LUA_PROBE_VAR_PROBEDESC "ProbeDesc"

#define LUA_PROBE_FUNC_MAKE_PAYLOAD      "Make_payload"
#define LUA_PROBE_FUNC_VALIDATE_RESPONSE "Validate_response"
#define LUA_PROBE_FUNC_HANDLE_RESPONSE   "Handle_response"

/*for internal x-ref*/
extern Probe LuaUdpProbe;

struct LuaUdpConf {
    char      *script;
    /**
     * Until now, I have no better way to solve multi-thread problem across Lua
     * and Xtate. So it's good to design a good workflow for Lua probe.
     *
     * For udp type probe, there're 3 funcs correspond to 3 essential threads at
     * least:
     * Tx: make_payload
     * Rx: validate_reponse
     * Rx(handler): handler_response
     *
     * So I brutely limit the multi-thread of Xtate and create 3 Lua VM for
     * those callback funcs. It's effective and causes that 3 funcs should be
     * thread- seperate.
     *
     * Well, we can't ask lua probe do everything like a real probe module,
     * right?
     *
     * TODO: Maybe one thread for one Lua VM to support full multiple threads.
     */
    lua_State *Ltx; /*for make_payload*/
    lua_State *Lrx; /*for validate_response*/
    lua_State *Lhx; /*for handle_response*/
};

static struct LuaUdpConf luaudp_conf = {0};

static ConfRes SET_script(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(luaudp_conf.script);

    luaudp_conf.script = STRDUP(value);

    return Conf_OK;
}

static ConfParam luaudp_parameters[] = {
    {"script",
     SET_script,
     Type_ARG,
     {0},
     "Specifies which lua script we'll load to as probe."},

    {0}};

/**
 * Simply check funcs in Ltx
 */
static bool check_func_exist(const char *func) {
    lua_getglobal(luaudp_conf.Ltx, func);
    if (lua_isfunction(luaudp_conf.Ltx, -1) == 0) {
        LOG(LEVEL_ERROR, "" LUA_PROBE_NAME ": no `%s` func in script %s.\n",
            func, luaudp_conf.script);
        return false;
    }
    lua_pop(luaudp_conf.Ltx, 1);
    return true;
}

static bool sync_probe_config() {
    /*probe name*/
    lua_getglobal(luaudp_conf.Ltx, LUA_PROBE_VAR_PROBENAME);
    if (lua_isstring(luaudp_conf.Ltx, -1) == 0) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": no `" LUA_PROBE_VAR_PROBENAME
            "` setting in script %s.\n",
            luaudp_conf.script);
        return false;
    }
    LOG(LEVEL_DEBUG, "(" LUA_PROBE_NAME ") " LUA_PROBE_VAR_PROBENAME ": %s.\n",
        lua_tostring(luaudp_conf.Ltx, -1));
    lua_pop(luaudp_conf.Ltx, 1);

    /*probe type*/
    lua_getglobal(luaudp_conf.Ltx, LUA_PROBE_VAR_PROBETYPE);
    if (lua_isinteger(luaudp_conf.Ltx, -1) == 0) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": no `" LUA_PROBE_VAR_PROBETYPE
            "` setting in script %s.\n",
            luaudp_conf.script);
        return false;
    }
    if (lua_tointeger(luaudp_conf.Ltx, -1) != ProbeType_UDP) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": need a %s `" LUA_PROBE_VAR_PROBETYPE
            "` in %s.\n",
            get_probe_type_name(ProbeType_UDP), luaudp_conf.script);
        return false;
    }
    lua_pop(luaudp_conf.Ltx, 1);

    /*probe desc*/
    lua_getglobal(luaudp_conf.Ltx, LUA_PROBE_VAR_PROBEDESC);
    if (lua_isstring(luaudp_conf.Ltx, -1) == 0) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": no `" LUA_PROBE_VAR_PROBEDESC
            "` setting in script %s.\n",
            luaudp_conf.script);
        return false;
    }
    lua_pop(luaudp_conf.Ltx, 1);

    return true;
}

static bool luaudp_init(const XConf *xconf) {
    if (!luaudp_conf.script) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME
            ": must specify a lua script as probe by `--script`.\n");
        return false;
    }

    if (xconf->tx_thread_count != 1 || xconf->rx_handler_count != 1) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME
            " doesn't support multi-tx-threads or multi-handle-threads now.\n");
        return false;
    }

    /* Dynamically link the library*/
    if (!stublua_init()) {
        LOG(LEVEL_ERROR, "failed to init lua library dynamicly.\n");
        LOG(LEVEL_HINT, "make sure lua library 5.3/5.4 was installed.\n");
        return false;
    }

    int x;

    /* Create Lua VM */
    luaudp_conf.Ltx = luaL_newstate();
    luaudp_conf.Lrx = luaL_newstate();
    luaudp_conf.Lhx = luaL_newstate();
    luaL_openlibs(luaudp_conf.Ltx);
    luaL_openlibs(luaudp_conf.Lrx);
    luaL_openlibs(luaudp_conf.Lhx);

    /* Get lua version*/
    lua_getglobal(luaudp_conf.Ltx, "_VERSION");
    const char *version = lua_tostring(luaudp_conf.Ltx, -1);
    LOG(LEVEL_INFO, "loaded lua library in %s\n", version);
    lua_pop(luaudp_conf.Ltx, 1);

    /* Load the script. This will verify the syntax.*/
    x = luaL_loadfile(luaudp_conf.Ltx, luaudp_conf.script);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "%s error loading: %s: %s for Tx\n",
            "SCRIPTING:", luaudp_conf.script,
            lua_tostring(luaudp_conf.Ltx, -1));
        lua_close(luaudp_conf.Ltx);
        lua_close(luaudp_conf.Lrx);
        lua_close(luaudp_conf.Lhx);
        FREE(luaudp_conf.script);
        return false;
    }
    x = luaL_loadfile(luaudp_conf.Lrx, luaudp_conf.script);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "%s error loading: %s: %s for Rx\n",
            "SCRIPTING:", luaudp_conf.script,
            lua_tostring(luaudp_conf.Lrx, -1));
        lua_close(luaudp_conf.Ltx);
        lua_close(luaudp_conf.Lrx);
        lua_close(luaudp_conf.Lhx);
        FREE(luaudp_conf.script);
        return false;
    }
    x = luaL_loadfile(luaudp_conf.Lhx, luaudp_conf.script);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "%s error loading: %s: %s for Handler\n",
            "SCRIPTING:", luaudp_conf.script,
            lua_tostring(luaudp_conf.Lhx, -1));
        lua_close(luaudp_conf.Ltx);
        lua_close(luaudp_conf.Lrx);
        lua_close(luaudp_conf.Lhx);
        FREE(luaudp_conf.script);
        return false;
    }

    /*
     * Lua: Start running the script and we can see global variables and funcs.
     * Just need to check for one VM because of same script.
     */
    LOG(LEVEL_DEBUG, "" LUA_PROBE_NAME " running script: %s\n",
        luaudp_conf.script);
    x = lua_pcall(luaudp_conf.Ltx, 0, 0, 0);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "" LUA_PROBE_NAME ": error running %s: %s for Tx\n",
            luaudp_conf.script, lua_tostring(luaudp_conf.Ltx, -1));
        lua_close(luaudp_conf.Ltx);
        lua_close(luaudp_conf.Lrx);
        lua_close(luaudp_conf.Lhx);
        FREE(luaudp_conf.script);
        return false;
    }
    x = lua_pcall(luaudp_conf.Lrx, 0, 0, 0);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "" LUA_PROBE_NAME ": error running %s: %s for Rx\n",
            luaudp_conf.script, lua_tostring(luaudp_conf.Lrx, -1));
        lua_close(luaudp_conf.Ltx);
        lua_close(luaudp_conf.Lrx);
        lua_close(luaudp_conf.Lhx);
        FREE(luaudp_conf.script);
        return false;
    }
    x = lua_pcall(luaudp_conf.Lhx, 0, 0, 0);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": error running %s: %s for Handler\n",
            luaudp_conf.script, lua_tostring(luaudp_conf.Lhx, -1));
        lua_close(luaudp_conf.Ltx);
        lua_close(luaudp_conf.Lrx);
        lua_close(luaudp_conf.Lhx);
        FREE(luaudp_conf.script);
        return false;
    }

    /**
     *Sync config
     */
    if (!sync_probe_config()) {
        lua_close(luaudp_conf.Ltx);
        lua_close(luaudp_conf.Lrx);
        lua_close(luaudp_conf.Lhx);
        FREE(luaudp_conf.script);
        return false;
    }

    /**
     * Check tcp type callback funcs
     */
    if (!check_func_exist(LUA_PROBE_FUNC_MAKE_PAYLOAD)) {
        lua_close(luaudp_conf.Ltx);
        lua_close(luaudp_conf.Lrx);
        lua_close(luaudp_conf.Lhx);
        FREE(luaudp_conf.script);
        return false;
    }
    if (!check_func_exist(LUA_PROBE_FUNC_VALIDATE_RESPONSE)) {
        lua_close(luaudp_conf.Ltx);
        lua_close(luaudp_conf.Lrx);
        lua_close(luaudp_conf.Lhx);
        FREE(luaudp_conf.script);
        return false;
    }
    if (!check_func_exist(LUA_PROBE_FUNC_HANDLE_RESPONSE)) {
        lua_close(luaudp_conf.Ltx);
        lua_close(luaudp_conf.Lrx);
        lua_close(luaudp_conf.Lhx);
        FREE(luaudp_conf.script);
        return false;
    }

    lua_settop(luaudp_conf.Ltx, 0);
    return true;
}

static size_t luaudp_make_payload(ProbeTarget   *target,
                                  unsigned char *payload_buf) {
    const char *ret;
    size_t      ret_len;

    lua_getglobal(luaudp_conf.Ltx, LUA_PROBE_FUNC_MAKE_PAYLOAD);
    lua_pushstring(luaudp_conf.Ltx,
                   ipaddress_fmt(target->target.ip_them).string);
    lua_pushinteger(luaudp_conf.Ltx, target->target.port_them);
    lua_pushstring(luaudp_conf.Ltx, ipaddress_fmt(target->target.ip_me).string);
    lua_pushinteger(luaudp_conf.Ltx, target->target.port_me);
    lua_pushinteger(luaudp_conf.Ltx, target->index);
    lua_pushinteger(luaudp_conf.Ltx, target->cookie);

    if (lua_pcall(luaudp_conf.Ltx, 6, 1, 0) != LUA_OK) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": func `" LUA_PROBE_FUNC_MAKE_PAYLOAD
            "` execute error in %s: %s\n",
            luaudp_conf.script, lua_tostring(luaudp_conf.Ltx, -1));
        lua_settop(luaudp_conf.Ltx, 0);
        return 0;
    }

    if (lua_isstring(luaudp_conf.Ltx, -1) == 0) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": func `" LUA_PROBE_FUNC_MAKE_PAYLOAD
            "` return error in script %s.\n",
            luaudp_conf.script);
        lua_settop(luaudp_conf.Ltx, 0);
        return 0;
    }

    ret = lua_tolstring(luaudp_conf.Ltx, -1, &ret_len);
    memcpy(payload_buf, ret, ret_len);
    lua_settop(luaudp_conf.Ltx, 0);
    return ret_len;
}

static bool luaudp_validate_response(ProbeTarget         *target,
                                     const unsigned char *px,
                                     unsigned             sizeof_px) {
    bool ret;

    lua_getglobal(luaudp_conf.Lrx, LUA_PROBE_FUNC_VALIDATE_RESPONSE);
    lua_pushstring(luaudp_conf.Lrx,
                   ipaddress_fmt(target->target.ip_them).string);
    lua_pushinteger(luaudp_conf.Lrx, target->target.port_them);
    lua_pushstring(luaudp_conf.Lrx, ipaddress_fmt(target->target.ip_me).string);
    lua_pushinteger(luaudp_conf.Lrx, target->target.port_me);
    lua_pushinteger(luaudp_conf.Lrx, target->index);
    lua_pushinteger(luaudp_conf.Lrx, target->cookie);
    lua_pushlstring(luaudp_conf.Lrx, (const char *)px, sizeof_px);

    if (lua_pcall(luaudp_conf.Lrx, 7, 1, 0) != LUA_OK) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": func `" LUA_PROBE_FUNC_VALIDATE_RESPONSE
            "` execute error in %s: %s\n",
            luaudp_conf.script, lua_tostring(luaudp_conf.Lrx, -1));
        lua_settop(luaudp_conf.Lrx, 0);
        return false;
    }

    if (lua_isboolean(luaudp_conf.Lrx, -1) == 0) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": func `" LUA_PROBE_FUNC_VALIDATE_RESPONSE
            "` return error in script %s.\n",
            luaudp_conf.script);
        lua_settop(luaudp_conf.Lrx, 0);
        return false;
    }

    ret = lua_toboolean(luaudp_conf.Lrx, -1);
    lua_settop(luaudp_conf.Lrx, 0);

    return ret;
}

static unsigned luaudp_handle_response(unsigned th_idx, ProbeTarget *target,
                                       const unsigned char *px,
                                       unsigned sizeof_px, OutItem *item) {
    const char *lua_ret;
    size_t      ret_len;
    unsigned    ret = 0;

    lua_getglobal(luaudp_conf.Lhx, LUA_PROBE_FUNC_HANDLE_RESPONSE);
    lua_pushstring(luaudp_conf.Lhx,
                   ipaddress_fmt(target->target.ip_them).string);
    lua_pushinteger(luaudp_conf.Lhx, target->target.port_them);
    lua_pushstring(luaudp_conf.Lhx, ipaddress_fmt(target->target.ip_me).string);
    lua_pushinteger(luaudp_conf.Lhx, target->target.port_me);
    lua_pushinteger(luaudp_conf.Lhx, target->index);
    lua_pushlstring(luaudp_conf.Lhx, (const char *)px, sizeof_px);

    if (lua_pcall(luaudp_conf.Lhx, 6, 5, 0) != LUA_OK) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": func `" LUA_PROBE_FUNC_HANDLE_RESPONSE
            "` execute error in %s: %s\n",
            luaudp_conf.script, lua_tostring(luaudp_conf.Lhx, -1));
        lua_settop(luaudp_conf.Lhx, 0);
        return 0;
    }

    if (lua_isinteger(luaudp_conf.Lhx, -5) == 0) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": func `" LUA_PROBE_FUNC_HANDLE_RESPONSE
            "` return error in script %s.\n",
            luaudp_conf.script);
        lua_settop(luaudp_conf.Lhx, 0);
        return 0;
    }
    if (lua_tointeger(luaudp_conf.Lhx, -5) > 0) {
        ret = lua_tointeger(luaudp_conf.Lhx, -5);
    } else if (lua_tointeger(luaudp_conf.Lhx, -5) < 0) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": func `" LUA_PROBE_FUNC_HANDLE_RESPONSE
            "` return error in script %s.\n",
            luaudp_conf.script);
        lua_settop(luaudp_conf.Lhx, 0);
        return 0;
    }

    if (lua_isinteger(luaudp_conf.Lhx, -4) == 0) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": func `" LUA_PROBE_FUNC_HANDLE_RESPONSE
            "` return error in script %s.\n",
            luaudp_conf.script);
        lua_settop(luaudp_conf.Lhx, 0);
        return 0;
    }
    item->level = lua_tointeger(luaudp_conf.Lhx, -4);

    if (lua_isstring(luaudp_conf.Lhx, -3) == 0) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": func `" LUA_PROBE_FUNC_HANDLE_RESPONSE
            "` return error in script %s.\n",
            luaudp_conf.script);
        lua_settop(luaudp_conf.Lhx, 0);
        return 0;
    }
    lua_ret = lua_tolstring(luaudp_conf.Lhx, -3, &ret_len);
    memcpy(item->classification, lua_ret, ret_len);

    if (lua_isstring(luaudp_conf.Lhx, -2) == 0) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": func `" LUA_PROBE_FUNC_HANDLE_RESPONSE
            "` return error in script %s.\n",
            luaudp_conf.script);
        lua_settop(luaudp_conf.Lhx, 0);
        return 0;
    }
    lua_ret = lua_tolstring(luaudp_conf.Lhx, -2, &ret_len);
    memcpy(item->reason, lua_ret, ret_len);

    if (lua_isstring(luaudp_conf.Lhx, -1) == 0) {
        LOG(LEVEL_ERROR,
            "" LUA_PROBE_NAME ": func `" LUA_PROBE_FUNC_HANDLE_RESPONSE
            "` return error in script %s.\n",
            luaudp_conf.script);
        lua_settop(luaudp_conf.Lhx, 0);
        return 0;
    }
    lua_ret = lua_tolstring(luaudp_conf.Lhx, -1, &ret_len);
    dach_append_banner(&item->probe_report, "lua report", lua_ret, ret_len);

    lua_settop(luaudp_conf.Lhx, 0);
    return ret;
}

void luaudp_close() {
    if (luaudp_conf.Ltx) {
        lua_close(luaudp_conf.Ltx);
    }
    if (luaudp_conf.Lrx) {
        lua_close(luaudp_conf.Lrx);
    }
    if (luaudp_conf.Lhx) {
        lua_close(luaudp_conf.Lhx);
    }
    FREE(luaudp_conf.script);
}

Probe LuaUdpProbe = {
    .name       = "lua-udp",
    .type       = ProbeType_UDP,
    .params     = luaudp_parameters,
    .short_desc = "Use user-defined LUA script to do UDP scan.",
    .desc       = LUA_PROBE_NAME
    " let a specifies proper lua script as a " LUA_PROBE_TYPE " type probe. It "
    "will save a lot of time for us to write simple probes or test ideas. "
    "The example script(" LUA_PROBE_EG ") could be found at lua-probes dir."
    " In a nutshell, we should set some global variables as probe config "
    "include:\n"
    "`" LUA_PROBE_VAR_PROBENAME "`\n"
    "`" LUA_PROBE_VAR_PROBETYPE "`\n"
    "`" LUA_PROBE_VAR_PROBEDESC "`\n"
    "And implement some global functions for calling back include:\n"
    "`" LUA_PROBE_FUNC_MAKE_PAYLOAD "`\n"
    "`" LUA_PROBE_FUNC_VALIDATE_RESPONSE "`\n"
    "`" LUA_PROBE_FUNC_HANDLE_RESPONSE "`\n"
    "NOTE: This is an experimental function and does not support more than "
    "one tx thread or rx-handle thread well. Even through, it is mandatory "
    "to implement functions thread-separately. However, we had 3 essential"
    " threads at least and should be careful to thread-safe problems.\n"
    "Dependencies: lua5.3/5.4.",

    .init_cb              = &luaudp_init,
    .make_payload_cb      = &luaudp_make_payload,
    .validate_response_cb = &luaudp_validate_response,
    .handle_response_cb   = &luaudp_handle_response,
    .close_cb             = &luaudp_close,
};