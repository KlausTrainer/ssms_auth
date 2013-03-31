-module(ssms_sup).
-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-include("ssms_srp.hrl").

%% ===================================================================
%% API functions
%% ===================================================================

-spec start_link() -> {ok, pid()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    Processes = [
        {
            ssms_srp_auth_db,
            {ssms_srp_auth_db, start_link, ["priv/ssms_srp_auth_db.bitcask"]},
            permanent, 2000, worker, dynamic
        },
        {
            term_cache_ets,
            {term_cache_ets, start_link, [[{ttl, 60000}, {name, ?SRP_AUTH_CACHE}]]},
            permanent, 2000, worker, dynamic
        },
        {
            ssms_web,
            {ssms_web, start, [8443, srp_2048]},
            permanent, 2000, worker, dynamic
        }
    ],
    {ok, {{one_for_one, 5, 10}, Processes}}.
