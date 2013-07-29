-module(ssms_auth_sup).
-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).


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
            ssms_auth_db,
            {ssms_auth_db, start_link, []},
            permanent, 2000, worker, dynamic
        },
        {
            ssms_auth_cache,
            {ssms_auth_cache, start_link, [[{ttl, 60000}, {name, ssms_auth_cache}]]},
            permanent, 2000, worker, dynamic
        },
        {
            ssms_auth_web,
            {ssms_auth_web, start, []},
            permanent, 2000, worker, dynamic
        }
    ],
    {ok, {{one_for_one, 5, 10}, Processes}}.
