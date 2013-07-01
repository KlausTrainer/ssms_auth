-module(ssms_web).

%% API
-export([start/2, stop/0]).

-include("ssms_srp.hrl").

-spec start(inet:port_number(), ssms_srp_auth_handler:srp_config()) -> {ok, pid()}.
start(Port, SrpConfig) ->
    PrivDir = code:priv_dir(ssms),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/srp_auth", ssms_srp_auth_handler, SrpConfig}
        ]}
    ]),
    cowboy:start_https(?MODULE, 64, [
        {port, Port},
        {cacertfile, PrivDir ++ "/ssl/cowboy-ca.crt"},
        {certfile, PrivDir ++ "/ssl/server.crt"},
        {keyfile, PrivDir ++ "/ssl/server.key"}
    ], [{env, [{dispatch, Dispatch}]}]).

stop() ->
    cowboy:stop_listener(?MODULE).
