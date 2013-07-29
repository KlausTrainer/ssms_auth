-module(ssms_auth_web).

%% API
-export([start/2, stop/0]).


-spec start(inet:port_number(), ssms_auth_handler:srp_config()) -> {ok, pid()}.
start(Port, SrpConfig) ->
    PrivDir = code:priv_dir(ssms_auth),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/srp_auth", ssms_auth_handler, SrpConfig}
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
