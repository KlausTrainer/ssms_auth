-module(ssms_web).

%% API
-export([start/1, stop/1]).

-include("ssms_srp.hrl").

-spec start(inet:port_number()) -> {ok, pid()}.
start(Port) ->
    PrivDir = code:priv_dir(ssms),
    {Generator, Prime} = ssl_srp_primes:get_srp_params(srp_2048),
    Multiplier = crypto:srp6a_multiplier(Generator, Prime),
    Opts = #ssms_srp_opts{generator=Generator, prime=Prime, multiplier=Multiplier},
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/srp_auth", ssms_srp_auth_handler, Opts}
        ]}
    ]),
    cowboy:start_https(?MODULE, 64, [
        {port, Port},
        {cacertfile, PrivDir ++ "/ssl/cowboy-ca.crt"},
        {certfile, PrivDir ++ "/ssl/server.crt"},
        {keyfile, PrivDir ++ "/ssl/server.key"}
    ], [{env, [{dispatch, Dispatch}]}]).

stop(Pid) ->
    cowboy:stop_listener(Pid).
