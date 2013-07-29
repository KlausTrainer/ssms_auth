-module(ssms_auth_web).

%% API
-export([start/0, stop/0]).


-spec start() -> {ok, pid()}.
start() ->
    PrivDir = code:priv_dir(ssms_auth),
    Port = ssms_auth:get_app_env(port, 8443),
    SrpConfig = ssms_auth:get_app_env(srp_config, srp_2048),
    CaCertFile = ssms_auth:get_app_env(cacertfile, PrivDir ++ "/ssl/cowboy-ca.crt"),
    CertFile = ssms_auth:get_app_env(certfile, PrivDir ++ "/ssl/server.crt"),
    KeyFile = ssms_auth:get_app_env(keyfile, PrivDir ++ "/ssl/server.key"),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/srp_auth", ssms_auth_handler, SrpConfig}
        ]}
    ]),
    cowboy:start_https(?MODULE, 64, [
        {port, Port},
        {cacertfile, CaCertFile},
        {certfile, CertFile},
        {keyfile, KeyFile},
        {ciphers, unbroken_cipher_suites()}
    ], [{env, [{dispatch, Dispatch}]}]).

stop() ->
    cowboy:stop_listener(?MODULE).


%% internal API

%% Unfortunately the implementation of elliptic-curve ciphers that has
%% been introduced in R16B01 is incomplete. Depending on the particular
%% client, this can cause the TLS handshake to break during key
%% agreement. Depending on the ssl application version, this function
%% returns a list of all cipher suites that are supported by default,
%% minus the elliptic-curve ones.
-spec unbroken_cipher_suites() -> [ssl:erl_cipher_suite()].
unbroken_cipher_suites() ->
    case proplists:get_value(ssl_app, ssl:versions()) of
    "5.3" ->
        lists:filter(fun(Suite) ->
            string:left(atom_to_list(element(1, Suite)), 4) =/= "ecdh"
        end, ssl:cipher_suites());
    _ ->
        ssl:cipher_suites()
    end.
