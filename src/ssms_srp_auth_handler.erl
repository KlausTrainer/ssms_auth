%% @doc SRP authentication handler.
-module(ssms_srp_auth_handler).

%% API
-export([init/3, terminate/3]).

-export([handle/2]).

-include("ssms_srp.hrl").

-define(RESPONSE_HEADERS, [{<<"Content-Type">>, <<"application/json; charset=utf-8">>}]).

%% External API

init(_Transport, Req, Opts) ->
    {ok, Req, Opts}.

terminate(_Reason, _Req, _State) ->
    ok.

%% Internal API

handle(Req, #ssms_srp_opts{generator=Generator, prime=Prime, multiplier=Multiplier} = Opts) ->
    {<<"POST">>, _} = cowboy_req:method(Req),
    {ok, Body, _} = cowboy_req:body(Req),
    {ok, Res} = case parse_req_body(Body) of
    error ->
        cowboy_req:reply(400, ?RESPONSE_HEADERS, <<"{\"error\":\"bad request\"}">>, Req);
    {{'I', Username}, {'A', ClientPubKey}} ->
        case ssms_srp_auth_db:lookup(Username) of
        not_found ->
            %% FIXME simulate the existence of an entry for this user name
            %% c.f. RFC 5054 section 2.5.1.3
            cowboy_req:reply(400, ?RESPONSE_HEADERS, <<"{\"error\":\"unknown_psk_identity\"}">>, Req);
        {ok, {Salt, Verifier}} ->
            ServerPrivKey = crypto:strong_rand_bytes(64),
            ServerPubKey = crypto:srp_value_B(Multiplier, Verifier, Generator, ServerPrivKey, Prime),
            U = crypto:srp6_value_u(ClientPubKey, ServerPubKey, Prime),
            ServerSecret = crypto:srp_server_secret(Verifier, ServerPrivKey, U, ClientPubKey, Prime),
            Response = jiffy:encode(
                {[{<<"s">>, base64:encode(Salt)},
                {<<"B">>, base64:encode(ServerPubKey)}]}),
            term_cache_ets:put(?SRP_AUTH_CACHE, ServerSecret, true),
            cowboy_req:reply(200, ?RESPONSE_HEADERS, Response, Req)
        end;
    {'M', ClientSecret} ->
        case term_cache_ets:get(?SRP_AUTH_CACHE, ClientSecret) of
        not_found ->
            cowboy_req:reply(400, ?RESPONSE_HEADERS, <<"{\"error\":\"bad_record_mac\"}">>, Req);
        {ok, _} ->
            cowboy_req:reply(200, ?RESPONSE_HEADERS, <<"{}">>, Req)
        end
    end,
    {ok, Res, Opts}.

parse_req_body(Body) ->
    try
        case jiffy:decode(Body) of
        {[{<<"M">>, M}]} ->
            {'M', base64:decode(M)};
        {Props} when length(Props) =:= 2 ->
            I = proplists:get_value(<<"I">>, Props),
            A = proplists:get_value(<<"A">>, Props),
            if I =/= undefined, A =/= undefined ->
                {{'I', base64:decode(I)}, {'A', base64:decode(A)}};
            true ->
                error
            end;
        _ ->
            error
        end
    catch throw:_ ->
        error
    end.
