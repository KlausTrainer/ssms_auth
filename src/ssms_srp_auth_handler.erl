%% @doc SRP authentication handler.
-module(ssms_srp_auth_handler).

%% API
-export([init/3, terminate/3]).

-export([handle/2]).

-type srp_config() :: srp_1024 | srp_2048.
-export_type([srp_config/0]).

-record(srp_opts, {
    generator = <<>> :: binary(),
    prime = <<>> :: binary(),
    version = '6a' :: '6a'
}).
-type srp_opts() :: #srp_opts{}.

-include("ssms_srp.hrl").

-define(RESPONSE_HEADERS, [{<<"Content-Type">>, <<"application/json; charset=utf-8">>}]).

%% External API

-spec init({ssl, http}, cowboy_req:req(), srp_config()) -> {ok, cowboy_req:req(), srp_opts()}.
init({ssl, http}, Req, SrpConfig) when SrpConfig =:= srp_1024; SrpConfig =:= srp_2048 ->
    {Generator, Prime} = ssl_srp_primes:get_srp_params(SrpConfig),
    SrpOpts = #srp_opts{generator=Generator, prime=Prime, version='6a'},
    {ok, Req, SrpOpts}.

terminate(_Reason, _Req, _State) ->
    ok.

%% Internal API

-spec handle(cowboy_req:req(), srp_opts()) -> {ok, cowboy_req:req(), srp_opts()}.
handle(Req, #srp_opts{generator=Generator, prime=Prime, version=Version} = Opts) ->
    {<<"POST">>, _} = cowboy_req:method(Req),
    {ok, Body, _} = cowboy_req:body(Req),
    {ok, Res} = case parse_req_body(Body) of
    error ->
        cowboy_req:reply(400, ?RESPONSE_HEADERS, <<"{\"error\":\"bad request\"}">>, Req);
    {{'I', Username}, {'A', ClientPublic}} ->
        case ssms_srp_auth_db:lookup(Username) of
        not_found ->
            %% FIXME simulate the existence of an entry for this user name
            %% c.f. RFC 5054 section 2.5.1.3
            cowboy_req:reply(400, ?RESPONSE_HEADERS, <<"{\"error\":\"unknown_psk_identity\"}">>, Req);
        {ok, {Salt, Verifier}} ->
            {ServerPublic, ServerPrivate} = crypto:srp_generate_key(Verifier, Generator, Prime, Version),
            SessionKey = crypto:srp_compute_key(Verifier, Prime, ClientPublic, ServerPublic, ServerPrivate, Version),
            Response = jiffy:encode(
                {[{<<"s">>, base64:encode(Salt)},
                {<<"B">>, base64:encode(ServerPublic)}]}),
            term_cache_ets:put(?SRP_AUTH_CACHE, SessionKey, true),
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
