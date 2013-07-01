%% @doc SRP authentication handler.
-module(ssms_srp_auth_handler).

%% API
-export([init/3]).
-export([rest_init/2]).
-export([allowed_methods/2]).
-export([content_types_accepted/2]).

-export([handle_post/2]).

-type srp_config() :: srp_1024 | srp_2048.
-export_type([srp_config/0]).

-record(srp_opts, {
    generator = <<>> :: binary(),
    prime = <<>> :: binary(),
    version = '6a' :: '6a'
}).
-type srp_opts() :: #srp_opts{}.

-include("ssms_srp.hrl").

-define(RESPONSE_HEADERS, [{<<"content-type">>, <<"application/json; charset=utf-8">>}]).

%% External API

-spec init({ssl, http}, cowboy_req:req(), srp_config()) -> {upgrade, protocol, cowboy_rest}.
init({ssl, http}, _Req, SrpConfig) when SrpConfig =:= srp_1024; SrpConfig =:= srp_2048 ->
	{upgrade, protocol, cowboy_rest}.

rest_init(Req, SrpConfig) ->
    {Generator, Prime} = ssl_srp_primes:get_srp_params(SrpConfig),
    SrpOpts = #srp_opts{generator=Generator, prime=Prime, version='6a'},
    {ok, Req, SrpOpts}.

allowed_methods(Req, State) ->
    {[<<"POST">>], Req, State}.

content_types_accepted(Req, State) ->
    {[{{<<"application">>, <<"json">>, []}, handle_post}], Req, State}.

%% Internal API

-spec handle_post(cowboy_req:req(), srp_opts()) -> {cowboy_req:req(), cowboy_req:req(), srp_opts()}.
handle_post(Req, #srp_opts{generator=Generator, prime=Prime, version=Version} = Opts) ->
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
            {ServerPublic, ServerPrivate} = crypto:generate_key(srp, {host, [Verifier, Generator, Prime, Version]}),
            SessionKey = crypto:compute_key(srp, ClientPublic, {ServerPublic, ServerPrivate}, {host, [Verifier, Prime, Version]}),
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
    {Res, Req, Opts}.

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
