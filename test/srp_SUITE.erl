-module(srp_SUITE).
-include_lib("common_test/include/ct.hrl").

-compile(export_all).

-include("ssms_srp.hrl").

all() ->
    [
        {group, srp_unit},
        {group, srp_integration}
    ].

groups() ->
    [
        {srp_unit, [], [srp6a_unit]},
        {srp_integration, [], [{srp6a_integration, [parallel, {repeat, 50}], [srp6a_integration, srp6a_integration]}]}
    ].

init_per_suite(Config) ->
    ok = crypto:start(),
    Config.

end_per_suite(_Config) ->
    ok = crypto:stop().

init_per_group(srp_integration, Config) ->
    ok = application:start(ranch),
    ok = application:start(cowboy),
    ok = application:start(inets),
    ok = httpc:set_options([{max_keep_alive_length, 0}, {max_sessions, 4}]),
    SrpConfig = srp_2048,
    {ok, _} = ssms_srp_auth_db:start(code:lib_dir(ssms) ++ "/test/ssms_srp_auth_test_db.bitcask"),
    {ok, _} = term_cache_ets:start([{ttl, 60000}, {name, ?SRP_AUTH_CACHE}]),
    {ok, _} = ssms_web:start(0, SrpConfig),
    SsmsWebPort = ranch:get_port(ssms_web),
    {Generator, Prime} = ?SRP_PARAMS(SrpConfig),
    Multiplier = ?SRP6a_MULTIPLIER(SrpConfig),
    Salt = crypto:strong_rand_bytes(32),
    Username = <<"alice">>,
    Password = <<"password123">>,
    UserPassHash = crypto:sha([Salt, crypto:sha([Username, <<$:>>, Password])]),
    Verifier = crypto:srp_mod_exp(Generator, UserPassHash, Prime),
    ssms_srp_auth_db:store(Username, {Salt, Verifier}),
    [{ssms_web_port, SsmsWebPort}, {generator, Generator}, {prime, Prime},
     {multiplier, Multiplier}, {username, Username}, {password, Password}
     | Config];
init_per_group(_GroupName, Config) ->
    Config.

end_per_group(srp_integration, Config) ->
    ok = ssms_srp_auth_db:delete(?config(username, Config)),
    ok = ssms_srp_auth_db:stop(),
    ok = term_cache_ets:stop(?SRP_AUTH_CACHE),
    ok = application:stop(inets),
    ok = application:stop(cowboy),
    ok = application:stop(ranch),
    Config;
end_per_group(_GroupName, Config) ->
    Config.

%%
%% SRP-6a test vectors from RFC5054.
%% Stolen from Erlang/OTP 'lib/crypto/test/crypto_SUITE.erl'.
%%
srp6a_unit(_Config) ->
    SrpConfig = srp_1024,
    Username = <<"alice">>, % I
    Password = <<"password123">>,
    Salt = hexstr2bin("BEB25379D1A8581EB5A727673A2441EE"),
    {Generator, Prime} = ?SRP_PARAMS(SrpConfig),
    Multiplier = ?SRP6a_MULTIPLIER(SrpConfig), % k
    %% X = hexstr2bin("94B7555AABE9127CC58CCF4993DB6CF84D16C124"),
    Verifier = hexstr2bin("7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D812"
            "9BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5"
            "C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5"
            "EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78"
            "E955A5E29E7AB245DB2BE315E2099AFB"),
    ClientPrivKey = hexstr2bin("60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DD"
            "DA2D4393"), % a
    ServerPrivKey = hexstr2bin("E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D1"
            "05284D20"), % b
    ClientPubKey = hexstr2bin("61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC4"
             "4352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC"
             "8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44"
             "BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEA"
             "B349EF5D76988A3672FAC47B0769447B"), % A
    ServerPubKey = hexstr2bin("BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011"
             "BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC99"
             "6C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA"
             "37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAE"
             "EB4012B7D7665238A8E3FB004B117B58"), % B
    U = crypto:srp6_value_u(ClientPubKey, ServerPubKey, Prime),
    PremasterSecret = hexstr2bin("B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D"
             "233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C"
             "41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F"
             "3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D"
             "C346D7E474B29EDE8A469FFECA686E5A"),
    UserPassHash = crypto:sha([Salt, crypto:sha([Username, <<$:>>, Password])]),
    m(crypto:srp_mod_exp(Generator, UserPassHash, Prime), Verifier),
    m(crypto:srp_mod_exp(Generator, ClientPrivKey, Prime), ClientPubKey),
    m(crypto:srp6a_multiplier(Generator, Prime), Multiplier),
    m(crypto:srp6_value_u(ClientPubKey, ServerPubKey, Prime), U),
    m(crypto:srp_value_B(Multiplier, Verifier, Generator, ServerPrivKey, Prime), ServerPubKey),
    m(crypto:srp_client_secret(ClientPrivKey, U, ServerPubKey, Multiplier, Generator, UserPassHash, Prime), PremasterSecret),
    m(crypto:srp_server_secret(Verifier, ServerPrivKey, U, ClientPubKey, Prime), PremasterSecret),
    ok.

srp6a_integration(Config) ->
    SsmsWebPort = ?config(ssms_web_port, Config),
    Username = ?config(username, Config),
    Password = ?config(password, Config),
    Generator = ?config(generator, Config),
    Prime = ?config(prime, Config),
    Multiplier = ?config(multiplier, Config),
    ClientPrivKey = crypto:strong_rand_bytes(64),
    ClientPubKey = crypto:srp_mod_exp(Generator, ClientPrivKey, Prime),
    HttpOptions = [{ssl, [{verify, verify_none}]}],
    Options = [{body_format, binary}],
    Url = "https://127.0.0.1:" ++ integer_to_list(SsmsWebPort) ++ "/srp_auth",
    BadRequest1 = create_request(Url, <<>>),
    BadRequest2 = create_request(Url, <<"{}">>),
    BadRequest3 = create_request(Url, [{'I', base64:encode(<<"foobator42">>)},
                                       {'A', base64:encode(crypto:rand_bytes(256))}]),
    BadRequest4 = create_request(Url, [{'M', base64:encode(crypto:rand_bytes(256))}]),
    BadRequest5 = create_request(Url, [{'I',  base64:encode(Username)},
                                       {'A', base64:encode(ClientPubKey)},
                                       {<<"Foo">>, <<"Bar">>}]),
    GoodRequest1 = create_request(Url, [{'I',  base64:encode(Username)},
                                       {'A', base64:encode(ClientPubKey)}]),
    {ok, {{_, 400, _}, _, <<"{\"error\":\"bad request\"}">>}} =
        httpc:request(post, BadRequest1, HttpOptions, Options),
    {ok, {{_, 400, _}, _, <<"{\"error\":\"bad request\"}">>}} =
        httpc:request(post, BadRequest2, HttpOptions, Options),
    {ok, {{_, 400, _}, _, <<"{\"error\":\"unknown_psk_identity\"}">>}} =
        httpc:request(post, BadRequest3, HttpOptions, Options),
    {ok, {{_, 400, _}, _, <<"{\"error\":\"bad_record_mac\"}">>}} =
        httpc:request(post, BadRequest4, HttpOptions, Options),
    {ok, {{_, 400, _}, _, <<"{\"error\":\"bad request\"}">>}} =
        httpc:request(post, BadRequest5, HttpOptions, Options),
    {ok, {{_, 200, _}, _, Response1}} =
        httpc:request(post, GoodRequest1, HttpOptions, Options),
    {Params1} = jiffy:decode(Response1),
    Salt = base64:decode(proplists:get_value(<<"s">>, Params1)),
    ServerPubKey = base64:decode(proplists:get_value(<<"B">>, Params1)),
    UserPassHash = crypto:sha([Salt, crypto:sha([Username, <<$:>>, Password])]),
    U = crypto:srp6_value_u(ClientPubKey, ServerPubKey, Prime),
    M = crypto:srp_client_secret(ClientPrivKey, U, ServerPubKey, Multiplier, Generator, UserPassHash, Prime),
    BadRequest6 = create_request(Url, [{'M',  base64:encode(M)}, {<<"Foo">>, <<"Bar">>}]),
    {ok, {{_, 400, _}, _, <<"{\"error\":\"bad request\"}">>}} =
        httpc:request(post, BadRequest6, HttpOptions, Options),
    GoodRequest2 = create_request(Url, [{'M',  base64:encode(M)}]),
    {ok, {{_, 200, _}, _, <<"{}">>}} =
        httpc:request(post, GoodRequest2, HttpOptions, Options),
    ok.


%%
%% helper functions
%%

create_request(Url, Body) when is_binary(Body) ->
    {Url, [], "application/json", Body};
create_request(Url, Params) when is_list(Params) ->
    {Url, [], "application/json", jiffy:encode({Params})}.

% match
m(X, X) ->
    true.

hexstr2bin(S) ->
    list_to_binary(hexstr2list(S)).

hexstr2list([X,Y|T]) ->
    [mkint(X) * 16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
    [].

mkint(C) when $0 =< C, C =< $9 ->
    C - $0;
mkint(C) when $A =< C, C =< $F ->
    C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
    C - $a + 10.
