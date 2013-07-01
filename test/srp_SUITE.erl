-module(srp_SUITE).
-include_lib("common_test/include/ct.hrl").

%% ct
-export([all/0, groups/0, init_per_suite/1, end_per_suite/1,
	     init_per_group/2, end_per_group/2]).

%% tests
-export([srp6a_unit/1]).
-export([srp6a_integration/1]).
-export([srp6a_benchmark/1]).

-include("../include/ssms_srp.hrl").

all() ->
    [
        {group, srp_unit},
        {group, srp_integration},
        {group, srp_benchmark}
    ].

groups() ->
    [
        {srp_unit, [], [srp6a_unit]},
        {srp_integration, [], [srp6a_integration]},
        {srp_benchmark, [], [{srp6a_benchmark, [parallel], [srp6a_benchmark, srp6a_benchmark]}]}
    ].

init_per_suite(Config) ->
    ok = application:start(crypto),
    Config.

end_per_suite(_Config) ->
    ok = application:stop(crypto).

init_per_group(srp_integration, Config) ->
    ok = application:start(ranch),
    ok = application:start(cowboy),
    ok = application:start(ibrowse),
    SrpConfig = srp_2048,
    {ok, _} = ssms_srp_auth_db:start(code:lib_dir(ssms) ++ "/test/ssms_srp_auth_test_db.bitcask"),
    {ok, _} = term_cache_ets:start([{ttl, 60000}, {name, ?SRP_AUTH_CACHE}]),
    {ok, _} = ssms_web:start(0, SrpConfig),
    SsmsWebPort = ranch:get_port(ssms_web),
    {Generator, Prime} = ssl_srp_primes:get_srp_params(SrpConfig),
    Salt = crypto:strong_rand_bytes(32),
    Username = <<"alice">>,
    Password = <<"password123">>,
    UserPassHash = crypto:hash(sha, [Salt, crypto:hash(sha, [Username, <<$:>>, Password])]),
    Verifier = crypto:mod_pow(Generator, UserPassHash, Prime),
    ssms_srp_auth_db:store(Username, {Salt, Verifier}),
    [{ssms_web_port, SsmsWebPort}, {generator, Generator}, {prime, Prime},
     {username, Username}, {password, Password} | Config];
init_per_group(_GroupName, Config) ->
    Config.

end_per_group(srp_integration, Config) ->
    ok = ssms_web:stop(),
    ok = ssms_srp_auth_db:delete(?config(username, Config)),
    ok = ssms_srp_auth_db:stop(),
    ok = term_cache_ets:stop(?SRP_AUTH_CACHE),
    ok = application:stop(ibrowse),
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
    Salt = hexstr2bin("BEB25379D1A8581EB5A727673A2441EE"), % s
    {Generator, Prime} = ssl_srp_primes:get_srp_params(SrpConfig), % g, N
    Version = '6a',
    Scrambler = hexstr2bin("CE38B9593487DA98554ED47D70A7AE5F462EF019"),
    Verifier = hexstr2bin("7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D812"
              "9BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5"
              "C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5"
              "EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78"
              "E955A5E29E7AB245DB2BE315E2099AFB"), % v
    ClientPrivate = hexstr2bin("60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DD"
              "DA2D4393"), % a
    ServerPrivate = hexstr2bin("E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D1"
              "05284D20"), % b
    ClientPublic = hexstr2bin("61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC4"
             "4352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC"
             "8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44"
             "BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEA"
             "B349EF5D76988A3672FAC47B0769447B"), % A
    ServerPublic = hexstr2bin("BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011"
             "BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC99"
             "6C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA"
             "37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAE"
             "EB4012B7D7665238A8E3FB004B117B58"), % B
    SessionKey = hexstr2bin("B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D"
                "233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C"
                "41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F"
                "3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D"
                "C346D7E474B29EDE8A469FFECA686E5A"),
    UserPassHash = crypto:hash(sha, [Salt, crypto:hash(sha, [Username, <<$:>>, Password])]), % x
    Verifier = crypto:mod_pow(Generator, UserPassHash, Prime), % v
    {ClientPublic, ClientPrivate} = crypto:generate_key(srp, {user, [Generator, Prime, Version]}, ClientPrivate),
    {ServerPublic, ServerPrivate} = crypto:generate_key(srp, {host, [Verifier, Generator, Prime, Version]}, ServerPrivate),
    SessionKey = crypto:compute_key(srp, ServerPublic, {ClientPublic, ClientPrivate}, {user, [UserPassHash, Prime, Generator, Version, Scrambler]}),
    SessionKey = crypto:compute_key(srp, ClientPublic, {ServerPublic, ServerPrivate}, {host, [Verifier, Prime, Version, Scrambler]}).

srp6a_integration(Config) ->
    SsmsWebPort = ?config(ssms_web_port, Config),
    Username = ?config(username, Config),
    Password = ?config(password, Config),
    Generator = ?config(generator, Config),
    Prime = ?config(prime, Config),
    Version = '6a',
    {ClientPublic, ClientPrivate} = crypto:generate_key(srp, {user, [Generator, Prime, Version]}),
    Headers = [{"Content-Type", "application/json"}],
    Options = [{response_format, binary}, {ssl_options, [{verify, verify_none}]}],
    Url = "https://127.0.0.1:" ++ integer_to_list(SsmsWebPort) ++ "/srp_auth",
    BadRequest1 = <<>>,
    BadRequest2 = <<"{}">>,
    BadRequest3 = jiffy:encode({[{'I', base64:encode(<<"foobator42">>)},
                                 {'A', base64:encode(crypto:rand_bytes(256))}]}),
    BadRequest4 = jiffy:encode({[{'M', base64:encode(crypto:rand_bytes(256))}]}),
    BadRequest5 = jiffy:encode({[{'I', base64:encode(Username)},
                                 {'A', base64:encode(ClientPublic)},
                                 {<<"Foo">>, <<"Bar">>}]}),
    GoodRequest1 = jiffy:encode({[{'I', base64:encode(Username)},
                                  {'A', base64:encode(ClientPublic)}]}),
    {ok, "400", _, <<"{\"error\":\"bad request\"}">>} =
        ibrowse:send_req(Url, Headers, post, BadRequest1, Options),
    {ok, "400", _, <<"{\"error\":\"bad request\"}">>} =
        ibrowse:send_req(Url, Headers, post, BadRequest2, Options),
    {ok, "400", _, <<"{\"error\":\"unknown_psk_identity\"}">>} =
        ibrowse:send_req(Url, Headers, post, BadRequest3, Options),
    {ok, "400", _, <<"{\"error\":\"bad_record_mac\"}">>} =
        ibrowse:send_req(Url, Headers, post, BadRequest4, Options),
    {ok, "400", _, <<"{\"error\":\"bad request\"}">>} =
        ibrowse:send_req(Url, Headers, post, BadRequest5, Options),
    {ok, "200", _, Response1} =
        ibrowse:send_req(Url, Headers, post, GoodRequest1, Options),
    {Params1} = jiffy:decode(Response1),
    Salt = base64:decode(proplists:get_value(<<"s">>, Params1)),
    ServerPublic = base64:decode(proplists:get_value(<<"B">>, Params1)),
    UserPassHash = crypto:hash(sha, [Salt, crypto:hash(sha, [Username, <<$:>>, Password])]),
    M = crypto:compute_key(srp, ServerPublic, {ClientPublic, ClientPrivate}, {user, [UserPassHash, Prime, Generator, Version]}),
    BadRequest6 = jiffy:encode({[{'M', base64:encode(M)}, {<<"Foo">>, <<"Bar">>}]}),
    {ok, "400", _, <<"{\"error\":\"bad request\"}">>} =
        ibrowse:send_req(Url, Headers, post, BadRequest6, Options),
    GoodRequest2 = jiffy:encode({[{'M', base64:encode(M)}]}),
    {ok, "200", _, <<"{}">>} =
        ibrowse:send_req(Url, Headers, post, GoodRequest2, Options),
    ok.

srp6a_benchmark(_Config) ->
    Verifier = <<102,38,89,197,126,4,196,82,10,252,163,184,186,71,172,104,240,219,
                 106,76,255,60,70,182,231,222,40,111,82,51,201,200,112,71,193,245,
                 140,95,252,35,122,206,105,202,254,12,189,67,154,26,19,206,225,13,
                 153,53,223,59,50,134,23,234,129,213,46,185,196,136,176,23,51,205,
                 135,47,215,107,224,224,37,3,171,3,194,53,153,224,46,62,229,253,73,
                 161,36,230,212,94,118,126,66,88,103,92,253,244,85,215,38,187,192,
                 199,69,28,170,119,231,107,88,55,102,117,222,77,248,27,4,186,149,
                 104,113,92,73,238,80,227,192,23,223,189,56,154,95,54,89,246,47,58,
                 150,251,106,173,211,208,98,248,233,151,135,178,214,141,231,135,219,
                 122,64,140,153,65,56,210,252,53,154,47,19,39,23,101,51,247,242,2,
                 125,251,226,130,96,0,201,253,123,174,192,230,176,245,56,187,221,75,
                 175,113,241,87,129,176,214,59,57,225,233,8,91,7,167,61,4,147,115,
                 176,119,22,88,112,75,204,27,191,180,141,5,178,124,35,2,77,161,238,
                 4,128,102,86,182,25,33,31,19,6,214,249,126,219,69,170,245,14>>,
    Generator = <<2>>,
    Prime = <<172,107,219,65,50,74,154,155,241,102,222,94,19,137,88,47,175,114,182,
              101,25,135,238,7,252,49,146,148,61,181,96,80,163,115,41,203,180,160,
              153,237,129,147,224,117,119,103,161,61,213,35,18,171,75,3,49,13,205,
              127,72,169,218,4,253,80,232,8,57,105,237,183,103,176,207,96,149,23,
              154,22,58,179,102,26,5,251,213,250,170,232,41,24,169,150,47,11,147,
              184,85,249,121,147,236,151,94,234,168,13,116,10,219,244,255,116,115,
              89,208,65,213,195,62,167,29,40,30,68,107,20,119,59,202,151,180,58,35,
              251,128,22,118,189,32,122,67,108,100,129,241,210,185,7,135,23,70,26,
              91,157,50,230,136,248,119,72,84,69,35,181,36,176,213,125,94,167,122,
              39,117,210,236,250,3,44,251,219,245,47,179,120,97,96,39,144,4,229,122,
              230,175,135,78,115,3,206,83,41,156,204,4,28,123,195,8,216,42,86,152,
              243,168,208,195,130,113,174,53,248,233,219,251,182,148,181,200,3,216,
              159,122,228,53,222,35,109,82,95,84,117,155,101,227,114,252,214,142,
              242,15,167,17,31,158,74,255,115>>,
    Version = '6a',
    ClientPublic = <<147,135,197,167,101,157,146,98,80,254,27,126,171,23,23,248,252,
                     32,63,64,235,77,9,102,192,115,192,184,174,105,217,215,232,81,
                     42,127,208,27,198,53,22,95,97,187,16,134,124,150,213,66,139,
                     140,18,156,248,92,172,157,249,164,195,29,87,21,97,152,54,0,45,
                     104,195,149,235,218,25,93,208,112,138,173,210,27,215,20,86,105,
                     172,250,136,174,163,197,143,152,5,79,50,51,205,184,28,4,195,
                     209,136,183,134,197,123,123,183,128,211,198,254,175,136,227,
                     133,42,86,27,208,55,254,202,246,49,171,177,204,212,87,30,92,
                     237,9,51,234,198,62,8,62,176,100,42,153,203,65,86,231,61,148,
                     244,21,236,5,251,83,172,170,165,222,131,3,214,27,12,206,131,
                     121,35,61,188,196,96,222,225,39,5,152,41,220,24,108,9,64,231,
                     67,13,183,103,195,112,49,64,149,153,196,52,11,153,162,27,174,
                     100,144,91,86,174,47,19,197,18,168,107,154,114,175,237,111,115,
                     83,185,9,242,4,139,73,125,20,242,164,75,105,91,80,147,128,187,
                     220,208,152,143,97,208,155,74,145,138,134,134,19,118,16,188>>,
    times(fun () ->
              {ServerPublic, ServerPrivate} = crypto:generate_key(srp, {host, [Verifier, Generator, Prime, Version]}),
              _SessionKey = crypto:compute_key(srp, ClientPublic, {ServerPublic, ServerPrivate}, {host, [Verifier, Prime, Version]})
          end, 1000).

%%
%% helper functions
%%

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

times(_Fun, 0) -> ok;
times(Fun, I) ->
    Fun(),
    times(Fun, I - 1).
