-module(ssms).

%% API
-export([start/0]).

start() ->
    application:start(asn1),
    application:start(crypto),
    application:start(ranch),
    application:start(cowboy),
    application:start(sasl),
    ok = application:start(ssms).
