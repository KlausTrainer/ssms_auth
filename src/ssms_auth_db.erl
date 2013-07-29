%% @doc Handles storage of user account data.
-module(ssms_auth_db).

-behaviour(gen_server).

%% API
-export([start/0, start_link/0, stop/0]).
-export([lookup/1, delete/1, store/2]).

%% gen_server callbacks
-export([
    init/1, handle_call/3, handle_info/2, handle_cast/2,
    code_change/3, terminate/2
]).


%% External API

-spec start() -> {ok, pid()} | ignore | {error, term()}.
start() ->
    gen_server:start({local, ?MODULE}, ?MODULE,
                          [db_path()], []).

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE,
                          [db_path()], []).

-spec stop() -> ok.
stop() ->
    catch gen_server:call(?MODULE, stop),
    ok.

-spec lookup(binary()) -> not_found | {ok, {Salt :: binary(), Verifier :: binary()}}.
lookup(Username) when is_binary(Username) ->
    case gen_server:call(?MODULE, {lookup, Username}, infinity) of
    not_found -> not_found;
    {ok, Result} -> {ok, binary_to_term(Result, [safe])}
    end.

-spec delete(binary()) -> ok.
delete(Username) when is_binary(Username) ->
    gen_server:call(?MODULE, {delete, Username}, infinity).

-spec store(binary(), {binary(), binary()}) -> ok.
store(Username, {Salt, Verifier}) when is_binary(Username), is_binary(Salt), is_binary(Verifier) ->
    gen_server:call(?MODULE, {store, Username, term_to_binary({Salt, Verifier})}, infinity).


%% gen_server callbacks

init([DbPath]) ->
    {ok, bitcask:open(DbPath, [read_write, sync_on_put])}.


handle_call({lookup, Username}, _From, State) ->
    {reply, bitcask:get(State, Username), State};

handle_call({delete, Username}, _From, State) ->
    {reply, bitcask:delete(State, Username), State};

handle_call({store, Username, Value}, _From, State) ->
    {reply, bitcask:put(State, Username, Value), State};

handle_call(stop, _From, State) ->
    bitcask:close(State),
    {stop, normal, ok, []}.


handle_cast(_Req, State) ->
    {noreply, State}.


handle_info(timeout, State) ->
    {noreply, State}.


code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


terminate(_Reason, State) ->
    bitcask:close(State).


%% internal API

db_path() ->
    PrivDir = code:priv_dir(ssms_auth),
    ssms_auth:get_app_env(db_path, PrivDir ++ "/ssms_auth_db.bitcask").
