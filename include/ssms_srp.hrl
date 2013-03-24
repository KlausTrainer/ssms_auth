-record(ssms_srp_opts, {
    generator = <<>> :: binary(),
    prime = <<>> :: binary(),
    multiplier = <<>> :: binary()
}).

-define(SRP_AUTH_CACHE, ssms_srp_auth_cache).
