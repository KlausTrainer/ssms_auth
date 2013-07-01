PROJECT = ssms

# options

CT_SUITES = srp
PLT_APPS = crypto asn1 public_key ssl sasl

# dependencies

DEPS = cowboy jiffy bitcask
dep_cowboy = https://github.com/extend/cowboy.git 0.8.6
dep_jiffy = https://github.com/davisp/jiffy.git 0.8.4
dep_bitcask = https://github.com/basho/bitcask.git 1.6.3

TEST_DEPS = ibrowse
dep_ibrowse = https://github.com/cmullaparthi/ibrowse.git v4.0.2

# standard targets

include erlang.mk

check: tests

test: tests
