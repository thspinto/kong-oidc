#!/bin/bash
set -e


source .env
export LUA_VERSION=${LUA_VERSION}
export KONG_VERSION=${KONG_VERSION}
export LUA_RESTY_OPENIDC_VERSION=${LUA_RESTY_OPENIDC_VERSION}

pip install hererocks
hererocks lua_install -r^ --lua=${LUA_VERSION}
export PATH=${PATH}:${PWD}/lua_install/bin

if [[ "$OSTYPE" == "darwin"* ]]; then
  brew tap kong/kong
  brew install kong
else
  luarocks install kong ${KONG_VERSION}
fi
luarocks install lua-resty-openidc ${LUA_RESTY_OPENIDC_VERSION}
luarocks install lua-cjson
luarocks install luaunit
luarocks install luacov
