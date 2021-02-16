ARG KONG_BASE_TAG
ARG LUA_VERSION
ARG LUA_RESTY_OPENIDC_VERSION
FROM kong:${KONG_BASE_TAG}

ENV LUA_PATH /usr/local/share/lua/${LUA_VERSION}/?.lua;/usr/local/kong-oidc/?.lua
# For lua-cjson
ENV LUA_CPATH /usr/local/lib/lua/${LUA_VERSION}/?.so

USER root
# Install unzip for luarocks, gcc for lua-cjson
RUN yum install -y unzip gcc
RUN luarocks install luacov
RUN luarocks install luaunit
RUN luarocks install lua-cjson

# Change openidc version when version in rockspec changes
RUN luarocks install lua-resty-openidc ${LUA_RESTY_OPENIDC_VERSION}

WORKDIR /usr/local/kong-oidc

COPY . .
