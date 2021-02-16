ARG KONG_BASE_TAG
ARG LUA_VERSION
ARG LUA_RESTY_OPENIDC_VERSION
FROM kong:${KONG_BASE_TAG}

USER root
# Install unzip for luarocks, gcc for lua-cjson
RUN yum install -y unzip gcc
RUN luarocks install luacov
RUN luarocks install luaunit
RUN luarocks install lua-cjson
RUN luarocks install lua-resty-string

# Change openidc version when version in rockspec changes
RUN luarocks install lua-resty-openidc ${LUA_RESTY_OPENIDC_VERSION}

WORKDIR /usr/local/kong-oidc

COPY . .
