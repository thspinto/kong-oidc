local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local cjson = require("cjson")
local openidc = require("resty.openidc")

OidcHandler.PRIORITY = 1000


function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  local oidcConfig, oidcSessionConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    ngx.log(ngx.DEBUG, "OidcHandler processing request, path: " .. ngx.var.request_uri)
    session.configure(config)
    handle(oidcConfig, oidcSessionConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig, oidcSessionConfig)
  local response
  if oidcConfig.introspection_endpoint then
    response = introspect(oidcConfig)

    -- if response, then introspect successful
    if response then
      local access_token = utils.get_bearer_access_token_from_header(oidcConfig)
      local user_info = get_user_info(oidcConfig, response)

      if access_token then
        utils.injectAccessToken(access_token)
      end

      if user_info then
        utils.injectUser(user_info)
      end
    end

  end

  -- no valid access token, force oidc authentication
  if response == nil then
    response = make_oidc(oidcConfig, oidcSessionConfig)
    if response then
      if (response.user) then
        utils.injectUser(response.user)
      end
      if (response.access_token) then
        utils.injectAccessToken(response.access_token)
      end
      if (response.id_token) then
        utils.injectIDToken(response.id_token)
      end
    end
  end
end

function make_oidc(oidcConfig, oidcSessionConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)

  -- inspiration: https://docs.konghq.com/hub/kong-inc/openid-connect/, see authorization_query_args_client
  -- check request args for login_hint and if exists then add
  local args, err = ngx.req.get_uri_args()
  if args then
    local login_hint = args["login_hint"]
    if login_hint then
      ngx.log(ngx.DEBUG, "OidcHandler login_hint found: " .. login_hint .. ", adding it to authorization_params")
      oidcConfig["authorization_params"] = {
        login_hint = login_hint
      }
    end
  end

  -- grab X-Requested-With Header to see if request was from browser/ajax
  local unauth_action = nil
  local ngx_headers = ngx.req.get_headers()
  if ngx_headers then
    local xhr_value = ngx_headers["X-Requested-With"]
    -- was the request ajax/async?
    if xhr_value == "XMLHttpRequest" then
      -- reference: https://github.com/zmartzone/lua-resty-openidc/blob/master/lib/resty/openidc.lua#L1436
      -- set to deny so resty.openidc returns instead of redirects (ends request)
      ngx.log(ngx.DEBUG, "OidcHandler ajax/async request detected, setting unauth_action = deny")
      unauth_action = "deny"
    end
  end

  local res, err, original_url, session = openidc.authenticate(oidcConfig, nil, unauth_action, oidcSessionConfig)

  -- @todo: add unit test to check for session:close()
  -- handle and close session, prevent locking
  session:close()

  -- if err is "unauthorized request" we know that token/session has expired/invalid AND request is Ajax/Async since
  -- code execution has gone this far, so return 401 status code to allow client to respond accordingly
  if err == "unauthorized request" then
    ngx.log(ngx.DEBUG, "OidcHandler unauthorized ajax/async request detected, responding with 401 status code")
    local message = cjson.encode({ status = ngx.status, request_path = ngx.var.request_uri})
    utils.exit(ngx.HTTP_UNAUTHORIZED, message, ngx.HTTP_UNAUTHORIZED)
  end

  if err then
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

function introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    -- introspect token
    local res, err = openidc.introspect(oidcConfig)

    -- check if token is valid (err returned)
    if err then
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end

function get_user_info(oidcConfig, introspect_response)
  local access_token = utils.get_bearer_access_token_from_header(oidcConfig)
  local user_info = utils.cache_get("userinfo", access_token)
  local err = nil
  
  -- cache miss
  if not user_info then
    ngx.log(ngx.INFO, "userinfo cache miss, calling userinfo endpoint")
    user_info, err = openidc.call_userinfo_endpoint(oidcConfig, access_token)
    
    if err then
      return nil, err
    end

    local introspection_cache_ignore = oidcConfig.introspection_cache_ignore or false
    local expiry_claim = oidcConfig.introspection_expiry_claim or "exp"
    local introspection_interval = oidcConfig.introspection_interval or 0
    
    if not introspection_cache_ignore and introspect_response[expiry_claim] then
      local ttl = introspect_response[expiry_claim]
      ngx.log(ngx.INFO, ttl)

      if expiry_claim == "exp" then --https://tools.ietf.org/html/rfc7662#section-2.2
        ttl = ttl - ngx.time()
      end
      if introspection_interval > 0 then
        if ttl > introspection_interval then
          ttl = introspection_interval
        end
      end
      ngx.log(ngx.INFO, "setting cache now")
      ngx.log(ngx.INFO, "cach ttl: " .. ttl)
      utils.cache_set("userinfo", access_token, cjson.encode(user_info), ttl)
    end

  else
    user_info = cjson.decode(user_info)
  end

  return user_info
end


return OidcHandler
