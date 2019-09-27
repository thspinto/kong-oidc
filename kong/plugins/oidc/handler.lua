local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local cjson = require("cjson")

OidcHandler.PRIORITY = 1000


function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    ngx.log(ngx.DEBUG, "OidcHandler processing request, path: " .. ngx.var.request_uri)
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local response
  if oidcConfig.introspection_endpoint then
    response = introspect(oidcConfig)
    if response then
      utils.injectUser(response)
    end
  end

  if response == nil then
    response = make_oidc(oidcConfig)
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

function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)

  -- inspiration: https://docs.konghq.com/hub/kong-inc/openid-connect/, see authorization_query_args_client
  -- check request args for login_hint and if exists then add
  local args, err = ngx.req.get_uri_args()
  if not err then
    local login_hint = args["login_hint"]
    if login_hint then
      ngx.log(ngx.DEBUG, "OidcHandler found login_hint query param: " .. login_hint .. " adding it authorization_params")
      oidcConfig["authorization_params"] = {
        login_hint = login_hint
      }
    end
  end

  -- grab X-Requested-With Header to see if request was from browser/ajax
  local unauth_action = nil
  local xhr_value = ngx.req.get_headers()["X-Requested-With"]

  -- was the request ajax/async?
  if xhr_value == "XMLHttpRequest" then
    -- reference: https://github.com/zmartzone/lua-resty-openidc/blob/master/lib/resty/openidc.lua#L1436
    -- set to deny so resty.openidc returns instead of redirects (ends request)
    ngx.log(ngx.DEBUG, "OidcHandler detected the request was ajax/async setting unauth_action=deny")
    unauth_action = "deny"
  end

  local res, err = require("resty.openidc").authenticate(oidcConfig, nil, unauth_action)

  -- if err is "unauthorized request" we know that token/session has expired/invalid AND request is Ajax/Async since
  -- code execution has gone this far, so return 401 status code to allow client to respond accordingly
  if err == "unauthorized request" then
    ngx.log(ngx.DEBUG, "OidcHandler returning 401 status code for unauthorized ajax/async request")
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say(cjson.encode({ status = ngx.status, request_path = ngx.var.request_uri}))
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
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
    local res, err = require("resty.openidc").introspect(oidcConfig)
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


return OidcHandler
