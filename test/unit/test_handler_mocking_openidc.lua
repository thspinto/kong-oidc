local lu = require("luaunit")
TestHandler = require("test.unit.mockable_case"):extend()
local session = nil;
local idpAuthPath = "/path/to/idp/authentication"
local publicRoute = "/this/route/is/publicly/accessible"
local constants = require("kong.plugins.oidc.util.constants")

function TestHandler:setUp()
  TestHandler.super:setUp()

  session = {
    close = function(...) end
  }

  package.loaded["cjson"] = nil
  self.cjson = {
    encode = function(...) end,
    decode = function(...) end
  }
  package.preload["cjson"] = function()
    return self.cjson
  end

  package.loaded["kong.plugins.oidc.utils"] = nil
  package.preload["kong.plugins.oidc.utils"] = require("kong.plugins.oidc.utils")

  package.loaded["resty.openidc"] = nil
  self.module_resty = {
    openidc = {
      authenticate = function(...)
        return {}, nil, "/", session
      end,
      call_userinfo_endpoint = function(...)
        return { email = "test@gmail.com" }
      end,
      get_discovery_doc = function(opts)
        opts.discovery = opts.discovery or {}
        return opts
      end
    }
  }
  package.preload["resty.openidc"] = function()
    return self.module_resty.openidc
  end

  -- todo: can we simplify this?
  -- reload kong.plugins.oidc.handler to force reload of resty.openidc
  package.loaded["kong.plugins.oidc.handler"] = nil
  self.handler = require("kong.plugins.oidc.handler")()
end

function TestHandler:tearDown()
  TestHandler.super:tearDown()
end

function TestHandler:test_authenticate_is_called()
  -- arrange
  local authenticate_called = false
  self.module_resty.openidc.authenticate = function(opts)
    authenticate_called = true
    return {}, false, "/", session
  end

  -- act
  self.handler:access({})

  -- assert
  lu.assertTrue(authenticate_called)
end

function TestHandler:test_authenticate_ok_with_userinfo()
  -- arrange
  local authenticate_called = false
  self.module_resty.openidc.authenticate = function(opts)
    authenticate_called = true
    return {user = {sub = "sub"}}, false, "/", session
  end
  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  -- act
  self.handler:access({})

  -- assert
  lu.assertTrue(authenticate_called)
  lu.assertEquals(ngx.ctx.authenticated_credential.id, "sub")
  lu.assertEquals(headers[constants.REQUEST_HEADERS.X_USERINFO], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_authenticate_ok_with_no_accesstoken()
  -- arrange
  local authenticate_called = false
  self.module_resty.openidc.authenticate = function(opts)
    authenticate_called = true
    return {}, true, "/", session
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  -- act
  self.handler:access({})

  -- assert
  lu.assertTrue(authenticate_called)
  lu.assertNil(headers[constants.REQUEST_HEADERS.X_ACCESS_TOKEN])
end

function TestHandler:test_authenticate_ok_with_accesstoken()
  -- arrange
  local authenticate_called = false
  self.module_resty.openidc.authenticate = function(opts)
    authenticate_called = true
    return {access_token = "ACCESS_TOKEN"}, true, "/", session
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  -- act
  self.handler:access({})

  -- assert
  lu.assertTrue(authenticate_called)
  lu.assertEquals(headers[constants.REQUEST_HEADERS.X_ACCESS_TOKEN], "ACCESS_TOKEN")
end

function TestHandler:test_authenticate_ok_with_no_idtoken()
  -- arrange
  local authenticate_called = false
  self.module_resty.openidc.authenticate = function(opts)
    authenticate_called = true
    return {}, true, "/", session
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  -- act
  self.handler:access({})

  -- assert
  lu.assertTrue(authenticate_called)
  lu.assertNil(headers[constants.REQUEST_HEADERS.X_ID_TOKEN])
end

function TestHandler:test_authenticate_ok_with_idtoken()
  -- arrange
  local authenticate_called = false
  self.module_resty.openidc.authenticate = function(opts)
    authenticate_called = true
    return {id_token = {sub = "sub"}}, true, "/", session
  end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  -- act
  self.handler:access({})

  -- assert
  lu.assertTrue(authenticate_called)
  lu.assertEquals(headers[constants.REQUEST_HEADERS.X_ID_TOKEN], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_authenticate_error_no_recovery()
  -- arrange
  local statusCode = nil
  local authenticate_called = false
  package.loaded["kong.plugins.oidc.utils"].exit = function(httpStatusCode, message, ngxCode)
    statusCode = httpStatusCode
  end
  self.module_resty.openidc.authenticate = function(opts)
    authenticate_called = true
    return {}, true, "/", session
  end

  -- act
  self.handler:access({})

  -- assert
  lu.assertTrue(authenticate_called)
  lu.assertEquals(statusCode, 500)
end

function TestHandler:test_authenticate_nok_with_recovery()
  -- arrange
  local redirect = nil
  ngx.redirect = function(path)
    redirect = path
  end
  self.module_resty.openidc.authenticate = function(opts)
    return {}, true, "/", session
  end

  -- aact
  self.handler:access({recovery_page_path = "x"})

  -- arrange
  lu.assertEquals(redirect, "x")
end

function TestHandler:test_introspect_called_when_bearer_token()
  -- arrange
  local instrospect_called = false
  self.module_resty.openidc.introspect = function(opts)
    instrospect_called = true
    return false, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  -- act
  self.handler:access({discovery = { introspection_endpoint = "x" }})

  -- assert
  lu.assertTrue(instrospect_called)
end

function TestHandler:test_introspect_ok_with_userinfo()
  -- arrange
  local called_userinfo_endpoint = false
  local userinfo_to_be_encoded = nil
  local instrospect_called = false

  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.module_resty.openidc.introspect = function(opts)
    instrospect_called = true
    return {}, false
  end

  self.module_resty.openidc.call_userinfo_endpoint = function(...)
    called_userinfo_endpoint = true
    return { email = "test@gmail.com", email_verified = true }
  end

  self.cjson.encode = function(x)
    userinfo_to_be_encoded = x
  end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  -- act
  self.handler:access({ discovery = { introspection_endpoint = "x" }})

  -- assert
  lu.assertTrue(instrospect_called)
  lu.assertTrue(called_userinfo_endpoint)
  lu.assertEquals(userinfo_to_be_encoded.email, "test@gmail.com")
  lu.assertEquals(headers[constants.REQUEST_HEADERS.X_USERINFO], "eyJzdWIiOiJzdWIifQ==")
  lu.assertEquals(headers[constants.REQUEST_HEADERS.X_ACCESS_TOKEN], 'xxx')
end

function TestHandler:test_bearer_only_with_good_token()
  -- arrange
  local introspect_called = false
  self.module_resty.openidc.introspect = function(opts)
    introspect_called = true
    return {sub = "sub", exp = 1589290625}, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  -- act
  self.handler:access({ discovery = { introspection_endpoint = "x" }, bearer_only = "yes", realm = "kong"})

  -- assert
  lu.assertTrue(introspect_called)
  lu.assertEquals(headers[constants.REQUEST_HEADERS.X_USERINFO], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_bearer_only_with_bad_token()
  -- arrange
  local introspect_called = false
  self.module_resty.openidc.introspect = function(opts)
    introspect_called = true
    return {}, "validation failed"
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  -- act
  self.handler:access({ discovery = { introspection_endpoint = "x" }, bearer_only = "yes", realm = "kong"})

  -- assert
  lu.assertTrue(introspect_called)
  lu.assertEquals(ngx.header["WWW-Authenticate"], 'Bearer realm="kong",error="validation failed"')
  lu.assertEquals(ngx.status, ngx.HTTP_UNAUTHORIZED)
end

function TestHandler:test_authenticate_ok_with_login_hint()
  -- arrange
  local auth_param_login_hint

  ngx.req.get_uri_args = function()
    return {
      login_hint = "username123"
    }
  end

  self.module_resty.openidc.authenticate = function(opts)
    auth_param_login_hint= opts.authorization_params.login_hint
    return {}, true, "/", session
  end

  -- act
  self.handler:access({})

  -- assert
  lu.assertTrue(self:log_contains("login_hint found"))
  lu.assertEquals(auth_param_login_hint, "username123")
end

function TestHandler:test_authenticate_ok_with_xmlhttprequest()
  -- arrange
  local actual_unauth_action

  -- add XMLHttpRequest to headers
  ngx.req.get_headers = function()
    local headers = {}
    headers["X-Requested-With"] = "XMLHttpRequest"
    return headers
  end

  -- mock authenticate to be able to check unauth_action
  self.module_resty.openidc.authenticate = function(opts, target_url, unauth_action)
    actual_unauth_action = unauth_action
    return {}, false, "/", session
  end

  -- act
  self.handler:access({ force_authentication_path = idpAuthPath})

  -- assert
  lu.assertTrue(self:log_contains("ajax/async request detected"))
  lu.assertEquals(actual_unauth_action, constants.UNAUTH_ACTION.DENY)
end

function TestHandler:test_authenticate_nok_with_xmlhttprequest()
  -- arrange
  ngx.var.request_uri = "/api/auth/unauthorized"
  local statusCode
  local message_status
  local message_request_path

  -- add XMLHttpRequest to headers
  ngx.req.get_headers = function()
    local headers = {}
    headers["X-Requested-With"] = "XMLHttpRequest"
    return headers
  end

  -- mock authenticate to be able to check unauth_action
  self.module_resty.openidc.authenticate = function(opts, target_url, unauth_action)
    return {}, "unauthorized request", "/", session
  end

  -- mock encode to simply return parameter to check message used in utils.exit
  self.cjson.encode = function(x)
    return x
  end

  package.loaded["kong.plugins.oidc.utils"].exit = function(httpStatusCode, message, ngxCode)
    statusCode = httpStatusCode
    message_status = message.status
    message_request_path = message.request_path
  end

  -- act
  self.handler:access({})

  -- assert
  lu.assertEquals(message_status, ngx.HTTP_UNAUTHORIZED)
  lu.assertEquals(message_request_path, ngx.var.request_uri)
  lu.assertTrue(self:log_contains("ajax/async request detected"))
  lu.assertEquals(statusCode, ngx.HTTP_UNAUTHORIZED)
end

function TestHandler:test_authenticate_with_session_cookie_samesite_set_to_none()
  -- arrange
  local opts = {
    session = {
      cookie = {
        samesite = "None"
      }
    }
  }

  local v = nil;

  self.module_resty.openidc.authenticate = function(opts, target_url, unauth_action, session_opts)
    v = session_opts
    return {}, true, "/", session
  end


  -- act
  self.handler:access(opts)

  -- assert
  lu.assertItemsEquals(v, opts.session)
end

function TestHandler:test_authenticate_ok_to_force_authentication_path()
  -- arrange
  local actual_unauth_action
  ngx.var.request_uri = idpAuthPath

  -- mock authenticate to be able to check unauth_action
  self.module_resty.openidc.authenticate = function(opts, target_url, unauth_action)
    actual_unauth_action = unauth_action
    return {}, false, "/", session
  end
  -- act
  self.handler:access({ force_authentication_path = idpAuthPath })

  -- assert
  lu.assertTrue(self:log_contains("force_authentication_path matched request"))
  lu.assertEquals(actual_unauth_action, nil)
end

function TestHandler:test_authenticate_ok_to_non_force_authentication_path()
  -- arrange
  local actual_unauth_action

  -- mock authenticate to be able to check unauth_action
  self.module_resty.openidc.authenticate = function(opts, target_url, unauth_action)
    actual_unauth_action = unauth_action
    return {}, false, "/", session
  end
  -- act
  self.handler:access({ force_authentication_path = idpAuthPath })

  -- assert
  lu.assertEquals(actual_unauth_action, constants.UNAUTH_ACTION.PASS)
end

function TestHandler:test_authenticate_nok_to_force_authentication_path_with_xmlhttprequest()
  -- arrange
  local actual_unauth_action
  ngx.var.request_uri = idpAuthPath

  -- add XMLHttpRequest to headers
  ngx.req.get_headers = function()
    local headers = {}
    headers["X-Requested-With"] = "XMLHttpRequest"
    return headers
  end

  -- mock authenticate to be able to check unauth_action
  self.module_resty.openidc.authenticate = function(opts, target_url, unauth_action)
    actual_unauth_action = unauth_action
    return {}, "unauthorized request", "/", session
  end

  -- act
  self.handler:access({ force_authentication_path = idpAuthPath})

  -- assert
  lu.assertTrue(self:log_contains("ajax/async request detected"))
  lu.assertEquals(actual_unauth_action, constants.UNAUTH_ACTION.DENY)
  lu.assertEquals(ngx.status, ngx.HTTP_UNAUTHORIZED)
end

lu.run()


