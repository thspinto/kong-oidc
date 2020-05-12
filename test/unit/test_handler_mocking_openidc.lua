local lu = require("luaunit")
TestHandler = require("test.unit.mockable_case"):extend()
local session = nil;


function TestHandler:setUp()
  TestHandler.super:setUp()

  session = {
    close = function(...) end
  }

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
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
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
  lu.assertNil(headers['X-Access-Token'])
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
  lu.assertEquals(headers['X-Access-Token'], "ACCESS_TOKEN")
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
  lu.assertNil(headers['X-ID-Token'])
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
  lu.assertEquals(headers['X-ID-Token'], "eyJzdWIiOiJzdWIifQ==")
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
  self.handler:access({introspection_endpoint = "x"})
  
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

  package.loaded.cjson.encode = function(x)
    userinfo_to_be_encoded = x
  end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  -- act
  self.handler:access({introspection_endpoint = "x"})

  -- assert
  lu.assertTrue(instrospect_called)
  lu.assertTrue(called_userinfo_endpoint)
  lu.assertEquals(userinfo_to_be_encoded.email, "test@gmail.com")
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
  lu.assertEquals(headers['X-Access-Token'], 'xxx')
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
  self.handler:access({introspection_endpoint = "x", bearer_only = "yes", realm = "kong"})
  
  -- assert
  lu.assertTrue(introspect_called)
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
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
  self.handler:access({introspection_endpoint = "x", bearer_only = "yes", realm = "kong"})

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
  self.handler:access({})

  -- assert
  lu.assertTrue(self:log_contains("ajax/async request detected"))
  lu.assertEquals(actual_unauth_action, "deny")
end

function TestHandler:test_authenticate_nok_with_xmlhttprequest()
  -- arrange

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

  -- act
  self.handler:access({})

  -- assert
  lu.assertTrue(self:log_contains("ajax/async request detected"))
  lu.assertEquals(ngx.status, ngx.HTTP_UNAUTHORIZED)
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

lu.run()


