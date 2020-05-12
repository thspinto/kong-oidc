local lu = require("luaunit")
TestHandler = require("test.unit.mockable_case"):extend()
local session = nil;


function TestHandler:setUp()
  TestHandler.super:setUp()

  session = {
    close = function(...) end
  }

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

function TestHandler:test_authenticate_ok_no_userinfo()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, false, "/", session
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
end

function TestHandler:test_authenticate_ok_with_userinfo()
  self.module_resty.openidc.authenticate = function(opts)
    return {user = {sub = "sub"}}, false, "/", session
  end
  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertEquals(ngx.ctx.authenticated_credential.id, "sub")
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_authenticate_ok_with_no_accesstoken()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, true, "/", session
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertNil(headers['X-Access-Token'])
end

function TestHandler:test_authenticate_ok_with_accesstoken()
  self.module_resty.openidc.authenticate = function(opts)
    return {access_token = "ACCESS_TOKEN"}, true, "/", session
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertEquals(headers['X-Access-Token'], "ACCESS_TOKEN")
end

function TestHandler:test_authenticate_ok_with_no_idtoken()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, true, "/", session
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertNil(headers['X-ID-Token'])
end

function TestHandler:test_authenticate_ok_with_idtoken()
  self.module_resty.openidc.authenticate = function(opts)
    return {id_token = {sub = "sub"}}, true, "/", session
  end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertEquals(headers['X-ID-Token'], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_authenticate_nok_no_recovery()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, true, "/", session
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
end

-- fix heree
function TestHandler:test_authenticate_nok_with_recovery()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, true, "/", session
  end

  self.handler:access({recovery_page_path = "x"})
  lu.assertTrue(self:log_contains("recovery page"))
end

function TestHandler:test_introspect_ok_no_userinfo()
  self.module_resty.openidc.introspect = function(opts)
    return false, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  self.handler:access({introspection_endpoint = "x"})
  lu.assertTrue(self:log_contains("introspect succeeded"))
end

function TestHandler:test_introspect_ok_with_userinfo()
  self.module_resty.openidc.introspect = function(opts)
    return {}, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({introspection_endpoint = "x"})
  lu.assertTrue(self:log_contains("introspect succeeded"))
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_bearer_only_with_good_token()
  self.module_resty.openidc.introspect = function(opts)
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

  self.handler:access({introspection_endpoint = "x", bearer_only = "yes", realm = "kong"})
  lu.assertTrue(self:log_contains("introspect succeeded"))
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_bearer_only_with_bad_token()
  self.module_resty.openidc.introspect = function(opts)
    return {}, "validation failed"
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  self.handler:access({introspection_endpoint = "x", bearer_only = "yes", realm = "kong"})

  lu.assertEquals(ngx.header["WWW-Authenticate"], 'Bearer realm="kong",error="validation failed"')
  lu.assertEquals(ngx.status, ngx.HTTP_UNAUTHORIZED)
  lu.assertFalse(self:log_contains("introspect succeeded"))
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


