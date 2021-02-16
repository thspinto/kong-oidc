local lu = require("luaunit")
local constants = require("kong.plugins.oidc.util.constants")

TestIntrospect = require("test.unit.mockable_case"):extend()


function TestIntrospect:setUp()
  TestIntrospect.super:setUp()
  package.loaded["resty.openidc"] = nil
  -- @todo: modularize this mock
  self.module_resty = {
    openidc = {
      call_userinfo_endpoint = function(...)
        return { email = "test@gmail.net" }
      end,
      get_discovery_doc = function(opts)
        opts.discovery = { introspection_endpoint = "x" }
      end,
      jwt_verify = function(opts, access_token)
        return {}
      end
    }
  }
  package.preload["resty.openidc"] = function()
    return self.module_resty.openidc
  end
  package.loaded["kong.plugins.oidc.handler"] = nil
  self.handler = require("kong.plugins.oidc.handler")()
end

function TestIntrospect:tearDown()
  TestIntrospect.super:tearDown()
end

function TestIntrospect:test_access_token_exists()
  package.loaded["resty.openidc"].introspect = function(...) return {}, nil end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  local call_userinfo_endpoint_called = false
  self.module_resty.openidc.call_userinfo_endpoint = function(opts, access_token)
    call_userinfo_endpoint_called = true
    return { email = "test@gmail.com" }
  end

  local dict = {}
  function dict:get(key) return key end
  _G.ngx.shared = {introspection = dict }

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("introspect succeeded"))
  lu.assertTrue(call_userinfo_endpoint_called)
  lu.assertEquals(headers[constants.REQUEST_HEADERS.X_USERINFO], "eyJzdWIiOiJzdWIifQ==")
end

function TestIntrospect:test_no_authorization_header()
  package.loaded["resty.openidc"].authenticate = function(...) return {}, nil, "/", { close = function() end } end
  ngx.req.get_headers = function() return {} end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({})
  lu.assertFalse(self:log_contains(self.mocked_ngx.ERR))
  lu.assertEquals(headers[constants.REQUEST_HEADERS.X_USERINFO], nil)
end


lu.run()
