local utils = require("kong.plugins.oidc.utils")
local lu = require("luaunit")
-- opts_fixture, ngx are global to prevent mutation in consecutive tests
local opts_fixture = nil

TestUtils = require("test.unit.base_case"):extend()

function TestUtils:setUp()
  -- reset opts_fixture
  opts_fixture = {
    client_id = 1,
    client_secret = 2,
    discovery = "d",
    scope = "openid",
    response_type = "code",
    ssl_verify = "no",
    token_endpoint_auth_method = "client_secret_post",
    introspection_endpoint_auth_method = "client_secret_basic",
    introspection_expiry_claim = "expires",
    introspection_cache_ignore = false,
    introspection_interval = 600,
    filters = "pattern1,pattern2,pattern3",
    logout_path = "/logout",
    redirect_uri = "http://domain.com/auth/callback",
    redirect_after_logout_uri = "/login",
    prompt = "login",
    session = { cookie = { samesite = "None" } },
    force_authentication_path = "/api/auth/login"
  }

  _G.ngx = {
    var = { request_uri = "/path"},
    req = { get_uri_args = function() return nil end }
  }
end

function TestUtils:testOptions()
  local opts, session = utils.get_options(opts_fixture, ngx)

  local expectedFilters = {
    "pattern1",
    "pattern2",
    "pattern3"
  }

  lu.assertEquals(opts.client_id, 1)
  lu.assertEquals(opts.client_secret, 2)
  lu.assertEquals(opts.discovery, "d")
  lu.assertEquals(opts.scope, "openid")
  lu.assertEquals(opts.response_type, "code")
  lu.assertEquals(opts.ssl_verify, "no")
  lu.assertEquals(opts.token_endpoint_auth_method, "client_secret_post")
  lu.assertEquals(opts.introspection_endpoint_auth_method, "client_secret_basic")
  lu.assertEquals(opts.introspection_expiry_claim, "expires")
  lu.assertEquals(opts.introspection_cache_ignore, false)
  lu.assertEquals(opts.introspection_interval, 600)
  lu.assertItemsEquals(opts.filters, expectedFilters)
  lu.assertEquals(opts.logout_path, "/logout")
  lu.assertEquals(opts.redirect_uri, "http://domain.com/auth/callback")
  lu.assertEquals(opts.redirect_after_logout_uri, "/login")
  lu.assertEquals(opts.prompt, "login")
  lu.assertEquals(session.cookie.samesite, "None")
  lu.assertEquals(opts.force_authentication_path, "/api/auth/login")

end

function TestUtils:testDiscoveryOverride()
  -- assign
  opts_fixture.discovery = nil
  opts_fixture.discovery_override = {
    authorization_endpoint = "https://localhost/auth/endpoint"
  }

  -- act
  local opts = utils.get_options(opts_fixture)

  -- assert
  lu.assertItemsEquals(opts.discovery, opts_fixture.discovery_override)
end

function TestUtils:testClearRequestHeaders()
  -- assign
  local headers = {}

  _G.ngx = {
    req = {
      clear_header = function(header)
        headers[header] = true
      end
    }
  }

  -- act
  utils.clear_request_headers()

  -- assert
  lu.assertTrue(headers["X-Access-Token"])
  lu.assertTrue(headers["X-ID-Token"])
  lu.assertTrue(headers["X-Userinfo"])
end

lu.run()
