--------------------------------------------------
--               Declare Contants               --
--------------------------------------------------
local constants = {

  -- Request Headers
  REQUEST_HEADERS = {
    X_ACCESS_TOKEN = "X-Access-Token",
    X_ID_TOKEN = "X-ID-Token",
    X_USERINFO = "X-Userinfo",
  },

  -- unauth_action values
  UNAUTH_ACTION = {
    PASS = "pass",
    DENY = "deny",
    NIL = nil,
  }
}


return constants
