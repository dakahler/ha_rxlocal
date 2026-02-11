"""Constants for the RxLocal integration."""

DOMAIN = "rxlocal"

# Keycloak OIDC endpoints
KEYCLOAK_TOKEN_URL = (
    "https://auth.redsailapp.com/auth/realms/rxlocal"
    "/protocol/openid-connect/token"
)

# Patient portal API
API_BASE_URL = "https://patient.rxlocal.com/api"

# OAuth2 public client (same as patient portal SPA)
OAUTH_CLIENT_ID = "patient-portal"
OAUTH_SCOPES = "openid profile email offline_access"

# Portal ID required by the API (app portal ID from SPA config)
APP_PORTAL_ID = "3A93FBAD-EE1D-41B5-9F59-E7115602E91E"

# Mobile secret header used by some endpoints
MOBILE_SECRET = "%rX60cAL5HA466DS00C2E1%"

# Polling interval: 30 minutes (prescription data doesn't change often)
DEFAULT_SCAN_INTERVAL = 1800

# Keycloak token lifetime is 300s; RxLocal token ~31 min
# Refresh proactively with 2 min buffer
TOKEN_REFRESH_BUFFER = 120

CONF_REFRESH_TOKEN = "refresh_token"
