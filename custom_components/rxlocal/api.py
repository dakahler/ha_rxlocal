"""RxLocal API client.

Authentication is a three-step process:
  1. Keycloak password grant -> Keycloak access/refresh tokens
  2. GET /api/auth/rxlocal-token with Keycloak bearer + portalid header
     -> RxLocal API JWT (used for all subsequent API calls)
  3. GET /api/account/getuserinfo -> rxLocalPatientID
     (the pharmacy-specific patient ID needed for all data queries)

The JWT sub/GlobalUserId is NOT the same as rxLocalPatientID.
All patient data endpoints require rxLocalPatientID as both the patient
identifier and the groupOwnerID parameter.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any

import aiohttp

from .const import (
    API_BASE_URL,
    APP_PORTAL_ID,
    KEYCLOAK_TOKEN_URL,
    MOBILE_SECRET,
    OAUTH_CLIENT_ID,
    OAUTH_SCOPES,
    TOKEN_REFRESH_BUFFER,
)

_LOGGER = logging.getLogger(__name__)


class RxLocalApiError(Exception):
    """Base exception for RxLocal API errors."""


class RxLocalAuthError(RxLocalApiError):
    """Authentication error."""


class RxLocalConnectionError(RxLocalApiError):
    """Connection error."""


class RxLocalApiClient:
    """RxLocal API client with two-step Keycloak + RxLocal auth."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        keycloak_refresh_token: str | None = None,
    ) -> None:
        """Initialize the API client."""
        self._session = session

        # Keycloak tokens
        self._kc_access_token: str | None = None
        self._kc_refresh_token: str | None = keycloak_refresh_token
        self._kc_token_acquired_at: float = 0
        self._kc_token_lifetime: int = 300

        # RxLocal API token (obtained via token exchange)
        self._rx_token: str | None = None
        self._rx_token_acquired_at: float = 0
        self._rx_token_lifetime: int = 1800

        # User profile data from RxLocal JWT
        self._user_claims: dict[str, Any] = {}

        # Account info from /account/getuserinfo
        self._account_info: dict[str, Any] = {}
        self._rx_local_patient_id: str | None = None
        self._data_exchange_id: str | None = None

    @property
    def keycloak_refresh_token(self) -> str | None:
        """Return the current Keycloak refresh token."""
        return self._kc_refresh_token

    @property
    def user_claims(self) -> dict[str, Any]:
        """Return user claims from the RxLocal JWT."""
        return self._user_claims

    @property
    def rx_local_patient_id(self) -> str | None:
        """Return the pharmacy-specific patient ID."""
        return self._rx_local_patient_id

    @property
    def account_info(self) -> dict[str, Any]:
        """Return the full account info from getuserinfo."""
        return self._account_info

    # ------------------------------------------------------------------
    # Step 1: Keycloak authentication
    # ------------------------------------------------------------------

    async def keycloak_login(self, username: str, password: str) -> None:
        """Authenticate with Keycloak using username/password."""
        _LOGGER.debug("Keycloak password grant for %s", username)
        try:
            async with self._session.post(
                KEYCLOAK_TOKEN_URL,
                data={
                    "grant_type": "password",
                    "client_id": OAUTH_CLIENT_ID,
                    "username": username,
                    "password": password,
                    "scope": OAUTH_SCOPES,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ) as resp:
                if resp.status in (400, 401, 403):
                    body = await resp.text()
                    _LOGGER.debug("Keycloak auth rejected: %s %s", resp.status, body[:300])
                    raise RxLocalAuthError("Invalid email or password")
                if resp.status != 200:
                    body = await resp.text()
                    raise RxLocalApiError(f"Keycloak auth failed: HTTP {resp.status}")
                data = await resp.json()
        except aiohttp.ClientError as err:
            raise RxLocalConnectionError(f"Connection error: {err}") from err

        self._kc_access_token = data.get("access_token")
        self._kc_refresh_token = data.get("refresh_token")
        self._kc_token_lifetime = data.get("expires_in", 300)
        self._kc_token_acquired_at = time.monotonic()

        if not self._kc_access_token:
            raise RxLocalAuthError("No access token in Keycloak response")

        _LOGGER.debug("Keycloak login OK (expires_in=%s)", self._kc_token_lifetime)

    async def keycloak_refresh(self) -> None:
        """Refresh the Keycloak access token."""
        if not self._kc_refresh_token:
            raise RxLocalAuthError("No Keycloak refresh token")

        _LOGGER.debug("Refreshing Keycloak token")
        try:
            async with self._session.post(
                KEYCLOAK_TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "client_id": OAUTH_CLIENT_ID,
                    "refresh_token": self._kc_refresh_token,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ) as resp:
                if resp.status in (400, 401):
                    raise RxLocalAuthError("Keycloak refresh token expired")
                if resp.status != 200:
                    raise RxLocalApiError(f"Keycloak refresh failed: HTTP {resp.status}")
                data = await resp.json()
        except aiohttp.ClientError as err:
            raise RxLocalConnectionError(f"Connection error: {err}") from err

        self._kc_access_token = data.get("access_token")
        new_refresh = data.get("refresh_token")
        if new_refresh:
            self._kc_refresh_token = new_refresh
        self._kc_token_lifetime = data.get("expires_in", self._kc_token_lifetime)
        self._kc_token_acquired_at = time.monotonic()

        if not self._kc_access_token:
            raise RxLocalAuthError("No access token in Keycloak refresh response")

        _LOGGER.debug("Keycloak refresh OK")

    def _kc_token_expired(self) -> bool:
        """Check if Keycloak token is expired."""
        if not self._kc_access_token:
            return True
        elapsed = time.monotonic() - self._kc_token_acquired_at
        return elapsed >= (self._kc_token_lifetime - TOKEN_REFRESH_BUFFER)

    async def _ensure_kc_token(self) -> None:
        """Ensure we have a valid Keycloak token."""
        if self._kc_token_expired():
            await self.keycloak_refresh()

    # ------------------------------------------------------------------
    # Step 2: RxLocal token exchange
    # ------------------------------------------------------------------

    async def exchange_token(self) -> None:
        """Exchange Keycloak token for RxLocal API token."""
        await self._ensure_kc_token()

        _LOGGER.debug("Exchanging Keycloak token for RxLocal token")
        try:
            async with self._session.get(
                f"{API_BASE_URL}/auth/rxlocal-token",
                headers={
                    "Authorization": f"Bearer {self._kc_access_token}",
                    "Accept": "application/json",
                    "portalid": APP_PORTAL_ID,
                },
            ) as resp:
                if resp.status == 401:
                    body = await resp.text()
                    _LOGGER.debug("Token exchange 401: %s", body[:300])
                    raise RxLocalAuthError("Token exchange failed - unauthorized")
                if resp.status != 200:
                    body = await resp.text()
                    raise RxLocalApiError(
                        f"Token exchange failed: HTTP {resp.status}"
                    )
                data = await resp.json()
        except aiohttp.ClientError as err:
            raise RxLocalConnectionError(f"Connection error: {err}") from err

        rx_data = data.get("data", {})
        self._rx_token = rx_data.get("access_token")
        self._rx_token_acquired_at = time.monotonic()

        if not self._rx_token:
            raise RxLocalAuthError("No RxLocal token in exchange response")

        # Decode JWT to extract user profile claims
        try:
            jwt_payload = self._rx_token.split(".")[1]
            jwt_payload += "=" * (4 - len(jwt_payload) % 4)
            self._user_claims = json.loads(base64.urlsafe_b64decode(jwt_payload))
            _LOGGER.debug(
                "Token exchange OK: user=%s name=%s %s",
                self._user_claims.get("unique_name"),
                self._user_claims.get("given_name"),
                self._user_claims.get("family_name"),
            )
        except Exception:
            _LOGGER.debug("Could not decode RxLocal JWT claims")

    def _rx_token_expired(self) -> bool:
        """Check if RxLocal token is expired."""
        if not self._rx_token:
            return True
        elapsed = time.monotonic() - self._rx_token_acquired_at
        return elapsed >= (self._rx_token_lifetime - TOKEN_REFRESH_BUFFER)

    async def _ensure_rx_token(self) -> None:
        """Ensure we have a valid RxLocal API token."""
        if self._rx_token_expired():
            await self.exchange_token()

    # ------------------------------------------------------------------
    # Step 3: Account info (rxLocalPatientID discovery)
    # ------------------------------------------------------------------

    async def fetch_account_info(self) -> dict[str, Any]:
        """Fetch account info including rxLocalPatientID.

        The rxLocalPatientID is the pharmacy-specific patient ID,
        which is different from the JWT sub (GlobalUserId).
        This ID is required for all patient data API calls.
        """
        data = await self._request("GET", "account/getuserinfo")
        if isinstance(data, dict):
            self._account_info = data
            self._rx_local_patient_id = data.get("rxLocalPatientID")
            self._data_exchange_id = data.get("primaryDataExchangeIdentifier")
            _LOGGER.debug(
                "Account info OK: rxLocalPatientID=%s, globalUserID=%s",
                self._rx_local_patient_id,
                data.get("globalUserID"),
            )
        return self._account_info

    # ------------------------------------------------------------------
    # Convenience: full login flow
    # ------------------------------------------------------------------

    @classmethod
    async def login(
        cls,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
    ) -> "RxLocalApiClient":
        """Full login: Keycloak auth + RxLocal token exchange + account info."""
        client = cls(session=session)
        await client.keycloak_login(username, password)
        await client.exchange_token()
        await client.fetch_account_info()
        return client

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _get_headers(self, *, mobile: bool = False, user_id: bool = False) -> dict[str, str]:
        """Build headers for authenticated API requests."""
        headers: dict[str, str] = {
            "Authorization": f"Bearer {self._rx_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "portalid": APP_PORTAL_ID,
        }
        if mobile:
            headers["rxlocal_mobile_ss"] = MOBILE_SECRET
        if user_id and self._user_claims.get("sub"):
            headers["rxlocaluserid"] = self._user_claims["sub"]
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        mobile: bool = False,
        user_id: bool = False,
        **kwargs: Any,
    ) -> Any:
        """Make an authenticated API request with automatic token management."""
        await self._ensure_rx_token()

        url = f"{API_BASE_URL}/{path}"
        headers = self._get_headers(mobile=mobile, user_id=user_id)
        _LOGGER.debug("API request: %s %s", method, url)

        try:
            async with self._session.request(
                method, url, headers=headers, **kwargs
            ) as resp:
                if resp.status == 401:
                    _LOGGER.debug("Got 401, re-exchanging token and retrying")
                    self._rx_token = None
                    await self.exchange_token()
                    headers = self._get_headers(mobile=mobile, user_id=user_id)
                    async with self._session.request(
                        method, url, headers=headers, **kwargs
                    ) as retry:
                        if retry.status == 401:
                            raise RxLocalAuthError("Auth failed after token re-exchange")
                        return await self._parse_response(retry, method, url)
                return await self._parse_response(resp, method, url)
        except aiohttp.ClientError as err:
            raise RxLocalConnectionError(f"Connection error: {err}") from err

    @staticmethod
    async def _parse_response(
        resp: aiohttp.ClientResponse, method: str, url: str
    ) -> Any:
        """Parse API response, handling various status codes."""
        if resp.status in (200, 201):
            text = await resp.text()
            if not text:
                return {}
            try:
                data = json.loads(text)
                # Many endpoints wrap data in {serviceResult, data}
                if isinstance(data, dict) and "data" in data:
                    return data["data"]
                return data
            except json.JSONDecodeError:
                return text
        if resp.status == 403:
            body = await resp.text()
            _LOGGER.debug("403 on %s %s: %s", method, url, body[:200])
            raise RxLocalApiError(f"Access denied: {body[:100]}")
        if resp.status == 400:
            body = await resp.text()
            _LOGGER.debug("400 on %s %s: %s", method, url, body[:200])
            raise RxLocalApiError(f"Bad request: {body[:100]}")
        body = await resp.text()
        raise RxLocalApiError(f"{method} {url} -> HTTP {resp.status}: {body[:100]}")

    # ------------------------------------------------------------------
    # User profile
    # ------------------------------------------------------------------

    def get_user_profile(self) -> dict[str, Any]:
        """Get user profile from JWT claims + account info."""
        return {
            "user_id": self._user_claims.get("sub"),
            "rx_local_patient_id": self._rx_local_patient_id,
            "email": self._user_claims.get("email"),
            "given_name": self._user_claims.get("given_name"),
            "family_name": self._user_claims.get("family_name"),
            "name": (
                f"{self._user_claims.get('given_name', '')} "
                f"{self._user_claims.get('family_name', '')}"
            ).strip(),
            "phone": self._user_claims.get("mobile_phone"),
            "role": self._user_claims.get("role"),
            "username": self._user_claims.get("preferred_username"),
        }

    # ------------------------------------------------------------------
    # Data fetching methods
    # ------------------------------------------------------------------

    def _patient_id(self) -> str:
        """Return the rxLocalPatientID for API calls."""
        return self._rx_local_patient_id or self._user_claims.get("sub", "")

    async def get_patient_medications(self) -> list[dict[str, Any]]:
        """Get patient medications."""
        pid = self._patient_id()
        data = await self._request(
            "POST", "patients/getrxlocalpatientmedications",
            json={
                "rxLocalPatientID": pid,
                "groupOwnerID": pid,
                "active": True,
            },
            user_id=True,
        )
        if isinstance(data, list):
            return data
        return []

    async def get_patient_pharmacies(self) -> list[dict[str, Any]]:
        """Get patient's linked pharmacies via group locations."""
        pid = self._patient_id()
        data = await self._request(
            "GET",
            f"patient/group/owner/{pid}/locations",
        )
        if not isinstance(data, list):
            return []
        # Deduplicate by dataExchangeIdentifier
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for loc in data:
            dei = loc.get("dataExchangeIdentifier", "")
            if dei and dei in seen:
                continue
            if dei:
                seen.add(dei)
            unique.append(loc)
        return unique

    async def get_patient_vaccines(self) -> list[dict[str, Any]]:
        """Get patient vaccines."""
        pid = self._patient_id()
        data = await self._request("GET", f"patients/{pid}/vaccines")
        if isinstance(data, list):
            return data
        return []

    async def get_patient_refills(self) -> list[dict[str, Any]]:
        """Get patient refill requests."""
        pid = self._patient_id()
        params: dict[str, str] = {"rxLocalPatientID": pid}
        if self._data_exchange_id:
            params["locationDEI"] = self._data_exchange_id
        data = await self._request(
            "GET",
            f"refill/{pid}/v2",
            params=params,
            user_id=True,
        )
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "refills" in data:
            return data["refills"]
        return []
