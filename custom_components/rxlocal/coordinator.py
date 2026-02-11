"""Data update coordinator for RxLocal."""

from __future__ import annotations

import asyncio
from datetime import timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import RxLocalApiClient, RxLocalApiError, RxLocalAuthError
from .const import CONF_REFRESH_TOKEN, DEFAULT_SCAN_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)


class RxLocalCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """RxLocal data update coordinator."""

    config_entry: ConfigEntry

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        )
        self.config_entry = entry
        self.client: RxLocalApiClient | None = None

    async def _ensure_client(self) -> RxLocalApiClient:
        """Ensure we have an authenticated API client."""
        if self.client is not None:
            return self.client

        session = async_get_clientsession(self.hass)
        refresh_token = self.config_entry.data.get(CONF_REFRESH_TOKEN)

        if refresh_token:
            self.client = RxLocalApiClient(
                session=session,
                keycloak_refresh_token=refresh_token,
            )
        else:
            self.client = await RxLocalApiClient.login(
                session=session,
                username=self.config_entry.data[CONF_EMAIL],
                password=self.config_entry.data[CONF_PASSWORD],
            )

        # Ensure we have the rxLocalPatientID
        if not self.client.rx_local_patient_id:
            await self.client.fetch_account_info()

        return self.client

    def _persist_refresh_token(self) -> None:
        """Update the stored Keycloak refresh token if it changed."""
        if not self.client or not self.client.keycloak_refresh_token:
            return
        current = self.config_entry.data.get(CONF_REFRESH_TOKEN)
        if self.client.keycloak_refresh_token != current:
            new_data = {
                **self.config_entry.data,
                CONF_REFRESH_TOKEN: self.client.keycloak_refresh_token,
            }
            self.hass.config_entries.async_update_entry(
                self.config_entry, data=new_data
            )
            _LOGGER.debug("Updated stored Keycloak refresh token")

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from RxLocal API."""
        try:
            client = await self._ensure_client()
            result = await self._fetch_all_data(client)
            self._persist_refresh_token()
            return result
        except RxLocalAuthError as err:
            self.client = None
            raise ConfigEntryAuthFailed(f"Authentication failed: {err}") from err
        except RxLocalApiError as err:
            if self.data:
                _LOGGER.warning(
                    "Error fetching RxLocal data (%s), keeping last known data", err
                )
                return self.data
            raise UpdateFailed(f"Error communicating with API: {err}") from err

    async def _fetch_all_data(self, client: RxLocalApiClient) -> dict[str, Any]:
        """Fetch all data from the API concurrently."""
        # User profile comes from JWT claims + account info (no API call)
        userinfo = client.get_user_profile()

        # Patient data endpoints
        results = await asyncio.gather(
            client.get_patient_medications(),
            client.get_patient_pharmacies(),
            client.get_patient_vaccines(),
            client.get_patient_refills(),
            return_exceptions=True,
        )

        medications = results[0] if not isinstance(results[0], Exception) else []
        pharmacies = results[1] if not isinstance(results[1], Exception) else []
        vaccines = results[2] if not isinstance(results[2], Exception) else []
        refills = results[3] if not isinstance(results[3], Exception) else []

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                _LOGGER.debug("API call %d failed: %s", i, result)

        data: dict[str, Any] = {
            "userinfo": userinfo,
            "medications": medications if isinstance(medications, list) else [],
            "pharmacies": pharmacies if isinstance(pharmacies, list) else [],
            "vaccines": vaccines if isinstance(vaccines, list) else [],
            "refills": refills if isinstance(refills, list) else [],
        }

        _LOGGER.debug(
            "RxLocal update: %d medications, %d pharmacies, %d vaccines, %d refills",
            len(data["medications"]),
            len(data["pharmacies"]),
            len(data["vaccines"]),
            len(data["refills"]),
        )

        return data
