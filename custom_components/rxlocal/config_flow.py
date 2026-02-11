"""Config flow for the RxLocal integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import RxLocalApiClient, RxLocalAuthError, RxLocalConnectionError
from .const import CONF_REFRESH_TOKEN, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


class RxLocalConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for RxLocal."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
            self._abort_if_unique_id_configured()

            session = async_get_clientsession(self.hass)

            try:
                client = await RxLocalApiClient.login(
                    session=session,
                    username=user_input[CONF_EMAIL],
                    password=user_input[CONF_PASSWORD],
                )
            except RxLocalAuthError:
                errors["base"] = "invalid_auth"
            except RxLocalConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected exception during RxLocal login")
                errors["base"] = "unknown"
            else:
                data = {
                    CONF_EMAIL: user_input[CONF_EMAIL],
                    CONF_PASSWORD: user_input[CONF_PASSWORD],
                }
                if client.keycloak_refresh_token:
                    data[CONF_REFRESH_TOKEN] = client.keycloak_refresh_token

                return self.async_create_entry(
                    title=user_input[CONF_EMAIL],
                    data=data,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )
