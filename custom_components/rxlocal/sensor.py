"""Sensor platform for RxLocal."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import RxLocalCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up RxLocal sensors from a config entry."""
    coordinator: RxLocalCoordinator = hass.data[DOMAIN][entry.entry_id]

    entities: list[SensorEntity] = [
        RxLocalMedicationCountSensor(coordinator, entry),
        RxLocalPendingRefillsSensor(coordinator, entry),
        RxLocalPharmacySensor(coordinator, entry),
    ]

    # Create per-medication sensors if data is available
    medications = (
        coordinator.data.get("medications", []) if coordinator.data else []
    )
    for i, med in enumerate(medications):
        if not isinstance(med, dict):
            continue
        rx_number = str(med.get("rxNumber", i))
        drug_name = (
            med.get("dispensedAs")
            or med.get("writtenAs")
            or med.get("displayName")
            or f"Medication {rx_number}"
        )
        entities.append(
            RxLocalMedicationSensor(coordinator, entry, rx_number, drug_name, i)
        )

    async_add_entities(entities)


class RxLocalBaseSensor(CoordinatorEntity[RxLocalCoordinator], SensorEntity):
    """Base class for RxLocal sensors."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: RxLocalCoordinator,
        entry: ConfigEntry,
        description: SensorEntityDescription,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._entry = entry

        # Build device info from user profile
        user_name = "RxLocal Patient"
        if coordinator.data:
            userinfo = coordinator.data.get("userinfo", {})
            name = userinfo.get("name", "")
            if name:
                user_name = f"RxLocal - {name}"

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=user_name,
            manufacturer="RxLocal / RedSail Technologies",
            entry_type=DeviceEntryType.SERVICE,
        )


class RxLocalMedicationCountSensor(RxLocalBaseSensor):
    """Sensor for the total number of active medications."""

    def __init__(
        self, coordinator: RxLocalCoordinator, entry: ConfigEntry
    ) -> None:
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            entry,
            SensorEntityDescription(
                key="prescription_count",
                translation_key="prescription_count",
                icon="mdi:pill",
                state_class=SensorStateClass.MEASUREMENT,
            ),
        )

    @property
    def native_value(self) -> int | None:
        """Return the total number of active medications."""
        if self.coordinator.data is None:
            return None
        return len(self.coordinator.data.get("medications", []))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        if self.coordinator.data is None:
            return {}
        userinfo = self.coordinator.data.get("userinfo", {})
        attrs: dict[str, Any] = {
            "patient_name": userinfo.get("name"),
            "patient_email": userinfo.get("email"),
        }
        vaccines = self.coordinator.data.get("vaccines", [])
        if vaccines:
            attrs["vaccine_count"] = len(vaccines)
        return attrs


class RxLocalPendingRefillsSensor(RxLocalBaseSensor):
    """Sensor for pending refill requests."""

    def __init__(
        self, coordinator: RxLocalCoordinator, entry: ConfigEntry
    ) -> None:
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            entry,
            SensorEntityDescription(
                key="pending_refills",
                translation_key="pending_refills",
                icon="mdi:autorenew",
                state_class=SensorStateClass.MEASUREMENT,
            ),
        )

    @property
    def native_value(self) -> int | None:
        """Return the number of pending refills."""
        if self.coordinator.data is None:
            return None
        return len(self.coordinator.data.get("refills", []))


class RxLocalPharmacySensor(RxLocalBaseSensor):
    """Sensor for linked pharmacy."""

    def __init__(
        self, coordinator: RxLocalCoordinator, entry: ConfigEntry
    ) -> None:
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            entry,
            SensorEntityDescription(
                key="pharmacy",
                translation_key="pharmacy",
                icon="mdi:store",
            ),
        )

    @property
    def native_value(self) -> str | None:
        """Return the primary pharmacy name."""
        if self.coordinator.data is None:
            return None
        pharmacies = self.coordinator.data.get("pharmacies", [])
        if not pharmacies:
            return "No pharmacy linked"
        first = pharmacies[0]
        if isinstance(first, dict):
            return first.get("name")
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        if self.coordinator.data is None:
            return {}
        pharmacies = self.coordinator.data.get("pharmacies", [])
        if not pharmacies:
            return {}
        first = pharmacies[0]
        if not isinstance(first, dict):
            return {}
        return {
            "address": first.get("addressLine1"),
            "city": first.get("city"),
            "state": first.get("state"),
            "zip": first.get("zip"),
            "phone": first.get("phone"),
            "email": first.get("email"),
            "pharmacy_count": len(pharmacies),
        }


class RxLocalMedicationSensor(
    CoordinatorEntity[RxLocalCoordinator], SensorEntity
):
    """Sensor for a specific medication."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: RxLocalCoordinator,
        entry: ConfigEntry,
        rx_number: str,
        drug_name: str,
        index: int,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._rx_number = rx_number
        self._drug_name = drug_name
        self._index = index
        self.entity_description = SensorEntityDescription(
            key=f"rx_{rx_number}",
            name=drug_name,
            icon="mdi:medication",
        )
        self._attr_unique_id = f"{entry.entry_id}_rx_{rx_number}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="RxLocal Patient",
            manufacturer="RxLocal / RedSail Technologies",
            entry_type=DeviceEntryType.SERVICE,
        )

    def _get_med_data(self) -> dict[str, Any] | None:
        """Get the medication data for this sensor."""
        if not self.coordinator.data:
            return None
        medications = self.coordinator.data.get("medications", [])
        for med in medications:
            if not isinstance(med, dict):
                continue
            if str(med.get("rxNumber", "")) == self._rx_number:
                return med
        if self._index < len(medications):
            med = medications[self._index]
            if isinstance(med, dict):
                return med
        return None

    @property
    def native_value(self) -> str | None:
        """Return the refill request status."""
        med = self._get_med_data()
        if not med:
            return None
        return med.get("refillRequestStatus") or med.get("rxStatusType") or "Active"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        med = self._get_med_data()
        if not med:
            return {}
        return {
            "rx_number": med.get("rxNumber"),
            "drug_name": self._drug_name,
            "pharmacy": med.get("pharmacyName"),
            "refills_remaining": med.get("refillsRemaining"),
            "days_supply": med.get("daysSupply"),
            "last_filled": med.get("lastSoldOn"),
            "date_written": med.get("dateWritten"),
            "expiration_date": med.get("expirationDate"),
            "can_request_refill": med.get("canRequestRefill"),
            "requires_renewal": med.get("requiresRenewal"),
            "quantity_remaining": med.get("quantityRemaining"),
        }
