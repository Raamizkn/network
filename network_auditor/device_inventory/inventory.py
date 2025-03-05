"""
Device Inventory Manager implementation.
"""

import csv
import json
import os
from dataclasses import dataclass
from typing import List, Dict, Optional, Union

from network_auditor.config import DEFAULT_INVENTORY_FILE
from network_auditor.utils.logger import logger
from network_auditor.utils.exceptions import InventoryError


@dataclass
class Device:
    """
    Represents a network device in the inventory.
    """
    hostname: str
    ip_address: str
    device_type: str
    username: Optional[str] = None
    password: Optional[str] = None
    port: int = 22
    enable_password: Optional[str] = None
    use_keys: bool = False
    key_file: Optional[str] = None
    tags: List[str] = None

    def __post_init__(self):
        """
        Initialize default values after initialization.
        """
        if self.tags is None:
            self.tags = []

    def to_dict(self) -> Dict:
        """
        Convert the device to a dictionary.

        Returns:
            Dict: A dictionary representation of the device.
        """
        return {
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'device_type': self.device_type,
            'username': self.username,
            'password': self.password,
            'port': self.port,
            'enable_password': self.enable_password,
            'use_keys': self.use_keys,
            'key_file': self.key_file,
            'tags': self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Device':
        """
        Create a device from a dictionary.

        Args:
            data (Dict): A dictionary containing device information.

        Returns:
            Device: A new Device instance.
        """
        # Convert tags from string to list if necessary
        if 'tags' in data and isinstance(data['tags'], str):
            data['tags'] = [tag.strip() for tag in data['tags'].split(',')]
        
        # Convert use_keys from string to bool if necessary
        if 'use_keys' in data and isinstance(data['use_keys'], str):
            data['use_keys'] = data['use_keys'].lower() in ('true', 'yes', '1')
            
        # Convert port from string to int if necessary
        if 'port' in data and isinstance(data['port'], str):
            data['port'] = int(data['port'])
            
        return cls(**data)


class DeviceInventory:
    """
    Manages the inventory of network devices.
    """

    def __init__(self, inventory_file: str = DEFAULT_INVENTORY_FILE):
        """
        Initialize the device inventory.

        Args:
            inventory_file (str, optional): The path to the inventory file.
                Defaults to DEFAULT_INVENTORY_FILE from config.
        """
        self.inventory_file = inventory_file
        self.devices: List[Device] = []
        self._load_inventory()

    def _load_inventory(self):
        """
        Load the device inventory from the inventory file.

        Raises:
            InventoryError: If the inventory file cannot be loaded.
        """
        if not os.path.exists(self.inventory_file):
            logger.warning(f"Inventory file {self.inventory_file} does not exist. Creating empty inventory.")
            self.devices = []
            return

        try:
            file_ext = os.path.splitext(self.inventory_file)[1].lower()
            if file_ext == '.csv':
                self._load_from_csv()
            elif file_ext == '.json':
                self._load_from_json()
            else:
                raise InventoryError(f"Unsupported inventory file format: {file_ext}")
        except Exception as e:
            raise InventoryError(f"Failed to load inventory: {str(e)}")

    def _load_from_csv(self):
        """
        Load the device inventory from a CSV file.

        Raises:
            InventoryError: If the CSV file cannot be loaded.
        """
        try:
            with open(self.inventory_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                self.devices = [Device.from_dict(row) for row in reader]
            logger.info(f"Loaded {len(self.devices)} devices from {self.inventory_file}")
        except Exception as e:
            raise InventoryError(f"Failed to load CSV inventory: {str(e)}")

    def _load_from_json(self):
        """
        Load the device inventory from a JSON file.

        Raises:
            InventoryError: If the JSON file cannot be loaded.
        """
        try:
            with open(self.inventory_file, 'r') as f:
                data = json.load(f)
            self.devices = [Device.from_dict(device_data) for device_data in data]
            logger.info(f"Loaded {len(self.devices)} devices from {self.inventory_file}")
        except Exception as e:
            raise InventoryError(f"Failed to load JSON inventory: {str(e)}")

    def save_inventory(self):
        """
        Save the device inventory to the inventory file.

        Raises:
            InventoryError: If the inventory file cannot be saved.
        """
        try:
            file_ext = os.path.splitext(self.inventory_file)[1].lower()
            if file_ext == '.csv':
                self._save_to_csv()
            elif file_ext == '.json':
                self._save_to_json()
            else:
                raise InventoryError(f"Unsupported inventory file format: {file_ext}")
            logger.info(f"Saved {len(self.devices)} devices to {self.inventory_file}")
        except Exception as e:
            raise InventoryError(f"Failed to save inventory: {str(e)}")

    def _save_to_csv(self):
        """
        Save the device inventory to a CSV file.

        Raises:
            InventoryError: If the CSV file cannot be saved.
        """
        try:
            os.makedirs(os.path.dirname(self.inventory_file), exist_ok=True)
            with open(self.inventory_file, 'w', newline='') as f:
                if not self.devices:
                    writer = csv.writer(f)
                    writer.writerow(['hostname', 'ip_address', 'device_type', 'username', 'password', 
                                    'port', 'enable_password', 'use_keys', 'key_file', 'tags'])
                else:
                    fieldnames = self.devices[0].to_dict().keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for device in self.devices:
                        # Convert tags list to comma-separated string for CSV
                        device_dict = device.to_dict()
                        if device_dict['tags']:
                            device_dict['tags'] = ','.join(device_dict['tags'])
                        writer.writerow(device_dict)
        except Exception as e:
            raise InventoryError(f"Failed to save CSV inventory: {str(e)}")

    def _save_to_json(self):
        """
        Save the device inventory to a JSON file.

        Raises:
            InventoryError: If the JSON file cannot be saved.
        """
        try:
            os.makedirs(os.path.dirname(self.inventory_file), exist_ok=True)
            with open(self.inventory_file, 'w') as f:
                json.dump([device.to_dict() for device in self.devices], f, indent=2)
        except Exception as e:
            raise InventoryError(f"Failed to save JSON inventory: {str(e)}")

    def add_device(self, device: Union[Device, Dict]):
        """
        Add a device to the inventory.

        Args:
            device (Union[Device, Dict]): The device to add.

        Raises:
            InventoryError: If the device cannot be added.
        """
        try:
            if isinstance(device, dict):
                device = Device.from_dict(device)
            
            # Check if device with same hostname or IP already exists
            for existing_device in self.devices:
                if existing_device.hostname == device.hostname:
                    raise InventoryError(f"Device with hostname {device.hostname} already exists")
                if existing_device.ip_address == device.ip_address:
                    raise InventoryError(f"Device with IP address {device.ip_address} already exists")
                    
            self.devices.append(device)
            logger.info(f"Added device {device.hostname} ({device.ip_address}) to inventory")
        except Exception as e:
            if isinstance(e, InventoryError):
                raise
            raise InventoryError(f"Failed to add device: {str(e)}")

    def remove_device(self, hostname_or_ip: str):
        """
        Remove a device from the inventory.

        Args:
            hostname_or_ip (str): The hostname or IP address of the device to remove.

        Raises:
            InventoryError: If the device cannot be removed.
        """
        try:
            for i, device in enumerate(self.devices):
                if device.hostname == hostname_or_ip or device.ip_address == hostname_or_ip:
                    removed_device = self.devices.pop(i)
                    logger.info(f"Removed device {removed_device.hostname} ({removed_device.ip_address}) from inventory")
                    return
            raise InventoryError(f"Device with hostname or IP {hostname_or_ip} not found")
        except Exception as e:
            if isinstance(e, InventoryError):
                raise
            raise InventoryError(f"Failed to remove device: {str(e)}")

    def get_device(self, hostname_or_ip: str) -> Device:
        """
        Get a device from the inventory.

        Args:
            hostname_or_ip (str): The hostname or IP address of the device to get.

        Returns:
            Device: The requested device.

        Raises:
            InventoryError: If the device cannot be found.
        """
        for device in self.devices:
            if device.hostname == hostname_or_ip or device.ip_address == hostname_or_ip:
                return device
        raise InventoryError(f"Device with hostname or IP {hostname_or_ip} not found")

    def get_devices_by_tag(self, tag: str) -> List[Device]:
        """
        Get all devices with the specified tag.

        Args:
            tag (str): The tag to filter by.

        Returns:
            List[Device]: A list of devices with the specified tag.
        """
        return [device for device in self.devices if tag in device.tags]

    def get_devices_by_type(self, device_type: str) -> List[Device]:
        """
        Get all devices of the specified type.

        Args:
            device_type (str): The device type to filter by.

        Returns:
            List[Device]: A list of devices of the specified type.
        """
        return [device for device in self.devices if device.device_type == device_type]

    def get_all_devices(self) -> List[Device]:
        """
        Get all devices in the inventory.

        Returns:
            List[Device]: A list of all devices.
        """
        return self.devices 