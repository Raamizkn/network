"""
Configuration Retrieval Module implementation.
"""

import os
from typing import Dict, List, Optional, Union, Any

from network_auditor.device_inventory.inventory import Device
from network_auditor.connection.manager import ConnectionManager
from network_auditor.utils.logger import logger
from network_auditor.utils.exceptions import CommandExecutionError
from network_auditor.config import REPORTS_DIR


class ConfigRetriever:
    """
    Retrieves configurations from network devices.
    """

    # Default commands for retrieving configurations from different device types
    DEFAULT_CONFIG_COMMANDS = {
        'cisco_ios': 'show running-config',
        'cisco_nxos': 'show running-config',
        'cisco_asa': 'show running-config',
        'cisco_xe': 'show running-config',
        'cisco_xr': 'show running-config',
        'juniper': 'show configuration | display set',
        'juniper_junos': 'show configuration | display set',
        'arista_eos': 'show running-config',
        'f5_ltm': 'list /ltm',
        'paloalto_panos': 'show config running',
        'fortinet': 'show full-configuration',
        'hp_comware': 'display current-configuration',
        'hp_procurve': 'show running-config',
        'huawei': 'display current-configuration',
        'linux': 'cat /etc/network/interfaces',
    }

    # Additional commands to retrieve for compliance auditing
    ADDITIONAL_COMMANDS = {
        'cisco_ios': [
            'show version',
            'show interfaces',
            'show ip interface brief',
            'show vlan brief',
            'show access-lists',
            'show ip route',
            'show cdp neighbors',
            'show inventory',
            'show environment',
            'show users',
        ],
        'cisco_nxos': [
            'show version',
            'show interface',
            'show ip interface brief',
            'show vlan',
            'show access-lists',
            'show ip route',
            'show cdp neighbors',
            'show inventory',
            'show environment',
            'show users',
        ],
        'cisco_asa': [
            'show version',
            'show interface',
            'show nameif',
            'show access-list',
            'show route',
            'show inventory',
            'show environment',
            'show user',
        ],
        'juniper': [
            'show version',
            'show interfaces',
            'show route',
            'show firewall',
            'show system users',
        ],
        'arista_eos': [
            'show version',
            'show interfaces',
            'show ip interface brief',
            'show vlan',
            'show access-lists',
            'show ip route',
            'show inventory',
            'show environment',
            'show users',
        ],
    }

    def __init__(self, connection_manager: ConnectionManager):
        """
        Initialize the configuration retriever.

        Args:
            connection_manager (ConnectionManager): The connection manager to use.
        """
        self.connection_manager = connection_manager
        self.configs: Dict[str, Dict[str, Any]] = {}

    def get_config_command(self, device: Device) -> str:
        """
        Get the command to retrieve the configuration for a device.

        Args:
            device (Device): The device to get the command for.

        Returns:
            str: The command to retrieve the configuration.
        """
        return self.DEFAULT_CONFIG_COMMANDS.get(
            device.device_type, 'show running-config'
        )

    def get_additional_commands(self, device: Device) -> List[str]:
        """
        Get additional commands to retrieve for a device.

        Args:
            device (Device): The device to get the commands for.

        Returns:
            List[str]: The additional commands to retrieve.
        """
        return self.ADDITIONAL_COMMANDS.get(device.device_type, [])

    def retrieve_config(self, device: Device, save_to_file: bool = True) -> str:
        """
        Retrieve the configuration from a device.

        Args:
            device (Device): The device to retrieve the configuration from.
            save_to_file (bool, optional): Whether to save the configuration to a file.
                Defaults to True.

        Returns:
            str: The device configuration.

        Raises:
            CommandExecutionError: If the configuration cannot be retrieved.
        """
        try:
            command = self.get_config_command(device)
            logger.info(f"Retrieving configuration from {device.hostname} ({device.ip_address})")
            config = self.connection_manager.execute_command(device, command)
            
            if not config:
                raise CommandExecutionError(f"Empty configuration retrieved from {device.hostname} ({device.ip_address})")
            
            # Store the configuration
            device_id = f"{device.hostname}_{device.ip_address}"
            self.configs[device_id] = {'running_config': config}
            
            # Save to file if requested
            if save_to_file:
                self._save_config_to_file(device, config)
                
            logger.info(f"Successfully retrieved configuration from {device.hostname} ({device.ip_address})")
            return config
        except Exception as e:
            error_msg = f"Error retrieving configuration from {device.hostname} ({device.ip_address}): {str(e)}"
            logger.error(error_msg)
            raise CommandExecutionError(error_msg)

    def retrieve_additional_info(self, device: Device, save_to_file: bool = True) -> Dict[str, str]:
        """
        Retrieve additional information from a device.

        Args:
            device (Device): The device to retrieve the information from.
            save_to_file (bool, optional): Whether to save the information to files.
                Defaults to True.

        Returns:
            Dict[str, str]: A dictionary mapping command names to their outputs.
        """
        results = {}
        device_id = f"{device.hostname}_{device.ip_address}"
        
        if device_id not in self.configs:
            self.configs[device_id] = {}
            
        commands = self.get_additional_commands(device)
        if not commands:
            logger.info(f"No additional commands defined for device type {device.device_type}")
            return results
            
        logger.info(f"Retrieving additional information from {device.hostname} ({device.ip_address})")
        
        for command in commands:
            try:
                logger.debug(f"Executing command on {device.hostname}: {command}")
                output = self.connection_manager.execute_command(device, command)
                
                # Store the command output
                command_key = command.replace(' ', '_')
                results[command_key] = output
                self.configs[device_id][command_key] = output
                
                # Save to file if requested
                if save_to_file:
                    self._save_command_output_to_file(device, command, output)
                    
                logger.debug(f"Successfully executed command on {device.hostname}: {command}")
            except Exception as e:
                logger.warning(f"Error executing command on {device.hostname}: {command} - {str(e)}")
                # Continue with other commands even if one fails
                
        logger.info(f"Successfully retrieved additional information from {device.hostname} ({device.ip_address})")
        return results

    def _save_config_to_file(self, device: Device, config: str) -> None:
        """
        Save a device configuration to a file.

        Args:
            device (Device): The device the configuration is from.
            config (str): The configuration to save.
        """
        try:
            # Create directory for device
            device_dir = os.path.join(REPORTS_DIR, 'configs', device.hostname)
            os.makedirs(device_dir, exist_ok=True)
            
            # Save configuration to file
            config_file = os.path.join(device_dir, 'running_config.txt')
            with open(config_file, 'w') as f:
                f.write(config)
                
            logger.debug(f"Saved configuration for {device.hostname} to {config_file}")
        except Exception as e:
            logger.warning(f"Error saving configuration for {device.hostname} to file: {str(e)}")

    def _save_command_output_to_file(self, device: Device, command: str, output: str) -> None:
        """
        Save command output to a file.

        Args:
            device (Device): The device the output is from.
            command (str): The command that was executed.
            output (str): The command output to save.
        """
        try:
            # Create directory for device
            device_dir = os.path.join(REPORTS_DIR, 'configs', device.hostname)
            os.makedirs(device_dir, exist_ok=True)
            
            # Create a safe filename from the command
            filename = command.replace(' ', '_').replace('|', '').replace('/', '_') + '.txt'
            
            # Save output to file
            output_file = os.path.join(device_dir, filename)
            with open(output_file, 'w') as f:
                f.write(output)
                
            logger.debug(f"Saved output of command '{command}' for {device.hostname} to {output_file}")
        except Exception as e:
            logger.warning(f"Error saving output of command '{command}' for {device.hostname} to file: {str(e)}")

    def get_stored_config(self, device: Device) -> Optional[str]:
        """
        Get the stored configuration for a device.

        Args:
            device (Device): The device to get the configuration for.

        Returns:
            Optional[str]: The stored configuration, or None if not available.
        """
        device_id = f"{device.hostname}_{device.ip_address}"
        if device_id in self.configs and 'running_config' in self.configs[device_id]:
            return self.configs[device_id]['running_config']
        return None

    def get_stored_command_output(self, device: Device, command: str) -> Optional[str]:
        """
        Get the stored output of a command for a device.

        Args:
            device (Device): The device to get the output for.
            command (str): The command to get the output for.

        Returns:
            Optional[str]: The stored command output, or None if not available.
        """
        device_id = f"{device.hostname}_{device.ip_address}"
        command_key = command.replace(' ', '_')
        if device_id in self.configs and command_key in self.configs[device_id]:
            return self.configs[device_id][command_key]
        return None