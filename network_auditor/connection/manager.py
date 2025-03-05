"""
Connection Manager implementation.
"""

import time
from typing import Dict, Optional, Any, Tuple

import netmiko
from netmiko import ConnectHandler
from netmiko.ssh_exception import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
    SSHException,
)

from network_auditor.device_inventory.inventory import Device
from network_auditor.utils.logger import logger
from network_auditor.utils.exceptions import DeviceConnectionError
from network_auditor.config import (
    DEFAULT_CONNECTION_TIMEOUT,
    DEFAULT_CONNECTION_RETRIES,
    DEFAULT_COMMAND_TIMEOUT,
)


class ConnectionManager:
    """
    Manages secure SSH connections to network devices.
    """

    def __init__(
        self,
        connection_timeout: int = DEFAULT_CONNECTION_TIMEOUT,
        connection_retries: int = DEFAULT_CONNECTION_RETRIES,
        command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
    ):
        """
        Initialize the connection manager.

        Args:
            connection_timeout (int, optional): The connection timeout in seconds.
                Defaults to DEFAULT_CONNECTION_TIMEOUT from config.
            connection_retries (int, optional): The number of connection retries.
                Defaults to DEFAULT_CONNECTION_RETRIES from config.
            command_timeout (int, optional): The command timeout in seconds.
                Defaults to DEFAULT_COMMAND_TIMEOUT from config.
        """
        self.connection_timeout = connection_timeout
        self.connection_retries = connection_retries
        self.command_timeout = command_timeout
        self.connections: Dict[str, Any] = {}

    def _get_connection_params(self, device: Device) -> Dict[str, Any]:
        """
        Get the connection parameters for a device.

        Args:
            device (Device): The device to connect to.

        Returns:
            Dict[str, Any]: The connection parameters.
        """
        params = {
            'device_type': device.device_type,
            'host': device.ip_address,
            'username': device.username,
            'password': device.password,
            'port': device.port,
            'timeout': self.connection_timeout,
        }

        if device.enable_password:
            params['secret'] = device.enable_password

        if device.use_keys:
            params['use_keys'] = True
            if device.key_file:
                params['key_file'] = device.key_file

        return params

    def connect(self, device: Device) -> Tuple[bool, Optional[str]]:
        """
        Connect to a device.

        Args:
            device (Device): The device to connect to.

        Returns:
            Tuple[bool, Optional[str]]: A tuple containing a boolean indicating success
                and an optional error message.
        """
        device_id = f"{device.hostname}_{device.ip_address}"
        
        # Check if already connected
        if device_id in self.connections and self.connections[device_id] is not None:
            try:
                # Test if the connection is still active
                self.connections[device_id].find_prompt()
                logger.debug(f"Already connected to {device.hostname} ({device.ip_address})")
                return True, None
            except Exception:
                # Connection is stale, close it and reconnect
                logger.debug(f"Stale connection to {device.hostname} ({device.ip_address}), reconnecting")
                self.disconnect(device)

        connection_params = self._get_connection_params(device)
        
        for attempt in range(1, self.connection_retries + 1):
            try:
                logger.info(f"Connecting to {device.hostname} ({device.ip_address}), attempt {attempt}/{self.connection_retries}")
                connection = ConnectHandler(**connection_params)
                self.connections[device_id] = connection
                logger.info(f"Successfully connected to {device.hostname} ({device.ip_address})")
                return True, None
            except NetMikoTimeoutException:
                error_msg = f"Connection to {device.hostname} ({device.ip_address}) timed out"
                logger.warning(error_msg)
                if attempt < self.connection_retries:
                    logger.info(f"Retrying connection to {device.hostname} ({device.ip_address})")
                    time.sleep(2)  # Wait before retrying
                else:
                    return False, error_msg
            except NetMikoAuthenticationException:
                error_msg = f"Authentication failed for {device.hostname} ({device.ip_address})"
                logger.error(error_msg)
                return False, error_msg
            except SSHException as e:
                error_msg = f"SSH error connecting to {device.hostname} ({device.ip_address}): {str(e)}"
                logger.error(error_msg)
                if attempt < self.connection_retries:
                    logger.info(f"Retrying connection to {device.hostname} ({device.ip_address})")
                    time.sleep(2)  # Wait before retrying
                else:
                    return False, error_msg
            except Exception as e:
                error_msg = f"Error connecting to {device.hostname} ({device.ip_address}): {str(e)}"
                logger.error(error_msg)
                if attempt < self.connection_retries:
                    logger.info(f"Retrying connection to {device.hostname} ({device.ip_address})")
                    time.sleep(2)  # Wait before retrying
                else:
                    return False, error_msg

        # Should not reach here, but just in case
        return False, f"Failed to connect to {device.hostname} ({device.ip_address}) after {self.connection_retries} attempts"

    def disconnect(self, device: Device) -> None:
        """
        Disconnect from a device.

        Args:
            device (Device): The device to disconnect from.
        """
        device_id = f"{device.hostname}_{device.ip_address}"
        if device_id in self.connections and self.connections[device_id] is not None:
            try:
                self.connections[device_id].disconnect()
                logger.info(f"Disconnected from {device.hostname} ({device.ip_address})")
            except Exception as e:
                logger.warning(f"Error disconnecting from {device.hostname} ({device.ip_address}): {str(e)}")
            finally:
                self.connections[device_id] = None

    def disconnect_all(self) -> None:
        """
        Disconnect from all devices.
        """
        for device_id, connection in list(self.connections.items()):
            if connection is not None:
                try:
                    connection.disconnect()
                    logger.info(f"Disconnected from {device_id}")
                except Exception as e:
                    logger.warning(f"Error disconnecting from {device_id}: {str(e)}")
                finally:
                    self.connections[device_id] = None

    def execute_command(self, device: Device, command: str, use_textfsm: bool = False) -> str:
        """
        Execute a command on a device.

        Args:
            device (Device): The device to execute the command on.
            command (str): The command to execute.
            use_textfsm (bool, optional): Whether to use TextFSM for parsing the output.
                Defaults to False.

        Returns:
            str: The command output.

        Raises:
            DeviceConnectionError: If the device is not connected or the command execution fails.
        """
        device_id = f"{device.hostname}_{device.ip_address}"
        if device_id not in self.connections or self.connections[device_id] is None:
            success, error_msg = self.connect(device)
            if not success:
                raise DeviceConnectionError(f"Not connected to {device.hostname} ({device.ip_address}): {error_msg}")

        try:
            logger.info(f"Executing command on {device.hostname} ({device.ip_address}): {command}")
            if use_textfsm:
                output = self.connections[device_id].send_command(
                    command, use_textfsm=True, read_timeout=self.command_timeout
                )
            else:
                output = self.connections[device_id].send_command(
                    command, read_timeout=self.command_timeout
                )
            logger.debug(f"Command executed successfully on {device.hostname} ({device.ip_address})")
            return output
        except Exception as e:
            error_msg = f"Error executing command on {device.hostname} ({device.ip_address}): {str(e)}"
            logger.error(error_msg)
            # Try to reconnect and retry once
            try:
                logger.info(f"Reconnecting to {device.hostname} ({device.ip_address})")
                self.disconnect(device)
                success, _ = self.connect(device)
                if success:
                    logger.info(f"Retrying command on {device.hostname} ({device.ip_address}): {command}")
                    if use_textfsm:
                        output = self.connections[device_id].send_command(
                            command, use_textfsm=True, read_timeout=self.command_timeout
                        )
                    else:
                        output = self.connections[device_id].send_command(
                            command, read_timeout=self.command_timeout
                        )
                    logger.debug(f"Command executed successfully on retry for {device.hostname} ({device.ip_address})")
                    return output
            except Exception as retry_error:
                error_msg = f"Error retrying command on {device.hostname} ({device.ip_address}): {str(retry_error)}"
                logger.error(error_msg)
            
            raise DeviceConnectionError(error_msg)

    def execute_config_commands(self, device: Device, commands: list) -> str:
        """
        Execute configuration commands on a device.

        Args:
            device (Device): The device to execute the commands on.
            commands (list): The commands to execute.

        Returns:
            str: The command output.

        Raises:
            DeviceConnectionError: If the device is not connected or the command execution fails.
        """
        device_id = f"{device.hostname}_{device.ip_address}"
        if device_id not in self.connections or self.connections[device_id] is None:
            success, error_msg = self.connect(device)
            if not success:
                raise DeviceConnectionError(f"Not connected to {device.hostname} ({device.ip_address}): {error_msg}")

        try:
            logger.info(f"Executing config commands on {device.hostname} ({device.ip_address})")
            output = self.connections[device_id].send_config_set(commands)
            logger.debug(f"Config commands executed successfully on {device.hostname} ({device.ip_address})")
            return output
        except Exception as e:
            error_msg = f"Error executing config commands on {device.hostname} ({device.ip_address}): {str(e)}"
            logger.error(error_msg)
            # Try to reconnect and retry once
            try:
                logger.info(f"Reconnecting to {device.hostname} ({device.ip_address})")
                self.disconnect(device)
                success, _ = self.connect(device)
                if success:
                    logger.info(f"Retrying config commands on {device.hostname} ({device.ip_address})")
                    output = self.connections[device_id].send_config_set(commands)
                    logger.debug(f"Config commands executed successfully on retry for {device.hostname} ({device.ip_address})")
                    return output
            except Exception as retry_error:
                error_msg = f"Error retrying config commands on {device.hostname} ({device.ip_address}): {str(retry_error)}"
                logger.error(error_msg)
            
            raise DeviceConnectionError(error_msg)

    def __del__(self):
        """
        Clean up connections when the object is destroyed.
        """
        self.disconnect_all() 