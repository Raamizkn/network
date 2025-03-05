"""
Custom exceptions for the Network Configuration Compliance Auditor.
"""


class NetworkAuditorError(Exception):
    """Base exception for all Network Auditor errors."""
    pass


class DeviceConnectionError(NetworkAuditorError):
    """Exception raised when a connection to a device fails."""
    pass


class CommandExecutionError(NetworkAuditorError):
    """Exception raised when a command execution fails."""
    pass


class ConfigurationParsingError(NetworkAuditorError):
    """Exception raised when parsing a configuration fails."""
    pass


class ComplianceCheckError(NetworkAuditorError):
    """Exception raised when a compliance check fails."""
    pass


class ReportGenerationError(NetworkAuditorError):
    """Exception raised when report generation fails."""
    pass


class InventoryError(NetworkAuditorError):
    """Exception raised when there is an error with the device inventory."""
    pass


class PolicyError(NetworkAuditorError):
    """Exception raised when there is an error with a compliance policy."""
    pass 