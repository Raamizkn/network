"""
Compliance Engine for the Network Configuration Compliance Auditor.

This module provides the core functionality for auditing network device
configurations against defined compliance policies.
"""

import os
import re
import logging
import yaml
import json
from typing import Dict, List, Any, Optional, Union, Callable
from pathlib import Path

# Setup logging
logger = logging.getLogger(__name__)

class Policy:
    """
    Represents a compliance policy rule.
    
    A policy consists of a name, description, severity, and a set of
    conditions that must be met for a configuration to be compliant.
    """
    
    def __init__(self, name: str, description: str, severity: str = 'medium',
                 conditions: Optional[Dict[str, Any]] = None):
        """
        Initialize a Policy.
        
        Args:
            name: Name of the policy.
            description: Description of what the policy checks.
            severity: Severity level ('low', 'medium', 'high', 'critical').
            conditions: Dictionary of conditions that must be met.
        """
        self.name = name
        self.description = description
        self.severity = severity.lower()
        self.conditions = conditions or {}
        
        # Validate severity
        valid_severities = ['low', 'medium', 'high', 'critical']
        if self.severity not in valid_severities:
            logger.warning(f"Invalid severity '{severity}' for policy '{name}'. Using 'medium' instead.")
            self.severity = 'medium'
    
    @classmethod
    def from_dict(cls, policy_dict: Dict[str, Any]) -> 'Policy':
        """
        Create a Policy from a dictionary.
        
        Args:
            policy_dict: Dictionary containing policy attributes.
            
        Returns:
            Policy object.
        """
        return cls(
            name=policy_dict.get('name', 'Unnamed Policy'),
            description=policy_dict.get('description', ''),
            severity=policy_dict.get('severity', 'medium'),
            conditions=policy_dict.get('conditions', {})
        )
    
    @classmethod
    def from_yaml(cls, yaml_file: str) -> List['Policy']:
        """
        Load policies from a YAML file.
        
        Args:
            yaml_file: Path to the YAML file.
            
        Returns:
            List of Policy objects.
        """
        try:
            with open(yaml_file, 'r') as f:
                policies_data = yaml.safe_load(f)
            
            policies = []
            for policy_data in policies_data.get('policies', []):
                policies.append(cls.from_dict(policy_data))
            
            return policies
        except Exception as e:
            logger.error(f"Error loading policies from {yaml_file}: {str(e)}")
            return []
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the Policy to a dictionary.
        
        Returns:
            Dictionary representation of the Policy.
        """
        return {
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'conditions': self.conditions
        }
    
    def __str__(self) -> str:
        """String representation of the Policy."""
        return f"Policy(name='{self.name}', severity='{self.severity}')"


class ComplianceEngine:
    """
    Engine for auditing network device configurations against compliance policies.
    """
    
    def __init__(self, policies_dir: Optional[str] = None):
        """
        Initialize the ComplianceEngine.
        
        Args:
            policies_dir: Directory containing policy files.
        """
        self.policies_dir = policies_dir
        self.policies: List[Policy] = []
        
        # Load policies if directory is provided
        if self.policies_dir:
            self.load_policies(self.policies_dir)
    
    def load_policies(self, policies_dir: str) -> None:
        """
        Load policies from a directory.
        
        Args:
            policies_dir: Directory containing policy files.
        """
        if not os.path.exists(policies_dir):
            logger.error(f"Policies directory does not exist: {policies_dir}")
            return
        
        logger.info(f"Loading policies from {policies_dir}")
        
        # Clear existing policies
        self.policies = []
        
        # Load policies from YAML files
        for file_name in os.listdir(policies_dir):
            if file_name.endswith('.yaml') or file_name.endswith('.yml'):
                file_path = os.path.join(policies_dir, file_name)
                policies = Policy.from_yaml(file_path)
                self.policies.extend(policies)
                logger.info(f"Loaded {len(policies)} policies from {file_name}")
        
        logger.info(f"Loaded a total of {len(self.policies)} policies")
    
    def add_policy(self, policy: Policy) -> None:
        """
        Add a policy to the engine.
        
        Args:
            policy: Policy to add.
        """
        self.policies.append(policy)
        logger.info(f"Added policy: {policy.name}")
    
    def audit_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Audit a configuration against all loaded policies.
        
        Args:
            config: Parsed configuration data.
            
        Returns:
            Audit results containing compliance status for each policy.
        """
        logger.info(f"Auditing configuration against {len(self.policies)} policies")
        
        results = {
            'device_info': {
                'device_type': config.get('device_type', 'unknown')
            },
            'policies': [],
            'summary': {
                'total_policies': len(self.policies),
                'compliant': 0,
                'non_compliant': 0,
                'not_applicable': 0,
                'by_severity': {
                    'critical': {'total': 0, 'non_compliant': 0},
                    'high': {'total': 0, 'non_compliant': 0},
                    'medium': {'total': 0, 'non_compliant': 0},
                    'low': {'total': 0, 'non_compliant': 0}
                }
            }
        }
        
        # Audit each policy
        for policy in self.policies:
            policy_result = self._check_policy(policy, config)
            results['policies'].append(policy_result)
            
            # Update summary statistics
            severity = policy.severity
            results['summary']['by_severity'][severity]['total'] += 1
            
            if policy_result['status'] == 'compliant':
                results['summary']['compliant'] += 1
            elif policy_result['status'] == 'non_compliant':
                results['summary']['non_compliant'] += 1
                results['summary']['by_severity'][severity]['non_compliant'] += 1
            else:  # not_applicable
                results['summary']['not_applicable'] += 1
        
        logger.info(f"Audit complete: {results['summary']['compliant']} compliant, "
                   f"{results['summary']['non_compliant']} non-compliant, "
                   f"{results['summary']['not_applicable']} not applicable")
        
        return results
    
    def _check_policy(self, policy: Policy, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if a configuration complies with a specific policy.
        
        Args:
            policy: Policy to check.
            config: Parsed configuration data.
            
        Returns:
            Dictionary containing the policy check results.
        """
        result = {
            'policy_name': policy.name,
            'description': policy.description,
            'severity': policy.severity,
            'status': 'not_applicable',
            'details': []
        }
        
        # Skip if no conditions are defined
        if not policy.conditions:
            logger.warning(f"Policy '{policy.name}' has no conditions defined")
            return result
        
        # Check if the policy applies to this device type
        applicable_device_types = policy.conditions.get('device_types', [])
        if applicable_device_types and config.get('device_type') not in applicable_device_types:
            logger.debug(f"Policy '{policy.name}' does not apply to device type '{config.get('device_type')}'")
            return result
        
        # Policy is applicable, now check compliance
        result['status'] = 'compliant'
        
        # Check each condition type
        for condition_type, condition_value in policy.conditions.items():
            if condition_type == 'device_types':
                continue  # Already checked
            
            checker_method = getattr(self, f"_check_{condition_type}", None)
            if checker_method:
                condition_result = checker_method(condition_value, config)
                if not condition_result['compliant']:
                    result['status'] = 'non_compliant'
                    result['details'].append(condition_result)
            else:
                logger.warning(f"Unknown condition type '{condition_type}' in policy '{policy.name}'")
        
        return result
    
    def _check_interfaces(self, condition: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Check interface-related conditions."""
        result = {
            'condition_type': 'interfaces',
            'compliant': True,
            'details': []
        }
        
        interfaces = config.get('interfaces', [])
        
        # Check required interfaces
        required_interfaces = condition.get('required', [])
        for req_iface in required_interfaces:
            found = False
            for iface in interfaces:
                if iface.get('interface', '').lower() == req_iface.lower():
                    found = True
                    break
            
            if not found:
                result['compliant'] = False
                result['details'].append(f"Required interface '{req_iface}' not found")
        
        # Check interface properties
        interface_properties = condition.get('properties', {})
        for iface in interfaces:
            iface_name = iface.get('interface', '')
            
            # Skip interfaces not specified in the condition
            if interface_properties and iface_name.lower() not in [i.lower() for i in interface_properties.keys()]:
                continue
            
            # Check properties for this interface
            props = interface_properties.get(iface_name, {})
            for prop_name, expected_value in props.items():
                actual_value = iface.get(prop_name)
                
                if actual_value != expected_value:
                    result['compliant'] = False
                    result['details'].append(
                        f"Interface '{iface_name}' property '{prop_name}' has value '{actual_value}' "
                        f"but expected '{expected_value}'"
                    )
        
        return result
    
    def _check_acls(self, condition: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Check ACL-related conditions."""
        result = {
            'condition_type': 'acls',
            'compliant': True,
            'details': []
        }
        
        acls = config.get('acls', [])
        
        # Check required ACLs
        required_acls = condition.get('required', [])
        for req_acl in required_acls:
            found = False
            for acl in acls:
                if acl.get('name', '').lower() == req_acl.lower():
                    found = True
                    break
            
            if not found:
                result['compliant'] = False
                result['details'].append(f"Required ACL '{req_acl}' not found")
        
        # Check forbidden ACL entries
        forbidden_entries = condition.get('forbidden_entries', [])
        for acl in acls:
            acl_name = acl.get('name', '')
            entries = acl.get('entries', [])
            
            for entry in entries:
                entry_text = entry.get('text', '')
                
                for forbidden in forbidden_entries:
                    if re.search(forbidden, entry_text, re.IGNORECASE):
                        result['compliant'] = False
                        result['details'].append(
                            f"ACL '{acl_name}' contains forbidden entry: '{entry_text}'"
                        )
        
        return result
    
    def _check_ntp(self, condition: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Check NTP-related conditions."""
        result = {
            'condition_type': 'ntp',
            'compliant': True,
            'details': []
        }
        
        ntp = config.get('ntp', {})
        
        # Check required NTP servers
        required_servers = condition.get('required_servers', [])
        actual_servers = ntp.get('servers', [])
        
        for req_server in required_servers:
            if req_server not in actual_servers:
                result['compliant'] = False
                result['details'].append(f"Required NTP server '{req_server}' not configured")
        
        # Check if authentication is required
        if condition.get('require_authentication', False) and not ntp.get('authentication', False):
            result['compliant'] = False
            result['details'].append("NTP authentication is required but not enabled")
        
        return result
    
    def _check_snmp(self, condition: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Check SNMP-related conditions."""
        result = {
            'condition_type': 'snmp',
            'compliant': True,
            'details': []
        }
        
        snmp = config.get('snmp', {})
        
        # Check community strings
        forbidden_communities = condition.get('forbidden_communities', [])
        communities = snmp.get('communities', [])
        
        for community in communities:
            community_string = community.get('string', '')
            
            for forbidden in forbidden_communities:
                if re.search(forbidden, community_string, re.IGNORECASE):
                    result['compliant'] = False
                    result['details'].append(f"Forbidden SNMP community string found: '{community_string}'")
        
        # Check if location is required
        if condition.get('require_location', False) and not snmp.get('location'):
            result['compliant'] = False
            result['details'].append("SNMP location is required but not configured")
        
        # Check if contact is required
        if condition.get('require_contact', False) and not snmp.get('contact'):
            result['compliant'] = False
            result['details'].append("SNMP contact is required but not configured")
        
        return result
    
    def _check_logging(self, condition: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Check logging-related conditions."""
        result = {
            'condition_type': 'logging',
            'compliant': True,
            'details': []
        }
        
        logging_config = config.get('logging', {})
        
        # Check required logging servers
        required_servers = condition.get('required_servers', [])
        actual_servers = logging_config.get('servers', [])
        
        for req_server in required_servers:
            if req_server not in actual_servers:
                result['compliant'] = False
                result['details'].append(f"Required logging server '{req_server}' not configured")
        
        # Check minimum logging levels
        min_levels = condition.get('minimum_levels', {})
        
        for level_type, min_level in min_levels.items():
            actual_level = logging_config.get(f"{level_type}_level")
            
            if not actual_level:
                result['compliant'] = False
                result['details'].append(f"Logging level for '{level_type}' not configured")
            elif not self._is_log_level_sufficient(actual_level, min_level):
                result['compliant'] = False
                result['details'].append(
                    f"Logging level for '{level_type}' is '{actual_level}' but minimum required is '{min_level}'"
                )
        
        return result
    
    def _is_log_level_sufficient(self, actual: str, minimum: str) -> bool:
        """
        Check if an actual logging level meets or exceeds a minimum level.
        
        Args:
            actual: Actual logging level.
            minimum: Minimum required logging level.
            
        Returns:
            True if the actual level meets or exceeds the minimum, False otherwise.
        """
        # Define logging levels in order of increasing severity
        levels = ['debugging', 'informational', 'notifications', 'warnings', 'errors', 'critical', 'alerts', 'emergencies']
        
        try:
            actual_idx = levels.index(actual.lower())
            min_idx = levels.index(minimum.lower())
            
            # Higher index means more severe (and thus sufficient)
            return actual_idx >= min_idx
        except ValueError:
            # If level not found, assume not sufficient
            return False
    
    def _check_aaa(self, condition: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Check AAA-related conditions."""
        result = {
            'condition_type': 'aaa',
            'compliant': True,
            'details': []
        }
        
        aaa = config.get('aaa', {})
        
        # Check if TACACS+ is required
        if condition.get('require_tacacs', False) and not aaa.get('servers', {}).get('tacacs'):
            result['compliant'] = False
            result['details'].append("TACACS+ authentication is required but not configured")
        
        # Check authentication methods
        required_auth_methods = condition.get('required_auth_methods', [])
        
        if required_auth_methods:
            auth_login_lists = aaa.get('authentication', {}).get('login', [])
            
            # Check if any authentication list contains all required methods
            found_all_methods = False
            
            for auth_list in auth_login_lists:
                methods = auth_list.get('methods', [])
                
                # Check if all required methods are in this list
                if all(method in methods for method in required_auth_methods):
                    found_all_methods = True
                    break
            
            if not found_all_methods:
                result['compliant'] = False
                result['details'].append(
                    f"Required authentication methods not found: {', '.join(required_auth_methods)}"
                )
        
        return result
    
    def _check_users(self, condition: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Check user-related conditions."""
        result = {
            'condition_type': 'users',
            'compliant': True,
            'details': []
        }
        
        users = config.get('users', [])
        
        # Check for forbidden usernames
        forbidden_usernames = condition.get('forbidden', [])
        
        for user in users:
            username = user.get('username', '')
            
            for forbidden in forbidden_usernames:
                if re.search(forbidden, username, re.IGNORECASE):
                    result['compliant'] = False
                    result['details'].append(f"Forbidden username found: '{username}'")
        
        # Check for required privilege levels
        min_privilege = condition.get('minimum_privilege')
        
        if min_privilege is not None:
            for user in users:
                username = user.get('username', '')
                privilege = user.get('privilege')
                
                if privilege and int(privilege) < int(min_privilege):
                    result['compliant'] = False
                    result['details'].append(
                        f"User '{username}' has privilege level {privilege} which is below the minimum {min_privilege}"
                    )
        
        return result
    
    def export_results(self, results: Dict[str, Any], output_file: str, format: str = 'json') -> bool:
        """
        Export audit results to a file.
        
        Args:
            results: Audit results.
            output_file: Path to the output file.
            format: Output format ('json' or 'yaml').
            
        Returns:
            True if export was successful, False otherwise.
        """
        try:
            with open(output_file, 'w') as f:
                if format.lower() == 'json':
                    json.dump(results, f, indent=2)
                elif format.lower() == 'yaml':
                    yaml.dump(results, f, default_flow_style=False)
                else:
                    logger.error(f"Unsupported export format: {format}")
                    return False
            
            logger.info(f"Audit results exported to {output_file} in {format} format")
            return True
        except Exception as e:
            logger.error(f"Error exporting audit results: {str(e)}")
            return False 