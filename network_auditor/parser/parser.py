"""
Configuration Parser & Normalizer for the Network Configuration Compliance Auditor.

This module provides functionality to parse raw network device configurations
and convert them into structured data for compliance auditing.
"""

import re
import logging
import textfsm
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import yaml
import json
import os

# Setup logging
logger = logging.getLogger(__name__)

class ConfigParser:
    """
    Parser for network device configurations.
    
    This class handles parsing raw configuration text from various network devices
    and normalizes the data into a structured format for compliance auditing.
    """
    
    def __init__(self, templates_dir: Optional[str] = None):
        """
        Initialize the ConfigParser.
        
        Args:
            templates_dir: Directory containing TextFSM templates for parsing.
                           If None, will use default templates from ntc-templates.
        """
        self.templates_dir = templates_dir
        if not self.templates_dir:
            # Use ntc-templates if no custom templates directory is provided
            try:
                import ntc_templates
                self.templates_dir = os.path.join(os.path.dirname(ntc_templates.__file__), 'templates')
            except ImportError:
                logger.warning("ntc_templates not found. Using built-in templates.")
                self.templates_dir = os.path.join(Path(__file__).parent, 'templates')
        
        logger.info(f"Using templates directory: {self.templates_dir}")
    
    def parse_config(self, config_text: str, device_type: str) -> Dict[str, Any]:
        """
        Parse raw configuration text into structured data.
        
        Args:
            config_text: Raw configuration text from the device.
            device_type: Type of device (e.g., 'cisco_ios', 'juniper_junos').
            
        Returns:
            Dictionary containing structured configuration data.
        """
        logger.info(f"Parsing configuration for device type: {device_type}")
        
        # Initialize the result dictionary
        parsed_data = {
            'device_type': device_type,
            'interfaces': [],
            'routing': {},
            'acls': [],
            'vlans': [],
            'users': [],
            'ntp': {},
            'snmp': {},
            'logging': {},
            'aaa': {},
            'raw_config': config_text,
        }
        
        # Parse different sections of the configuration
        try:
            parsed_data['interfaces'] = self._parse_interfaces(config_text, device_type)
            parsed_data['routing'] = self._parse_routing(config_text, device_type)
            parsed_data['acls'] = self._parse_acls(config_text, device_type)
            parsed_data['vlans'] = self._parse_vlans(config_text, device_type)
            parsed_data['users'] = self._parse_users(config_text, device_type)
            parsed_data['ntp'] = self._parse_ntp(config_text, device_type)
            parsed_data['snmp'] = self._parse_snmp(config_text, device_type)
            parsed_data['logging'] = self._parse_logging(config_text, device_type)
            parsed_data['aaa'] = self._parse_aaa(config_text, device_type)
        except Exception as e:
            logger.error(f"Error parsing configuration: {str(e)}")
            # Continue with partial data rather than failing completely
        
        return parsed_data
    
    def _parse_with_textfsm(self, config_text: str, template_file: str) -> List[Dict[str, str]]:
        """
        Parse configuration using a TextFSM template.
        
        Args:
            config_text: Raw configuration text.
            template_file: Name of the TextFSM template file.
            
        Returns:
            List of dictionaries containing parsed data.
        """
        template_path = os.path.join(self.templates_dir, template_file)
        
        if not os.path.exists(template_path):
            logger.warning(f"Template file not found: {template_path}")
            return []
        
        try:
            with open(template_path, 'r') as template:
                fsm = textfsm.TextFSM(template)
                result = fsm.ParseText(config_text)
                
                # Convert to list of dictionaries
                parsed_data = []
                for item in result:
                    parsed_item = {}
                    for i, header in enumerate(fsm.header):
                        parsed_item[header.lower()] = item[i]
                    parsed_data.append(parsed_item)
                
                return parsed_data
        except Exception as e:
            logger.error(f"Error parsing with TextFSM: {str(e)}")
            return []
    
    def _parse_interfaces(self, config_text: str, device_type: str) -> List[Dict[str, Any]]:
        """Parse interface configurations."""
        if device_type.startswith('cisco_ios'):
            return self._parse_with_textfsm(config_text, 'cisco_ios_show_interfaces.textfsm')
        elif device_type.startswith('juniper'):
            return self._parse_with_textfsm(config_text, 'juniper_junos_show_interfaces.textfsm')
        # Add more device types as needed
        return []
    
    def _parse_routing(self, config_text: str, device_type: str) -> Dict[str, Any]:
        """Parse routing configurations."""
        routing_data = {
            'ospf': [],
            'bgp': [],
            'static_routes': [],
            'eigrp': []
        }
        
        if device_type.startswith('cisco_ios'):
            routing_data['ospf'] = self._parse_with_textfsm(config_text, 'cisco_ios_show_ip_ospf.textfsm')
            routing_data['bgp'] = self._parse_with_textfsm(config_text, 'cisco_ios_show_ip_bgp_summary.textfsm')
            routing_data['static_routes'] = self._parse_with_textfsm(config_text, 'cisco_ios_show_ip_route.textfsm')
        # Add more device types as needed
        
        return routing_data
    
    def _parse_acls(self, config_text: str, device_type: str) -> List[Dict[str, Any]]:
        """Parse ACL configurations."""
        if device_type.startswith('cisco_ios'):
            return self._parse_with_textfsm(config_text, 'cisco_ios_show_access-lists.textfsm')
        # Add more device types as needed
        return []
    
    def _parse_vlans(self, config_text: str, device_type: str) -> List[Dict[str, Any]]:
        """Parse VLAN configurations."""
        if device_type.startswith('cisco_ios'):
            return self._parse_with_textfsm(config_text, 'cisco_ios_show_vlan.textfsm')
        # Add more device types as needed
        return []
    
    def _parse_users(self, config_text: str, device_type: str) -> List[Dict[str, Any]]:
        """Parse user configurations."""
        # This might require custom regex parsing as TextFSM templates might not exist for all user configs
        users = []
        
        if device_type.startswith('cisco_ios'):
            # Simple regex for Cisco IOS user configuration
            user_regex = r'username\s+(\S+)\s+privilege\s+(\d+)\s+(?:secret|password)\s+(\d+)\s+(\S+)'
            matches = re.finditer(user_regex, config_text)
            
            for match in matches:
                users.append({
                    'username': match.group(1),
                    'privilege': match.group(2),
                    'encryption_type': match.group(3),
                    'password': match.group(4)  # Note: This will be encrypted
                })
        
        return users
    
    def _parse_ntp(self, config_text: str, device_type: str) -> Dict[str, Any]:
        """Parse NTP configurations."""
        ntp_data = {
            'servers': [],
            'source': None,
            'authentication': False
        }
        
        if device_type.startswith('cisco_ios'):
            # Parse NTP servers
            ntp_server_regex = r'ntp server\s+(\S+)'
            ntp_data['servers'] = re.findall(ntp_server_regex, config_text)
            
            # Parse NTP source
            ntp_source_match = re.search(r'ntp source\s+(\S+)', config_text)
            if ntp_source_match:
                ntp_data['source'] = ntp_source_match.group(1)
            
            # Check for NTP authentication
            ntp_data['authentication'] = 'ntp authenticate' in config_text
        
        return ntp_data
    
    def _parse_snmp(self, config_text: str, device_type: str) -> Dict[str, Any]:
        """Parse SNMP configurations."""
        snmp_data = {
            'communities': [],
            'location': None,
            'contact': None,
            'traps': []
        }
        
        if device_type.startswith('cisco_ios'):
            # Parse SNMP communities
            community_regex = r'snmp-server community\s+(\S+)\s+(\S+)'
            for match in re.finditer(community_regex, config_text):
                snmp_data['communities'].append({
                    'string': match.group(1),
                    'access': match.group(2)
                })
            
            # Parse SNMP location
            location_match = re.search(r'snmp-server location\s+(.+?)$', config_text, re.MULTILINE)
            if location_match:
                snmp_data['location'] = location_match.group(1).strip()
            
            # Parse SNMP contact
            contact_match = re.search(r'snmp-server contact\s+(.+?)$', config_text, re.MULTILINE)
            if contact_match:
                snmp_data['contact'] = contact_match.group(1).strip()
            
            # Parse SNMP traps
            trap_regex = r'snmp-server enable traps\s+(\S+)'
            snmp_data['traps'] = re.findall(trap_regex, config_text)
        
        return snmp_data
    
    def _parse_logging(self, config_text: str, device_type: str) -> Dict[str, Any]:
        """Parse logging configurations."""
        logging_data = {
            'servers': [],
            'console_level': None,
            'buffer_level': None,
            'trap_level': None
        }
        
        if device_type.startswith('cisco_ios'):
            # Parse logging servers
            server_regex = r'logging\s+host\s+(\S+)'
            logging_data['servers'] = re.findall(server_regex, config_text)
            
            # Parse console logging level
            console_match = re.search(r'logging console\s+(\S+)', config_text)
            if console_match:
                logging_data['console_level'] = console_match.group(1)
            
            # Parse buffer logging level
            buffer_match = re.search(r'logging buffered\s+(?:\d+\s+)?(\S+)', config_text)
            if buffer_match:
                logging_data['buffer_level'] = buffer_match.group(1)
            
            # Parse trap logging level
            trap_match = re.search(r'logging trap\s+(\S+)', config_text)
            if trap_match:
                logging_data['trap_level'] = trap_match.group(1)
        
        return logging_data
    
    def _parse_aaa(self, config_text: str, device_type: str) -> Dict[str, Any]:
        """Parse AAA configurations."""
        aaa_data = {
            'authentication': {
                'login': [],
                'enable': []
            },
            'authorization': {
                'commands': [],
                'exec': []
            },
            'accounting': {
                'commands': [],
                'exec': []
            },
            'servers': {
                'tacacs': [],
                'radius': []
            }
        }
        
        if device_type.startswith('cisco_ios'):
            # Parse AAA authentication login
            auth_login_regex = r'aaa authentication login\s+(\S+)\s+(.+?)$'
            for match in re.finditer(auth_login_regex, config_text, re.MULTILINE):
                aaa_data['authentication']['login'].append({
                    'list_name': match.group(1),
                    'methods': match.group(2).strip().split()
                })
            
            # Parse TACACS servers
            tacacs_regex = r'tacacs-server host\s+(\S+)'
            aaa_data['servers']['tacacs'] = re.findall(tacacs_regex, config_text)
            
            # Parse RADIUS servers
            radius_regex = r'radius-server host\s+(\S+)'
            aaa_data['servers']['radius'] = re.findall(radius_regex, config_text)
        
        return aaa_data
    
    def normalize_config(self, parsed_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize parsed configuration data to a standard format.
        
        This ensures that configurations from different device types
        are represented in a consistent way for compliance checking.
        
        Args:
            parsed_config: Parsed configuration data.
            
        Returns:
            Normalized configuration data.
        """
        # For now, we'll just return the parsed config as-is
        # In a real implementation, you would normalize data from different
        # device types to a common format
        return parsed_config
    
    def export_config(self, parsed_config: Dict[str, Any], 
                     output_file: str, format: str = 'json') -> bool:
        """
        Export parsed configuration to a file.
        
        Args:
            parsed_config: Parsed configuration data.
            output_file: Path to the output file.
            format: Output format ('json' or 'yaml').
            
        Returns:
            True if export was successful, False otherwise.
        """
        try:
            with open(output_file, 'w') as f:
                if format.lower() == 'json':
                    json.dump(parsed_config, f, indent=2)
                elif format.lower() == 'yaml':
                    yaml.dump(parsed_config, f, default_flow_style=False)
                else:
                    logger.error(f"Unsupported export format: {format}")
                    return False
            
            logger.info(f"Configuration exported to {output_file} in {format} format")
            return True
        except Exception as e:
            logger.error(f"Error exporting configuration: {str(e)}")
            return False 