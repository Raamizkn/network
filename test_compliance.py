#!/usr/bin/env python3
"""
Test script to demonstrate how to use the parser and compliance engine together.
"""

import os
import logging
from network_auditor.parser import ConfigParser
from network_auditor.compliance import ComplianceEngine, Policy

# Setup logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    # Sample configuration text (this would normally come from a device)
    sample_config = """
    hostname ROUTER1
    !
    interface GigabitEthernet0/0
     description WAN Interface
     ip address 192.168.1.1 255.255.255.0
     no shutdown
    !
    interface GigabitEthernet0/1
     description LAN Interface
     ip address 10.0.0.1 255.255.255.0
     no shutdown
    !
    ntp server 10.1.1.3
    !
    snmp-server community public RO
    snmp-server location Data Center
    !
    logging host 10.2.2.2
    logging console informational
    logging buffered debugging
    !
    username admin privilege 15 secret 5 $1$abc$XYZ123
    !
    """
    
    # Initialize the parser
    parser = ConfigParser()
    
    # Parse the configuration
    parsed_config = parser.parse_config(sample_config, "cisco_ios")
    logger.info(f"Parsed configuration: {parsed_config.keys()}")
    
    # Initialize the compliance engine with the policies directory
    policies_dir = os.path.join(os.getcwd(), "policies")
    engine = ComplianceEngine(policies_dir)
    
    # Audit the configuration
    audit_results = engine.audit_config(parsed_config)
    
    # Print the audit results
    print("\n=== Audit Results ===")
    print(f"Total Policies: {audit_results['summary']['total_policies']}")
    print(f"Compliant: {audit_results['summary']['compliant']}")
    print(f"Non-Compliant: {audit_results['summary']['non_compliant']}")
    print(f"Not Applicable: {audit_results['summary']['not_applicable']}")
    
    # Print details of non-compliant policies
    print("\n=== Non-Compliant Policies ===")
    for policy in audit_results['policies']:
        if policy['status'] == 'non_compliant':
            print(f"\nPolicy: {policy['policy_name']} (Severity: {policy['severity']})")
            print(f"Description: {policy['description']}")
            print("Issues:")
            for detail in policy['details']:
                for issue in detail['details']:
                    print(f"  - {issue}")
    
    # Export the results to a file
    engine.export_results(audit_results, "audit_results.json")
    logger.info("Exported audit results to audit_results.json")

if __name__ == "__main__":
    main() 