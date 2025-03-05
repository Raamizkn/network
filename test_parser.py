#!/usr/bin/env python3
"""
Test script to verify that the ConfigParser can be imported correctly.
"""

try:
    from network_auditor.parser import ConfigParser
    print("Successfully imported ConfigParser")
    
    # Create an instance to verify it works
    parser = ConfigParser()
    print(f"Created parser instance: {parser}")
    
except ImportError as e:
    print(f"Import error: {e}")
except Exception as e:
    print(f"Error: {e}") 