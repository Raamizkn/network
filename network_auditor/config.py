"""
Configuration settings for the Network Configuration Compliance Auditor.
"""

import os
import logging
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Directory for storing logs
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

# Directory for storing reports
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

# Directory for storing policies
POLICIES_DIR = os.path.join(BASE_DIR, 'policies')
os.makedirs(POLICIES_DIR, exist_ok=True)

# Directory for storing device inventory
INVENTORY_DIR = os.path.join(BASE_DIR, 'inventory')
os.makedirs(INVENTORY_DIR, exist_ok=True)

# Default device inventory file
DEFAULT_INVENTORY_FILE = os.path.join(INVENTORY_DIR, 'devices.csv')

# Default command timeout (in seconds)
DEFAULT_COMMAND_TIMEOUT = 60

# Default connection timeout (in seconds)
DEFAULT_CONNECTION_TIMEOUT = 30

# Default number of connection retries
DEFAULT_CONNECTION_RETRIES = 3

# Default logging level
DEFAULT_LOG_LEVEL = logging.INFO

# Default logging format
DEFAULT_LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Default logging file
DEFAULT_LOG_FILE = os.path.join(LOG_DIR, 'network_auditor.log')

# Web server settings (for optional web interface)
WEB_HOST = '0.0.0.0'
WEB_PORT = 5000
WEB_DEBUG = False

# Security settings
# Set to True to use environment variables for credentials
USE_ENV_CREDENTIALS = True
# Environment variable names for credentials
ENV_USERNAME = 'NETWORK_AUDITOR_USERNAME'
ENV_PASSWORD = 'NETWORK_AUDITOR_PASSWORD'
ENV_SECRET_KEY = 'NETWORK_AUDITOR_SECRET_KEY'

# Default secret key for web application (change this in production!)
DEFAULT_SECRET_KEY = 'change-this-in-production' 