# Network Configuration Compliance Auditor

A comprehensive tool for auditing network device configurations against compliance policies.

## Features

- Connect to network devices securely via SSH
- Retrieve and parse device configurations
- Audit configurations against defined compliance policies
- Generate detailed compliance reports
- Command-line interface for quick audits
- Web dashboard for detailed reports and historical tracking (optional)

## System Architecture

The system consists of the following core components:

1. **Device Inventory Manager**: Maintains a database of network devices
2. **Connection Manager**: Handles secure SSH connections to devices
3. **Configuration Retrieval Module**: Executes commands to retrieve device configurations
4. **Configuration Parser & Normalizer**: Processes raw configurations into structured data
5. **Compliance Policy Engine**: Compares configurations against predefined policies
6. **Reporting & Alerting Module**: Generates reports and sends alerts for non-compliance
7. **User Interface**: Provides CLI and/or web dashboard
8. **Logging & Error Handling**: Maintains detailed logs of all operations

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/network-auditor.git
   cd network-auditor
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface

```
python -m network_auditor.cli --device-list devices.csv --policies policies/
```

### Web Interface (Optional)

```
python -m network_auditor.web
```
Then navigate to http://localhost:5000 in your web browser.

## Configuration

1. Define your devices in a CSV or JSON file (see `examples/devices.csv`)
2. Create compliance policies in YAML format (see `examples/policies/`)

## Security Considerations

- Credentials are stored securely using environment variables or encrypted files
- SSH connections use key-based authentication when possible
- Logs and reports are protected to prevent exposure of sensitive configuration details

## License

Proprietary. All rights reserved. This software may not be used, copied, modified, or distributed without explicit written permission from the copyright holder.

## Contributing

Contributions are subject to the terms of the proprietary license agreement. Please contact the copyright holder before submitting any contributions. 