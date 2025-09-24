# Interfaces Module

## Overview

The `interfaces.py` module contains the Interface class for detecting and managing network interfaces across different operating systems (Linux, macOS, and Windows). This module provides functionality to identify network interfaces, retrieve their properties (IP addresses, MAC addresses, etc.), and filter them based on various criteria.

## Classes

### Interface

A class for detecting and managing network interfaces across different operating systems. This class provides methods to identify network interfaces on Linux, macOS, and Windows systems, retrieve their properties, and filter them based on various criteria.

#### Attributes

- `os_type (str)`: The lowercase name of the current operating system.
- `interfaces (dict)`: A dictionary of detected network interfaces and their properties.
- `VALID_IFACE_CHARS (set)`: A set of valid characters for interface names.

#### Methods

##### `__init__(self, log_dir: Optional[str] = None) -> None`

Initialize the Interface class.

Detects the current operating system and populates the interfaces dictionary with information about all available network interfaces.

**Parameters:**
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `_get_interfaces(self) -> Dict[str, dict]`

Get network interfaces based on the current operating system.

This method acts as a router to call the appropriate OS-specific method for detecting network interfaces.

**Returns:**
- `Dict[str, dict]`: A dictionary where keys are interface names and values are dictionaries containing interface properties.

**Raises:**
- `NotImplementedError`: If the current operating system is not supported.

##### `_get_linux_interfaces(self) -> Dict[str, dict]`

Get network interfaces on Linux systems.

Uses the netifaces library for basic interface detection and the 'ip' command for additional Linux-specific information.

**Returns:**
- `Dict[str, dict]`: A dictionary where keys are interface names and values are dictionaries containing interface properties including:
  - name: The interface name
  - mac: The MAC address
  - ipv4: The IPv4 address
  - ipv6: The IPv6 address (if available)
  - type: The detected interface type
  - state: The interface state (UP/DOWN) if available

##### `_get_macos_interfaces(self) -> Dict[str, dict]`

Get network interfaces on macOS systems.

Uses the netifaces library for basic interface detection and the 'ifconfig' command for additional macOS-specific information.

**Returns:**
- `Dict[str, dict]`: A dictionary where keys are interface names and values are dictionaries containing interface properties including:
  - name: The interface name
  - mac: The MAC address
  - ipv4: The IPv4 address
  - ipv6: The IPv6 address (if available)
  - type: The detected interface type
  - state: The interface state (UP/DOWN/UNKNOWN)

##### `_get_windows_interfaces(self) -> Dict[str, dict]`

Get network interfaces on Windows systems.

Uses the 'ipconfig /all' command to retrieve information about network interfaces on Windows systems.

**Returns:**
- `Dict[str, dict]`: A dictionary where keys are interface names and values are dictionaries containing interface properties including:
  - name: The interface name
  - mac: The MAC address (Physical Address)
  - ipv4: The IPv4 address (if available)
  - ipv6: The IPv6 address (if available)
  - type: The detected interface type
  - state: The interface state (typically 'UNKNOWN' as Windows doesn't provide this information in the same way as Linux/macOS)

##### `_is_valid_interface_name(self, iface: str) -> bool`

Validate that an interface name contains only allowed characters.

This is a security measure to prevent command injection when using interface names in subprocess calls.

**Parameters:**
- `iface (str)`: The interface name to validate

**Returns:**
- `bool`: True if the interface name is valid, False otherwise

##### `_detect_interface_type(self, iface: str) -> str`

Detect the type of network interface based on its name.

Uses common naming conventions to determine the interface type.

**Parameters:**
- `iface (str)`: The name of the network interface.

**Returns:**
- `str`: The detected interface type, one of:
  - 'loopback': For loopback interfaces
  - 'ethernet': For Ethernet interfaces
  - 'wireless': For WiFi interfaces
  - 'docker': For Docker network interfaces
  - 'virtual': For virtual interfaces
  - 'vpn': For VPN tunnel interfaces
  - 'unknown': If the type cannot be determined

##### `show_available_interfaces(self) -> None`

Display all available network interfaces with their details.

Prints a formatted list of all detected network interfaces and their properties to the console, including name, MAC address, IP addresses, interface type, and state.

**Returns:**
- `None`

##### `get_interface_by_type(self, type_name: str) -> List[str]`

Get all interfaces of a specific type.

**Parameters:**
- `type_name (str)`: The type of interface to filter by. Valid values include: 'loopback', 'ethernet', 'wireless', 'docker', 'virtual', 'vpn', 'unknown'.

**Returns:**
- `List[str]`: A list of interface names that match the specified type. Returns an empty list if no interfaces of the specified type are found.

##### `get_active_interfaces(self) -> List[str]`

Get all active network interfaces.

Returns a list of interface names that have their state set to 'UP'. Note that this may not be accurate on all systems, particularly Windows, where the state information might not be available.

**Returns:**
- `List[str]`: A list of active interface names. Returns an empty list if no active interfaces are found.

##### `get_interface_info(self, interface_name: str) -> dict`

Get detailed information about a specific network interface.

**Parameters:**
- `interface_name (str)`: The name of the interface to retrieve information for.

**Returns:**
- `dict`: A dictionary containing the interface properties including name, MAC address, IP addresses, type, and state (if available). Returns an empty dictionary if the specified interface is not found.

## Usage Example

```python
from network_security_suite.sniffer.interfaces import Interface

# Initialize the Interface class
interface_manager = Interface()

# Display all available network interfaces
interface_manager.show_available_interfaces()

# Get all Ethernet interfaces
ethernet_interfaces = interface_manager.get_interface_by_type("ethernet")
print(f"Ethernet interfaces: {ethernet_interfaces}")

# Get all active interfaces
active_interfaces = interface_manager.get_active_interfaces()
print(f"Active interfaces: {active_interfaces}")

# Get detailed information about a specific interface
if ethernet_interfaces:
    interface_info = interface_manager.get_interface_info(ethernet_interfaces[0])
    print(f"Interface details: {interface_info}")
```

## Dependencies

- `platform`: For detecting the operating system
- `shutil`: For finding executable paths
- `subprocess`: For executing system commands
- `pathlib`: For handling file paths
- `netifaces`: For cross-platform network interface detection
- `network_security_suite.sniffer.loggers`: For logging information, debug messages, and errors

## Notes

- The module is designed to work across multiple operating systems (Linux, macOS, and Windows).
- Security measures are implemented to prevent command injection when using interface names in subprocess calls.
- The module gracefully handles errors during interface detection, allowing the program to continue with partial interface information.
- Interface type detection is based on common naming conventions and may not be accurate for all interfaces.
- State information (UP/DOWN) may not be available on all systems, particularly Windows.