"""
interfaces.py
This module contains the Interface class for detecting and managing network interfaces.
Compatible with multiple operating systems.
"""

import platform
import shutil

# B404: We need to use subprocess for system commands, but we've implemented
# security measures to mitigate risks (full paths, no shell=True, input validation)
import subprocess  # nosec B404
from pathlib import Path
from typing import Dict, List

import netifaces  # You'll need to add this to your poetry dependencies

# from network_security_suite.sniffer.exceptions import InterfaceConfigurationError


class Interface:
    """
    A class for detecting and managing network interfaces across different operating systems.

    This class provides methods to identify network interfaces on Linux, macOS, and Windows
    systems, retrieve their properties (IP addresses, MAC addresses, etc.), and filter them
    based on various criteria.

    Attributes:
        os_type (str): The lowercase name of the current operating system.
        interfaces (dict): A dictionary of detected network interfaces and their properties.
    """

    # Valid characters for interface names (alphanumeric, dash, underscore, dot, colon)
    VALID_IFACE_CHARS = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:+"
    )

    def __init__(self) -> None:
        """
        Initialize the Interface class.

        Detects the current operating system and populates the interfaces dictionary
        with information about all available network interfaces.
        """
        self.os_type = platform.system().lower()
        self.interfaces = self._get_interfaces()

    def _get_interfaces(self) -> Dict[str, dict]:
        """
        Get network interfaces based on the current operating system.

        This method acts as a router to call the appropriate OS-specific method
        for detecting network interfaces.

        Returns:
            Dict[str, dict]: A dictionary where keys are interface names and values are
                dictionaries containing interface properties (name, MAC, IP addresses, etc.)

        Raises:
            NotImplementedError: If the current operating system is not supported.
        """
        if self.os_type == "linux":
            return self._get_linux_interfaces()
        if self.os_type == "darwin":  # macOS
            return self._get_macos_interfaces()
        if self.os_type == "windows":
            return self._get_windows_interfaces()
        raise NotImplementedError(f"Operating system {self.os_type} not supported")

    def _get_linux_interfaces(self) -> Dict[str, dict]:
        """
        Get network interfaces on Linux systems.

        Uses the netifaces library for basic interface detection and the 'ip' command
        for additional Linux-specific information.

        Returns:
            Dict[str, dict]: A dictionary where keys are interface names and values are
                dictionaries containing interface properties including:
                - name: The interface name
                - mac: The MAC address
                - ipv4: The IPv4 address
                - ipv6: The IPv6 address (if available)
                - type: The detected interface type
                - state: The interface state (UP/DOWN) if available
        """
        interfaces = {}
        try:
            # Using netifaces for basic interface detection
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                interface_info = {
                    "name": iface,
                    "mac": addrs.get(netifaces.AF_LINK, [{"addr": None}])[0]["addr"],
                    "ipv4": addrs.get(netifaces.AF_INET, [{"addr": None}])[0]["addr"],
                    "ipv6": (
                        addrs.get(netifaces.AF_INET6, [{"addr": None}])[0]["addr"]
                        if netifaces.AF_INET6 in addrs
                        else None
                    ),
                    "type": self._detect_interface_type(iface),
                }
                interfaces[iface] = interface_info

            # Additional Linux-specific information
            ip_path = shutil.which("ip")
            if ip_path:
                try:
                    # B603: This subprocess call is safe because:
                    # 1. We use the full path to the executable (ip_path from shutil.which)
                    # 2. We use a fixed list of arguments with no user input
                    # 3. We don't use shell=True
                    ip_link = subprocess.run(  # nosec B603
                        [ip_path, "link", "show"],
                        capture_output=True,
                        text=True,
                        check=True,
                    ).stdout
                    for line in ip_link.split("\n"):
                        if ":" in line:
                            iface_name = line.split(":")[1].strip()
                            if iface_name in interfaces:
                                # Add state information
                                state = "UP" if "UP" in line else "DOWN"
                                interfaces[iface_name]["state"] = state
                except subprocess.CalledProcessError:
                    pass

        except Exception:
            # Log the error but return any interfaces we've found so far
            # This allows the program to continue with partial interface information
            pass
        return interfaces

    def _get_macos_interfaces(self) -> Dict[str, dict]:
        """
        Get network interfaces on macOS systems.

        Uses the netifaces library for basic interface detection and the 'ifconfig' command
        for additional macOS-specific information.

        Returns:
            Dict[str, dict]: A dictionary where keys are interface names and values are
                dictionaries containing interface properties including:
                - name: The interface name
                - mac: The MAC address
                - ipv4: The IPv4 address
                - ipv6: The IPv6 address (if available)
                - type: The detected interface type
                - state: The interface state (UP/DOWN/UNKNOWN)
        """
        interfaces = {}
        try:
            # Basic interface detection using netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                interface_info = {
                    "name": iface,
                    "mac": addrs.get(netifaces.AF_LINK, [{"addr": None}])[0]["addr"],
                    "ipv4": addrs.get(netifaces.AF_INET, [{"addr": None}])[0]["addr"],
                    "ipv6": (
                        addrs.get(netifaces.AF_INET6, [{"addr": None}])[0]["addr"]
                        if netifaces.AF_INET6 in addrs
                        else None
                    ),
                    "type": self._detect_interface_type(iface),
                }

                # Additional macOS specific information using ifconfig
                ifconfig_path = shutil.which("ifconfig")
                if ifconfig_path and self._is_valid_interface_name(iface):
                    try:
                        # B603: This subprocess call is safe because:
                        # 1. We use the full path to the executable (ifconfig_path from shutil.which)
                        # 2. We validate the interface name with _is_valid_interface_name()
                        # 3. We don't use shell=True
                        ifconfig = subprocess.run(  # nosec B603
                            [ifconfig_path, iface],
                            capture_output=True,
                            text=True,
                            check=True,
                        ).stdout
                        interface_info["state"] = (
                            "UP" if "status: active" in ifconfig.lower() else "DOWN"
                        )
                    except subprocess.CalledProcessError:
                        interface_info["state"] = "UNKNOWN"
                else:
                    interface_info["state"] = "UNKNOWN"

                interfaces[iface] = interface_info

        except Exception:
            # Log the error but return any interfaces we've found so far
            # This allows the program to continue with partial interface information
            pass
        return interfaces

    def _get_windows_interfaces(self) -> Dict[str, dict]:
        """
        Get network interfaces on Windows systems.

        Uses the 'ipconfig /all' command to retrieve information about network interfaces
        on Windows systems.

        Returns:
            Dict[str, dict]: A dictionary where keys are interface names and values are
                dictionaries containing interface properties including:
                - name: The interface name
                - mac: The MAC address (Physical Address)
                - ipv4: The IPv4 address (if available)
                - ipv6: The IPv6 address (if available)
                - type: The detected interface type
                - state: The interface state (typically 'UNKNOWN' as Windows doesn't provide
                  this information in the same way as Linux/macOS)
        """
        interfaces = {}
        try:
            # Using Windows specific commands
            # On Windows, we need to use the full path to ipconfig.exe
            try:
                ipconfig_path = Path(r"C:\Windows\System32\ipconfig.exe")

                # Use the safer subprocess.run instead of check_output
                if ipconfig_path.exists():
                    # B603: This subprocess call is safe because:
                    # 1. We use the full path to the executable (hardcoded Windows system path)
                    # 2. We use a fixed list of arguments with no user input
                    # 3. We explicitly set shell=False for security
                    netsh_output = subprocess.run(  # nosec B603
                        [str(ipconfig_path), "/all"],
                        capture_output=True,
                        text=True,
                        shell=False,  # Explicitly set shell=False for security
                        check=True,
                    ).stdout
                else:
                    # Fallback to PATH-based execution if the hardcoded path doesn't exist
                    ipconfig_path_str = shutil.which("ipconfig")
                    if not ipconfig_path_str:
                        # Create but don't raise the exception - return empty dict instead
                        # This would be a good place for logging in a production environment
                        # InterfaceConfigurationError(config_issue="ipconfig command not found")
                        return {}  # Return empty dict if ipconfig is not found
                    ipconfig_path = Path(ipconfig_path_str)

                    # B603: This subprocess call is safe because:
                    # 1. We use the full path to the executable (ipconfig_path from shutil.which)
                    # 2. We use a fixed list of arguments with no user input
                    # 3. We explicitly set shell=False for security
                    netsh_output = subprocess.run(  # nosec B603
                        [ipconfig_path, "/all"],
                        capture_output=True,
                        text=True,
                        shell=False,  # Explicitly set shell=False for security
                        check=True,
                    ).stdout
            except subprocess.CalledProcessError:
                # Return empty dict if ipconfig fails
                # This would be a good place for logging in a production environment
                # InterfaceConfigurationError(config_issue="Error running ipconfig")
                return {}
            current_interface = None
            interface_info = {}

            for line in netsh_output.split("\n"):
                line = line.strip()
                if not line:
                    continue

                if not line.startswith(" "):
                    # New interface found
                    if current_interface and interface_info:
                        interfaces[current_interface] = interface_info
                    current_interface = line.rstrip(":")
                    interface_info = {
                        "name": current_interface,
                        "type": self._detect_interface_type(current_interface),
                        "state": "UNKNOWN",
                    }
                else:
                    # Parse interface details
                    if "Physical Address" in line:
                        interface_info["mac"] = line.split(":")[1].strip()
                    elif "IPv4 Address" in line:
                        interface_info["ipv4"] = (
                            line.split(":")[1].strip().replace("(Preferred)", "")
                        )
                    elif "IPv6 Address" in line:
                        interface_info["ipv6"] = (
                            line.split(":")[1].strip().replace("(Preferred)", "")
                        )

            # Add the last interface
            if current_interface and interface_info:
                interfaces[current_interface] = interface_info

        except Exception:
            # Log the error but return any interfaces we've found so far
            # This allows the program to continue with partial interface information
            pass
        return interfaces

    def _is_valid_interface_name(self, iface: str) -> bool:
        """
        Validate that an interface name contains only allowed characters.

        This is a security measure to prevent command injection when using
        interface names in subprocess calls.

        Args:
            iface (str): The interface name to validate

        Returns:
            bool: True if the interface name is valid, False otherwise
        """
        if not iface:
            return False

        # Check that all characters in the interface name are valid
        return all(c in self.VALID_IFACE_CHARS for c in iface)

    def _detect_interface_type(self, iface: str) -> str:
        """
        Detect the type of network interface based on its name.

        Uses common naming conventions to determine the interface type.

        Args:
            iface (str): The name of the network interface.

        Returns:
            str: The detected interface type, one of:
                - 'loopback': For loopback interfaces
                - 'ethernet': For Ethernet interfaces
                - 'wireless': For WiFi interfaces
                - 'docker': For Docker network interfaces
                - 'virtual': For virtual interfaces
                - 'vpn': For VPN tunnel interfaces
                - 'unknown': If the type cannot be determined
        """
        iface = iface.lower()
        if iface in ("lo", "loopback"):
            return "loopback"
        if iface.startswith(("eth", "en", "eno")):
            return "ethernet"
        if iface.startswith(("wlan", "wifi", "wl")):
            return "wireless"
        if iface.startswith(("docker", "br-")):
            return "docker"
        if iface.startswith("veth"):
            return "virtual"
        if iface.startswith(("tun", "tap")):
            return "vpn"
        return "unknown"

    def show_available_interfaces(self) -> None:
        """
        Display all available network interfaces with their details.

        Prints a formatted list of all detected network interfaces and their properties
        to the console, including name, MAC address, IP addresses, interface type, and state.

        Returns:
            None
        """
        print(f"\nNetwork Interfaces on {self.os_type.capitalize()}:")
        print("-" * 60)
        for name, info in self.interfaces.items():
            print(f"Interface: {name}")
            for key, value in info.items():
                if key != "name":
                    print(f"  {key}: {value}")
            print("-" * 60)

    def get_interface_by_type(self, type_name: str) -> List[str]:
        """
        Get all interfaces of a specific type.

        Args:
            type_name (str): The type of interface to filter by. Valid values include:
                'loopback', 'ethernet', 'wireless', 'docker', 'virtual', 'vpn', 'unknown'.

        Returns:
            List[str]: A list of interface names that match the specified type.
                Returns an empty list if no interfaces of the specified type are found.
        """
        return [
            name for name, info in self.interfaces.items() if info["type"] == type_name
        ]

    def get_active_interfaces(self) -> List[str]:
        """
        Get all active network interfaces.

        Returns a list of interface names that have their state set to 'UP'.
        Note that this may not be accurate on all systems, particularly Windows,
        where the state information might not be available.

        Returns:
            List[str]: A list of active interface names.
                Returns an empty list if no active interfaces are found.
        """
        return [
            name for name, info in self.interfaces.items() if info.get("state") == "UP"
        ]

    def get_interface_info(self, interface_name: str) -> dict:
        """
        Get detailed information about a specific network interface.

        Args:
            interface_name (str): The name of the interface to retrieve information for.

        Returns:
            dict: A dictionary containing the interface properties including name, MAC address,
                IP addresses, type, and state (if available). Returns an empty dictionary
                if the specified interface is not found.
        """
        return self.interfaces.get(interface_name, {})
