import platform
import re
import subprocess
from typing import Dict, List

import netifaces  # You'll need to add this to your poetry dependencies


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

    def __init__(self):
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
        elif self.os_type == "darwin":  # macOS
            return self._get_macos_interfaces()
        elif self.os_type == "windows":
            return self._get_windows_interfaces()
        else:
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
                    "ipv6": addrs.get(netifaces.AF_INET6, [{"addr": None}])[0]["addr"]
                    if netifaces.AF_INET6 in addrs
                    else None,
                    "type": self._detect_interface_type(iface),
                }
                interfaces[iface] = interface_info

            # Additional Linux-specific information
            if subprocess.getoutput("which ip"):
                try:
                    ip_link = subprocess.check_output(["ip", "link", "show"]).decode()
                    for line in ip_link.split("\n"):
                        if ":" in line:
                            iface_name = line.split(":")[1].strip()
                            if iface_name in interfaces:
                                # Add state information
                                state = "UP" if "UP" in line else "DOWN"
                                interfaces[iface_name]["state"] = state
                except subprocess.CalledProcessError:
                    pass

        except Exception as e:
            print(f"Error getting Linux interfaces: {e}")
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
                    "ipv6": addrs.get(netifaces.AF_INET6, [{"addr": None}])[0]["addr"]
                    if netifaces.AF_INET6 in addrs
                    else None,
                    "type": self._detect_interface_type(iface),
                }

                # Additional macOS specific information using ifconfig
                try:
                    ifconfig = subprocess.check_output(["ifconfig", iface]).decode()
                    interface_info["state"] = (
                        "UP" if "status: active" in ifconfig.lower() else "DOWN"
                    )
                except subprocess.CalledProcessError:
                    interface_info["state"] = "UNKNOWN"

                interfaces[iface] = interface_info

        except Exception as e:
            print(f"Error getting macOS interfaces: {e}")
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
            netsh_output = subprocess.check_output("ipconfig /all", shell=True).decode(
                "utf-8"
            )
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

        except Exception as e:
            print(f"Error getting Windows interfaces: {e}")
        return interfaces

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
        if iface == "lo" or iface == "loopback":
            return "loopback"
        elif iface.startswith(("eth", "en", "eno")):
            return "ethernet"
        elif iface.startswith(("wlan", "wifi", "wl")):
            return "wireless"
        elif iface.startswith(("docker", "br-")):
            return "docker"
        elif iface.startswith("veth"):
            return "virtual"
        elif iface.startswith("tun") or iface.startswith("tap"):
            return "vpn"
        else:
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
