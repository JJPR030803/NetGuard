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
from typing import Dict, List, Optional

import netifaces
import string

from network_security_suite.sniffer.loggers import DebugLogger, ErrorLogger, InfoLogger
from network_security_suite.sniffer.loggers import ConsoleLogger # Import ConsoleLogger
from .sniffer_config import SnifferConfig
from typing import Optional

class Interface:
    def __init__(
        self, 
        config: Optional[SnifferConfig] = None,
        interface: Optional[str] = None,  # Legacy support
        interface_detection_method: Optional[str] = None,  # Legacy support
        log_dir: Optional[str] = None  # Legacy support
    ):
        """Initialize the Interface class with configuration support."""
        # Import here to avoid circular imports
        from .sniffer_config import SnifferConfig
        
        # Use provided config or create default
        self.config = config if config is not None else SnifferConfig()
        
        # Legacy support - override config with direct parameters if provided
        if interface is not None:
            self.config.interface = interface
        if interface_detection_method is not None:
            self.config.interface_detection_method = interface_detection_method
        if log_dir is not None:
            self.config.log_dir = log_dir

        # Initialize loggers
        self.info_logger = InfoLogger(log_dir=self.config.log_dir)
        self.debug_logger = DebugLogger(log_dir=self.config.log_dir)
        self.error_logger = ErrorLogger(log_dir=self.config.log_dir)

        self.os_type = platform.system().lower()
        self.interfaces = {}
        self.VALID_IFACE_CHARS = set(string.ascii_letters + string.digits + "-_.")

        try:
            self.interfaces = self._get_interfaces()
            self.info_logger.log(f"Detected {len(self.interfaces)} network interfaces")
        except Exception as e:
            self.error_logger.log(f"Error detecting interfaces: {str(e)}")
            self.interfaces = {}

    def _setup_loggers(self):
        """Setup loggers based on configuration."""
        log_dir = self.config.log_dir if self.config.log_to_file else None

        if self.config.log_to_file:
            Path(self.config.log_dir).mkdir(parents=True, exist_ok=True)

        self.info_logger = InfoLogger(log_dir=log_dir) if self.config.enable_file_logging else ConsoleLogger()
        self.debug_logger = DebugLogger(log_dir=log_dir) if self.config.enable_file_logging else ConsoleLogger()
        self.error_logger = ErrorLogger(log_dir=log_dir) if self.config.enable_file_logging else ConsoleLogger()

    def _auto_select_interface(self):
        """Auto-select best interface based on config preferences."""
        for interface_type in self.config.preferred_interface_types:
            interfaces = self.get_interface_by_type(interface_type)
            if interfaces:
                active_interfaces = [iface for iface in interfaces 
                                   if self.interfaces[iface].get('state') == 'UP']
                if active_interfaces:
                    self.config.interface = active_interfaces[0]
                    self.info_logger.log(f"Auto-selected interface: {self.config.interface}")
                    return

        # Fallback to first available interface
        if self.interfaces:
            self.config.interface = list(self.interfaces.keys())[0]
            self.info_logger.log(f"Fallback interface selected: {self.config.interface}")

    def get_recommended_interface(self) -> Optional[str]:
        """
        Get a recommended interface based on configuration preferences.

        Returns:
            Optional[str]: The name of the recommended interface, or None if no suitable interface is found.
        """
        if not self.interfaces:
            self.error_logger.log("No interfaces available for recommendation")
            return None

        # If a specific interface is configured and exists, use it
        if (self.config.interface and 
            self.config.interface in self.interfaces and 
            self.config.interface_detection_method == 'manual'):
            return self.config.interface

        # Auto-detection based on preferences
        if self.config.interface_detection_method == 'auto':
            # Get active interfaces first
            active_interfaces = self.get_active_interfaces()

            # Filter by preferred types
            for preferred_type in self.config.preferred_interface_types:
                matching_interfaces = [
                    iface for iface in active_interfaces 
                    if self.interfaces[iface].get('type') == preferred_type
                ]
                if matching_interfaces:
                    selected = matching_interfaces[0]  # Take the first match
                    self.info_logger.log(f"Auto-selected interface: {selected} (type: {preferred_type})")
                    return selected

            # If no preferred type matches, return the first active interface
            if active_interfaces:
                selected = active_interfaces[0]
                self.info_logger.log(f"Auto-selected interface: {selected} (fallback)")
                return selected

        self.error_logger.log("No suitable interface found")
        return None

    def validate_interface(self, interface_name: str) -> bool:
        """Validate interface name based on config security settings."""
        if not self.config.validate_interface_names:
            return True

        return self._is_valid_interface_name(interface_name)

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
        self.debug_logger.log(f"Detecting network interfaces for {self.os_type}")
        try:
            if self.os_type == "linux":
                self.debug_logger.log("Using Linux interface detection method")
                return self._get_linux_interfaces()
            if self.os_type == "darwin":  # macOS
                self.debug_logger.log("Using macOS interface detection method")
                return self._get_macos_interfaces()
            if self.os_type == "windows":
                self.debug_logger.log("Using Windows interface detection method")
                return self._get_windows_interfaces()

            error_msg = f"Operating system {self.os_type} not supported"
            self.error_logger.log(error_msg)
            raise NotImplementedError(error_msg)
        except Exception as e:
            self.error_logger.log(f"Error detecting network interfaces: {str(e)}")
            raise

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
        self.debug_logger.log("Detecting Linux network interfaces")
        interfaces = {}
        try:
            # Using netifaces for basic interface detection
            self.debug_logger.log("Using netifaces for basic interface detection")
            for iface in netifaces.interfaces():
                self.debug_logger.log(f"Processing interface: {iface}")
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
                self.debug_logger.log(
                    f"Added interface {iface} with type {interface_info['type']}"
                )

            # Additional Linux-specific information
            ip_path = shutil.which("ip")
            if ip_path:
                self.debug_logger.log("Using 'ip' command for additional information")
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
                                self.debug_logger.log(
                                    f"Updated interface {iface_name} state to {state}"
                                )
                except subprocess.CalledProcessError:
                    self.error_logger.log("Failed to execute 'ip link show' command")
                    pass

            self.info_logger.log(
                f"Successfully detected {len(interfaces)} Linux network interfaces"
            )
        except Exception as e:
            self.error_logger.log(f"Error detecting Linux interfaces: {str(e)}")
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
        self.info_logger.log(f"Displaying {len(self.interfaces)} network interfaces")
        print(f"\nNetwork Interfaces on {self.os_type.capitalize()}:")
        print("-" * 60)
        for name, info in self.interfaces.items():
            print(f"Interface: {name}")
            self.debug_logger.log(f"Displaying details for interface: {name}")
            for key, value in info.items():
                if key != "name":
                    print(f"  {key}: {value}")
            print("-" * 60)
        self.info_logger.log("Finished displaying network interfaces")

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
        self.debug_logger.log(f"Filtering interfaces by type: {type_name}")
        interfaces = [
            name for name, info in self.interfaces.items() if info["type"] == type_name
        ]
        self.info_logger.log(
            f"Found {len(interfaces)} interfaces of type '{type_name}'"
        )
        return interfaces

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
        self.debug_logger.log("Filtering interfaces by active state (UP)")
        active_interfaces = [
            name for name, info in self.interfaces.items() if info.get("state") == "UP"
        ]
        self.info_logger.log(f"Found {len(active_interfaces)} active interfaces")
        return active_interfaces

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
        self.debug_logger.log(f"Retrieving information for interface: {interface_name}")
        interface_info = self.interfaces.get(interface_name, {})
        if interface_info:
            self.info_logger.log(f"Found interface information for {interface_name}")
        else:
            self.error_logger.log(f"Interface not found: {interface_name}")
        return interface_info