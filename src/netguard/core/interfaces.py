"""
interfaces.py
Network interface detection with two distinct modes:
- Interface.scan: Quick, stateless operations (scripting/testing)
- Interface(...): Full-featured manager (security audits/production)
"""

import platform
import shutil
import subprocess  # nosec B404
from pathlib import Path
from collections.abc import Iterator
from typing import ClassVar, Optional, Union

import netifaces  # type: ignore[import-untyped]

from netguard.core.loggers import (
    ConsoleLogger,
    DebugLogger,
    ErrorLogger,
    InfoLogger,
)

from .config import SnifferConfig


class _InterfaceScanner:
    """
    Stateless interface scanning utilities.

    Access via Interface.scan for quick operations without logging.
    Not meant to be instantiated directly.

    Examples:
        >>> # Quick scans (no logging, no configuration)
        >>> interfaces = Interface.scan.all()
        >>> is_valid = Interface.scan.validate_name("eth0")
        >>> iface_type = Interface.scan.detect_type("wlan0")
        >>> ethernet = Interface.scan.by_type(interfaces, "ethernet")
    """

    VALID_IFACE_CHARS: ClassVar[set[str]] = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:+"
    )

    @staticmethod
    def all(os_type: Optional[str] = None) -> dict[str, dict]:
        """
        Get all network interfaces (stateless scan).

        Args:
            os_type: Override OS detection (default: auto-detect)

        Returns:
            Dictionary mapping interface names to their properties

        Example:
            >>> interfaces = Interface.scan.all()
            >>> for name, info in interfaces.items():
            ...     print(f"{name}: {info['ipv4']}")
        """
        detected_os = os_type or platform.system().lower()

        if detected_os == "linux":
            return _InterfaceScanner._scan_linux()
        elif detected_os == "darwin":
            return _InterfaceScanner._scan_macos()
        elif detected_os == "windows":
            return _InterfaceScanner._scan_windows()
        else:
            raise NotImplementedError(f"OS {detected_os} not supported")

    @staticmethod
    def validate_name(iface: str) -> bool:
        """
        Validate interface name for security.

        Args:
            iface: Interface name to validate

        Returns:
            True if name contains only safe characters

        Example:
            >>> Interface.scan.validate_name("eth0")
            True
            >>> Interface.scan.validate_name("eth0; rm -rf /")
            False
        """
        if not iface:
            return False
        return all(c in _InterfaceScanner.VALID_IFACE_CHARS for c in iface)

    @staticmethod
    def detect_type(iface: str) -> str:
        """
        Detect interface type from name.

        Args:
            iface: Interface name

        Returns:
            Type: 'loopback', 'ethernet', 'wireless', 'docker',
                  'virtual', 'vpn', or 'unknown'

        Example:
            >>> Interface.scan.detect_type("eth0")
            'ethernet'
            >>> Interface.scan.detect_type("wlan0")
            'wireless'
        """
        iface_lower = iface.lower()

        if iface_lower in ("lo", "loopback"):
            return "loopback"

        prefix_mapping = [
            (("eth", "en", "eno"), "ethernet"),
            (("wlan", "wifi", "wl"), "wireless"),
            (("docker", "br-"), "docker"),
            (("veth",), "virtual"),
            (("tun", "tap"), "vpn"),
        ]

        for prefixes, iface_type in prefix_mapping:
            if iface_lower.startswith(prefixes):
                return iface_type

        return "unknown"

    @staticmethod
    def by_type(interfaces: dict[str, dict], type_name: str) -> list[str]:
        """
        Filter interfaces by type.

        Args:
            interfaces: Dictionary from Interface.scan.all()
            type_name: Type to filter by

        Returns:
            List of interface names matching the type

        Example:
            >>> interfaces = Interface.scan.all()
            >>> wireless = Interface.scan.by_type(interfaces, "wireless")
        """
        return [name for name, info in interfaces.items() if info.get("type") == type_name]

    @staticmethod
    def active(interfaces: dict[str, dict]) -> list[str]:
        """
        Filter to only active (UP) interfaces.

        Args:
            interfaces: Dictionary from Interface.scan.all()

        Returns:
            List of active interface names

        Example:
            >>> interfaces = Interface.scan.all()
            >>> active = Interface.scan.active(interfaces)
        """
        return [name for name, info in interfaces.items() if info.get("state") == "UP"]

    @staticmethod
    def default() -> Optional[str]:
        """
        Get the default network interface.

        Returns:
            Name of default interface or None

        Example:
            >>> default = Interface.scan.default()
            >>> print(f"Default: {default}")
        """
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get("default", {}).get(netifaces.AF_INET)
            return default_gateway[1] if default_gateway else None
        except Exception:
            return None

    # ========================================================================
    # Private implementation methods
    # ========================================================================

    @staticmethod
    def _scan_linux() -> dict[str, dict]:
        """Scan Linux interfaces."""
        interfaces = {}
        try:
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
                    "type": _InterfaceScanner.detect_type(iface),
                }
                interfaces[iface] = interface_info

            # Add state information
            ip_path = shutil.which("ip")
            if ip_path:
                try:
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
                                state = "UP" if "UP" in line else "DOWN"
                                interfaces[iface_name]["state"] = state
                except subprocess.CalledProcessError:
                    pass
        except Exception:
            pass
        return interfaces

    @staticmethod
    def _scan_macos() -> dict[str, dict]:
        """Scan macOS interfaces."""
        interfaces = {}
        try:
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
                    "type": _InterfaceScanner.detect_type(iface),
                }

                ifconfig_path = shutil.which("ifconfig")
                if ifconfig_path and _InterfaceScanner.validate_name(iface):
                    try:
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
            pass
        return interfaces

    @staticmethod
    def _scan_windows() -> dict[str, dict]:
        """Scan Windows interfaces."""
        interfaces = {}
        try:
            ipconfig_path = Path(r"C:\Windows\System32\ipconfig.exe")

            if ipconfig_path.exists():
                netsh_output = subprocess.run(  # nosec B603
                    [str(ipconfig_path), "/all"],
                    capture_output=True,
                    text=True,
                    shell=False,
                    check=True,
                ).stdout
            else:
                ipconfig_path_str = shutil.which("ipconfig")
                if not ipconfig_path_str:
                    return {}
                ipconfig_path = Path(ipconfig_path_str)

                netsh_output = subprocess.run(  # nosec B603
                    [str(ipconfig_path), "/all"],
                    capture_output=True,
                    text=True,
                    shell=False,
                    check=True,
                ).stdout

            current_interface = None
            interface_info = {}

            for raw_line in netsh_output.split("\n"):
                line = raw_line.strip()
                if not line:
                    continue

                if not line.startswith(" "):
                    if current_interface and interface_info:
                        interfaces[current_interface] = interface_info
                    current_interface = line.rstrip(":")
                    interface_info = {
                        "name": current_interface,
                        "type": _InterfaceScanner.detect_type(current_interface),
                        "state": "UNKNOWN",
                    }
                elif "Physical Address" in line:
                    interface_info["mac"] = line.split(":")[1].strip()
                elif "IPv4 Address" in line:
                    interface_info["ipv4"] = line.split(":")[1].strip().replace("(Preferred)", "")
                elif "IPv6 Address" in line:
                    interface_info["ipv6"] = line.split(":")[1].strip().replace("(Preferred)", "")

            if current_interface and interface_info:
                interfaces[current_interface] = interface_info

        except Exception:
            pass
        return interfaces


class Interface:
    """
    Full-featured interface manager with logging and configuration.

    Two usage modes:

    1. Quick scanning (no logging):
        >>> interfaces = Interface.scan.all()
        >>> default = Interface.scan.default()
        >>> if Interface.scan.validate_name("eth0"):
        ...     print("Valid")

    2. Managed operations (with logging):
        >>> manager = Interface(config=my_config)
        >>> manager.show_available_interfaces()  # Logged
        >>> recommended = manager.get_recommended_interface()  # Logged

    Use Interface.scan for:
    - Quick scripts and testing
    - One-off queries
    - Performance-critical operations

    Use Interface(...) for:
    - Security audits (logged operations)
    - Production packet sniffing (compliance/legal)
    - Complex workflows requiring configuration
    - Operations needing audit trails
    """

    # Expose scanner as namespace
    scan = _InterfaceScanner

    def __init__(
        self,
        config: Optional[SnifferConfig] = None,
        interface: Optional[str] = None,  # Legacy support
        interface_detection_method: Optional[str] = None,  # Legacy support
        log_dir: Optional[str] = None,  # Legacy support
    ):
        """
        Initialize interface manager.

        Args:
            config: Configuration object
            interface: (Legacy) Direct interface specification
            interface_detection_method: (Legacy) Detection method
            log_dir: (Legacy) Log directory
        """
        # Use provided config or create default
        self.config = config if config is not None else SnifferConfig()

        # Legacy support
        if interface is not None:
            self.config.interface = interface  # type: ignore
        if interface_detection_method is not None:
            self.config.interface_detection_method = interface_detection_method  # type: ignore
        if log_dir is not None:
            self.config.log_dir = log_dir  # type: ignore

        # Initialize loggers
        self._setup_loggers()

        self.os_type = platform.system().lower()
        self.interfaces: dict[str, dict] = {}

        try:
            # Use the scan namespace internally
            self.interfaces = self.scan.all(os_type=self.os_type)
            self.info_logger.log(f"Detected {len(self.interfaces)} network interfaces")
        except Exception as e:
            self.error_logger.log(f"Error detecting interfaces: {e!s}")
            self.interfaces = {}

    def __repr__(self) -> str:
        iface_names = list(self.interfaces.keys())
        return f"Interface(os_type={self.os_type!r}, interfaces={iface_names!r})"

    def __str__(self) -> str:
        active = self.get_active_interfaces()
        return f"Interface({self.os_type}): {len(self.interfaces)} detected, {len(active)} active"

    def __len__(self) -> int:
        return len(self.interfaces)

    def __bool__(self) -> bool:
        return bool(self.interfaces)

    def __contains__(self, interface_name: object) -> bool:
        return interface_name in self.interfaces

    def __getitem__(self, interface_name: str) -> dict:
        return self.interfaces[interface_name]

    def __iter__(self) -> Iterator[str]:
        return iter(self.interfaces)

    def _setup_loggers(self) -> None:
        """Setup loggers based on configuration."""
        log_dir = self.config.log_dir if self.config.log_to_file else None

        if self.config.log_to_file:
            Path(self.config.log_dir).mkdir(parents=True, exist_ok=True)

        self.info_logger: Union[InfoLogger, ConsoleLogger] = (
            InfoLogger(log_dir=log_dir) if self.config.enable_file_logging else ConsoleLogger()
        )
        self.debug_logger: Union[DebugLogger, ConsoleLogger] = (
            DebugLogger(log_dir=log_dir) if self.config.enable_file_logging else ConsoleLogger()
        )
        self.error_logger: Union[ErrorLogger, ConsoleLogger] = (
            ErrorLogger(log_dir=log_dir) if self.config.enable_file_logging else ConsoleLogger()
        )

    def validate_interface(self, interface_name: str) -> bool:
        """
        Validate interface name (with logging).

        Args:
            interface_name: Name to validate

        Returns:
            True if valid according to config
        """
        self.debug_logger.log(f"Validating interface: {interface_name}")

        if not self.config.validate_interface_names:
            self.debug_logger.log("Validation disabled by config")
            return True

        is_valid = self.scan.validate_name(interface_name)

        if is_valid:
            self.debug_logger.log(f"Interface {interface_name} is valid")
        else:
            self.error_logger.log(f"Interface {interface_name} contains invalid characters")

        return is_valid

    def get_recommended_interface(self) -> Optional[str]:
        """
        Get recommended interface based on config preferences (with logging).

        Returns:
            Interface name or None
        """
        if not self.interfaces:
            self.error_logger.log("No interfaces available for recommendation")
            return None

        # Manual mode - use configured interface
        if (
            self.config.interface
            and self.config.interface in self.interfaces
            and self.config.interface_detection_method == "manual"
        ):
            self.info_logger.log(f"Using manually configured interface: {self.config.interface}")
            return self.config.interface

        # Auto mode - use preferences
        if self.config.interface_detection_method == "auto":
            active_interfaces = self.get_active_interfaces()

            for preferred_type in self.config.preferred_interface_types:
                matching = [
                    iface
                    for iface in active_interfaces
                    if self.interfaces[iface].get("type") == preferred_type
                ]
                if matching:
                    selected = matching[0]
                    self.info_logger.log(
                        f"Auto-selected interface: {selected} (type: {preferred_type})"
                    )
                    return selected

            if active_interfaces:
                selected = active_interfaces[0]
                self.info_logger.log(f"Auto-selected interface: {selected} (fallback)")
                return selected

        self.error_logger.log("No suitable interface found")
        return None

    def show_available_interfaces(self) -> None:
        """Display all interfaces (with logging)."""
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

    def get_interface_by_type(self, type_name: str) -> list[str]:
        """
        Get interfaces by type (with logging).

        Args:
            type_name: Type to filter by

        Returns:
            List of matching interface names
        """
        self.debug_logger.log(f"Filtering interfaces by type: {type_name}")
        interfaces = self.scan.by_type(self.interfaces, type_name)
        self.info_logger.log(f"Found {len(interfaces)} interfaces of type '{type_name}'")
        return interfaces

    def get_active_interfaces(self) -> list[str]:
        """
        Get active interfaces (with logging).

        Returns:
            List of active interface names
        """
        self.debug_logger.log("Filtering interfaces by active state (UP)")
        active = self.scan.active(self.interfaces)
        self.info_logger.log(f"Found {len(active)} active interfaces")
        return active

    def get_interface_info(self, interface_name: str) -> dict:
        """
        Get interface details (with logging).

        Args:
            interface_name: Interface to query

        Returns:
            Dictionary of interface properties
        """
        self.debug_logger.log(f"Retrieving information for interface: {interface_name}")
        interface_info = self.interfaces.get(interface_name, {})

        if interface_info:
            self.info_logger.log(f"Found interface information for {interface_name}")
        else:
            self.error_logger.log(f"Interface not found: {interface_name}")

        return interface_info
