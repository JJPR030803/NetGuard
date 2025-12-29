from netguard.core.interfaces import Interface

if __name__ == "__main__":
    interface = Interface().get_active_interfaces()
    print(interface)
