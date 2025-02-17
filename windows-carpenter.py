import subprocess
import os
import ctypes

def run_powershell(command):
    """Runs a PowerShell command and returns the output."""
    result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
    return result.stdout.strip()

def get_disabled_services():
    """Retrieves a list of currently disabled services."""
    command = "Get-Service | Where-Object { $_.StartType -eq 'Disabled' } | Select-Object -ExpandProperty Name"
    output = run_powershell(command)
    return output.split("\n") if output else []

def disable_unnecessary_services():
    """Disables insecure and unnecessary Windows services."""
    services = [
        "RemoteRegistry", "tlntsvr", "wuauserv", "wscsvc", "wsearch", "fax", "AssignedAccessManager",
        "BDESVC", "bthserv", "BluetoothUserService", "DiagTrack", "diagnosticshub.standardcollector.service", 
        "DPS", "WdiServiceHost", "WdiSystemHost", "lfsvc", "MapsBroker", "Netlogon", "defragsvc", 
        "WPCSvc", "PhoneSvc", "Spooler", "SessionEnv", "TermService", "UmRdpService", "SensorService",
        "SCardSvr", "ScDeviceEnum", "SCPolicySvc", "WbioSrvc", "WerSvc", "workfolderssvc", "wisvc",
        "WalletService", "icssvc", "TabletInputService", "DevicePickerUserSvc", "AJRouter", "AdobeARMservice"
    ]
    
    # List the current disabled services before asking user
    print("\nCurrently disabled services:")
    disabled_services = get_disabled_services()
    if disabled_services:
        for service in disabled_services:
            print(f"- {service}")
    else:
        print("No services are currently disabled.")
    
    while True:
        print("\n1. Enable all services")
        print("2. Enable specific services")
        print("3. List all disabled services")
        print("4. Disable specific services")
        print("5. Disable all unnecessary services")
        print("6. Go back")
        
        option = input("Select an option (1-6) before disabling the services: ")
        
        if option == "1":
            for service in services:
                run_powershell(f"Set-Service -Name {service} -StartupType Manual")
            print("All services have been enabled.")
            continue
        elif option == "2":
            selected_services = input("Enter service names to enable (comma-separated): ").split(",")
            for service in selected_services:
                service = service.strip()
                if service in services:
                    run_powershell(f"Set-Service -Name {service} -StartupType Manual")
                    print(f"Enabled {service}.")
                else:
                    print(f"Service {service} not found in disabled list.")
            continue
        elif option == "3":
            print("\nAll disabled services:")
            disabled_services = get_disabled_services()
            if disabled_services:
                for service in disabled_services:
                    print(f"- {service}")
            else:
                print("No services are currently disabled.")
            continue
        elif option == "4":
            specific_services = input("Enter service names to disable (comma-separated): ").split(",")
            for service in specific_services:
                service = service.strip()
                if service in services:
                    run_powershell(f"Stop-Service -Name {service} -Force -ErrorAction SilentlyContinue")
                    run_powershell(f"Set-Service -Name {service} -StartupType Disabled")
                    print(f"Disabled {service}.")
                else:
                    print(f"Service {service} not found in list of unnecessary services.")
            continue
        elif option == "5":
            # Disable all unnecessary services immediately
            for service in services:
                print(f"Disabling {service}...")
                run_powershell(f"Stop-Service -Name {service} -Force -ErrorAction SilentlyContinue")
                run_powershell(f"Set-Service -Name {service} -StartupType Disabled")
            print("All unnecessary services have been disabled.")
            continue
        elif option == "6":
            break
        else:
            print("Invalid option. Please select again.")

def configure_ports():
    """Configures and manages ports by blocking, enabling, and listing them."""
    while True:
        print("\n1. Disable unnecessary ports")
        print("2. Disable specific ports")
        print("3. List current disabled ports")
        print("4. Enable specific ports")
        print("5. Enable all ports")
        print("6. Go back")
        
        option = input("Select an option (1-6): ")

        if option == "1":
            # Disabling unnecessary ports and printing the blocked ports
            print("Blocking SMB and RDP ports...")
            run_powershell("New-NetFirewallRule -DisplayName 'Block SMB' -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block")
            run_powershell("New-NetFirewallRule -DisplayName 'Block RDP' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block")
            print("Blocked the following ports:")
            print(" - SMB (Port 445)")
            print(" - RDP (Port 3389)")
        elif option == "2":
            # Disabling specific ports (without listing the disabled ports immediately)
            ports = input("Enter ports to disable (comma-separated): ").split(",")
            for port in ports:
                port = port.strip()
                print(f"Disabling port {port}...")
                run_powershell(f"New-NetFirewallRule -DisplayName 'Block Port {port}' -Direction Inbound -Protocol TCP -LocalPort {port} -Action Block")
            print("The specified ports have been disabled.")
        elif option == "3":
            # List current disabled ports
            print("Listing currently disabled ports...")
            blocked_ports = run_powershell("Get-NetFirewallRule | Where-Object {$_.Action -eq 'Block'} | Select-Object DisplayName, LocalPort")
            if blocked_ports:
                print(blocked_ports)
            else:
                print("No ports are currently blocked.")
        elif option == "4":
            # Enabling specific ports
            ports = input("Enter ports to enable (comma-separated): ").split(",")
            for port in ports:
                port = port.strip()
                print(f"Enabling port {port}...")
                run_powershell(f"Remove-NetFirewallRule -DisplayName 'Block Port {port}'")
            print("The specified ports have been enabled.")
        elif option == "5":
            # Enabling all blocked ports
            print("Enabling all blocked ports...")
            run_powershell("Get-NetFirewallRule | Where-Object {$_.Action -eq 'Block'} | Remove-NetFirewallRule")
            print("All ports have been enabled.")
        elif option == "6":
            # Go back to main menu
            break
        else:
            print("Invalid option. Please select again.")


def harden_registry():
    """Allows the user to enable or disable registry-based security enhancements."""
    while True:
        print("\nRegistry Hardening Options:")
        print("1. Disable insecure features")
        print("2. Enable insecure features")
        print("3. List current disabled insecure features")
        print("4. Go back")
        
        option = input("Select an option (1-4): ")

        if option == "1":
            print("Disabling insecure features...")
            security_settings = {
                "Disable Remote Desktop": "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 1 /f",
                "Disable Autorun": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f",
                "Disable Remote Registry": "HKLM:\\System\\CurrentControlSet\\Services\\RemoteRegistry /v Start /t REG_DWORD /d 4 /f"
            }
            for desc, command in security_settings.items():
                print(f"Applying: {desc}...")
                run_powershell(f"reg add {command}")
            print("Insecure features have been disabled.")

        elif option == "2":
            print("Enabling insecure features...")
            insecure_settings = {
                "Enable Remote Desktop": "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0 /f",
                "Enable Autorun": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 0 /f",
                "Enable Remote Registry": "HKLM:\\System\\CurrentControlSet\\Services\\RemoteRegistry /v Start /t REG_DWORD /d 2 /f"
            }
            for desc, command in insecure_settings.items():
                print(f"Reverting: {desc}...")
                run_powershell(f"reg add {command}")
            print("Insecure features have been enabled.")

        elif option == "3":
            print("Listing currently disabled insecure features...")
            disabled_features = {
                "Remote Desktop": "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections",
                "Autorun": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDriveTypeAutoRun",
                "Remote Registry": "HKLM:\\System\\CurrentControlSet\\Services\\RemoteRegistry /v Start"
            }
            for feature, reg_path in disabled_features.items():
                result = run_powershell(f"reg query {reg_path}")
                print(f"{feature}:\n{result}\n")
            print("Displayed all disabled insecure features.")

        elif option == "4":
            print("Returning to main menu...")
            break

        else:
            print("Invalid option. Please select again.")


def enable_windows_defender():
    """Ensures Windows Defender is enabled and updated."""
    print("Ensuring Windows Defender is active...")
    run_powershell("Set-MpPreference -DisableRealtimeMonitoring 0")
    run_powershell("Update-MpSignature")
    print("Windows Defender is now active and updated.")

def create_system_restore_point():
    """Creates a Windows system restore point before applying changes."""
    print("Creating a system restore point...")
    if ctypes.windll.shell32.IsUserAnAdmin():
        run_powershell("Checkpoint-Computer -Description 'SystemHardening' -RestorePointType MODIFY_SETTINGS")
        print("System restore point created.")
    else:
        print("Admin privileges required to create a restore point.")

def main():
    while True:
        print("\nWindows System Hardening Tool")
        print("1. Create System Restore Point")
        print("2. Configure Services")
        print("3. Configure Ports")
        print("4. Harden Registry")
        print("5. Enable Windows Defender")
        print("6. Exit")
        choice = input("Select an option (1-6): ")
        
        if choice == "1":
            create_system_restore_point()
        elif choice == "2":
            disable_unnecessary_services()
        elif choice == "3":
            configure_ports()
        elif choice == "4":
            harden_registry()
        elif choice == "5":
            enable_windows_defender()
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
