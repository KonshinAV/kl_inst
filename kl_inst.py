import os
import socket
import winreg
import wmi
from ldap3 import Connection,Server, SUBTREE, LEVEL
from datetime import datetime
import time
from sqlite3 import Connection, Cursor
from pprint import pprint


def get_win32object_info_wmi(select_body):
    w = wmi.WMI()
    return w.query(select_body) if select_body else False

class Computer:
    def __init__(self):
        self.hostname = socket.gethostname()
        self.ip = socket.gethostbyname(self.hostname)
        self.services = self.get_services()
        self.software = self.get_software()
        self.netadapters = self.get_netadapters()

        # Set NetAdapterSettings
        self.net_DNSDomainSuffixSearchOrder = False
        self.net_DefaultIPGateway = False
        self.net_DNSServerSearchOrder = False
        self.net_DHCPEnabled = False
        self.net_IPAddress = False
        self.net_IPSubnet = False
        self.net_MACAddress = False

        for adapter in self.netadapters:
            if adapter.DNSDomainSuffixSearchOrder:
                self.net_DNSDomainSuffixSearchOrder = adapter.DNSDomainSuffixSearchOrder
                self.net_DefaultIPGateway = adapter.DefaultIPGateway
                self.net_DNSServerSearchOrder = adapter.DNSServerSearchOrder
                self.net_DHCPEnabled = adapter.DHCPEnabled
                self.net_IPAddress = adapter.IPAddress
                self.net_IPSubnet = adapter.IPSubnet
                self.net_MACAddress = adapter.MACAddress
                break

        # Set Nagent Settings
        self.nagent_service_Name = False
        self.nagent_service_DisplayName = False
        self.nagent_service_ProcessId = False
        self.nagent_service_State = False
        self.nagent_service_Caption = False
        for service in self.services:
            if service.Name == 'klnagent':
                self.nagent_service_Name = service.Name
                self.nagent_service_DisplayName = service.DisplayName
                self.nagent_service_ProcessId = service.ProcessId
                self.nagent_service_State = service.State
                self.nagent_service_Caption = service.Caption
                # print(service)
                break

        self.nagent_InstallSource = False
        self.nagent_IdentifyingNumber = False
        self.nagent_InstallDate = False
        self.nagent_PackageName = False
        self.nagent_PackageCode = False
        self.nagent_LocalPackage = False
        if self.nagent_service_ProcessId:
            for soft in self.software:
                if self.nagent_service_Caption == soft.Caption:
                    self.nagent_InstallSource = soft.InstallSource
                    self.nagent_IdentifyingNumber = soft.IdentifyingNumber
                    self.nagent_InstallDate = soft.InstallDate
                    self.nagent_PackageName = soft.PackageName
                    self.nagent_PackageCode = soft.PackageCode
                    self.nagent_LocalPackage = soft.LocalPackage
                    break

        # Set AV Settings
        self.av_Installed = False
        if self.nagent_service_ProcessId:
            self.av_Installed = bool(self.get_winreg_key(reg_path='SOFTWARE\\WOW6432Node\\KasperskyLab\\Components\\34\\1103\\1.0.0.0\\Statistics\\AVState',
                                          reg_key='Protection_AvInstalled'))

    def get_services (self, update_in_properties = True):
        """
        Getting services on host

        :param update_in_properties:
        :return:
        :example:
        instance of Win32_Service
        {
            AcceptPause = FALSE;
            AcceptStop = FALSE;
            Caption = "Объект автоматизации Kaspersky Security Center 12";
            CheckPoint = 0;
            CreationClassName = "Win32_Service";
            DelayedAutoStart = FALSE;
            Description = "Объект автоматизации Kaspersky Security Center 12";
            DesktopInteract = FALSE;
            DisplayName = "Объект автоматизации Kaspersky Security Center 12";
            ErrorControl = "Normal";
            ExitCode = 1077;
            Name = "klakaut";
            PathName = "\"C:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Security Center Console\\klakaut.exe\"";
            ProcessId = 0;
            ServiceSpecificExitCode = 0;
            ServiceType = "Own Process";
            Started = FALSE;
            StartMode = "Manual";
            StartName = "NT AUTHORITY\\NetworkService";
            State = "Stopped";
            Status = "OK";
            SystemCreationClassName = "Win32_ComputerSystem";
            SystemName = "WIN10-DEV";
            TagId = 0;
            WaitHint = 0;
        };

        instance of Win32_Service
        {
            AcceptPause = FALSE;
            AcceptStop = TRUE;
            Caption = "Агент администрирования Kaspersky Security Center";
            CheckPoint = 0;
            CreationClassName = "Win32_Service";
            DelayedAutoStart = TRUE;
            Description = "Агент администрирования осуществляет взаимодействие между Сервером администрирования и программами \"Лаборатории Касперского\", установленными на устройствах.";
            DesktopInteract = FALSE;
            DisplayName = "Агент администрирования Kaspersky Security Center";
            ErrorControl = "Normal";
            ExitCode = 0;
            Name = "klnagent";
            PathName = "\"C:\\Program Files (x86)\\Kaspersky Lab\\NetworkAgent\\klnagent.exe\" ";
            ProcessId = 5904;
            ServiceSpecificExitCode = 0;
            ServiceType = "Own Process";
            Started = TRUE;
            StartMode = "Auto";
            StartName = "LocalSystem";
            State = "Running";
            Status = "OK";
            SystemCreationClassName = "Win32_ComputerSystem";
            SystemName = "WIN10-DEV";
            TagId = 0;
            WaitHint = 0;
        };
        """
        query = 'SELECT * FROM Win32_Service'
        if update_in_properties:
            self.services = get_win32object_info_wmi(select_body = query)
            return self.services
        else:
            return get_win32object_info_wmi(select_body = query)
    def get_software (self, update_in_properties = True):
        """
        Getting installed software on host

        :param update_in_properties:
        :return:[list] Win32Product instances list
        :example:
        instance of Win32_Product
        {
            AssignmentType = 1;
            Caption = "SQL Server Management Studio for Reporting Services";
            Description = "SQL Server Management Studio for Reporting Services";
            HelpLink = "http://go.microsoft.com/fwlink/?LinkId=154582";
            IdentifyingNumber = "{9B3B5F7F-9C68-4F43-9FC0-5551A08618C2}";
            InstallDate = "20201005";
            InstallSource = "C:\\ProgramData\\Package Cache\\{9B3B5F7F-9C68-4F43-9FC0-5551A08618C2}v15.0.18338.0\\x64\\";
            InstallState = 5;
            Language = "1033";
            LocalPackage = "C:\\Windows\\Installer\\4460b6.msi";
            Name = "SQL Server Management Studio for Reporting Services";
            PackageCache = "C:\\Windows\\Installer\\4460b6.msi";
            PackageCode = "{99303563-EFB3-49E2-8FF8-3686C3D82ABA}";
            PackageName = "ssms_rs.msi";
            Vendor = "Microsoft Corporation";
            Version = "15.0.18338.0";
            WordCount = 0;
        };
        instance of Win32_Product
        {
            AssignmentType = 1;
            Caption = "Агент администрирования Kaspersky Security Center";
            Description = "Агент администрирования Kaspersky Security Center";
            HelpLink = "https://support.kaspersky.ru";
            HelpTelephone = "http://support.kaspersky.com/support/business_support_contacts";
            IdentifyingNumber = "{ED1C2D7E-5C7A-48D8-A697-57D1C080ABA7}";
            InstallDate = "20201008";
            InstallLocation = "C:\\Program Files (x86)\\Kaspersky Lab\\NetworkAgent\\";
            InstallSource = "\\\\ksc\\KLSHARE\\Packages\\NETAGE~1.773\\exec\\";
            InstallState = 5;
            Language = "1049";
            LocalPackage = "C:\\Windows\\Installer\\1233b.msi";
            Name = "Агент администрирования Kaspersky Security Center";
            PackageCache = "C:\\Windows\\Installer\\1233b.msi";
            PackageCode = "{C13DF99E-D093-4A6E-B8CA-A8C8EDF35B41}";
            PackageName = "Kaspersky Network Agent.msi";
            URLUpdateInfo = "https://www.kaspersky.ru/downloads";
            Vendor = "\"Лаборатория Касперского\"";
            Version = "12.0.0.7734";
            WordCount = 0;
        };
        instance of Win32_Product
        {
            AssignmentType = 1;
            Caption = "Консоль администрирования Kaspersky Security Center";
            Description = "Консоль администрирования Kaspersky Security Center";
            HelpLink = "https://support.kaspersky.ru";
            HelpTelephone = "http://support.kaspersky.com/support/business_support_contacts";
            IdentifyingNumber = "{5D35D57A-30B9-493B-819F-C6C2181A0A1A}";
            InstallDate = "20201005";
            InstallLocation = "C:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Security Center Console\\";
            InstallSource = "\\\\192.168.31.100\\share\\kaspersky\\KSC\\";
            InstallState = 5;
            Language = "1049";
            LocalPackage = "C:\\Windows\\Installer\\446028.msi";
            Name = "Консоль администрирования Kaspersky Security Center";
            PackageCache = "C:\\Windows\\Installer\\446028.msi";
            PackageCode = "{206A5A36-DB8B-4D1D-A3C3-72017FC43707}";
            PackageName = "Kaspersky Security Center Console.msi";
            URLUpdateInfo = "https://www.kaspersky.ru/downloads";
            Vendor = "\"Лаборатория Касперского\"";
            Version = "12.0.0.7734";
            WordCount = 0;
        };
        """
        query = 'SELECT * FROM Win32_Product'
        if update_in_properties:
            self.software = get_win32object_info_wmi(select_body = query)
            return self.software
        else:
            return get_win32object_info_wmi(select_body = query)
    def get_netadapters (self, update_in_properties = True):
        '''
        Getting Host Net adapters configuration

        :param: update_in_properties:[bool] If you need  update object properties value use True, default is True
        :return:[list] List of instances (adapters)
        :Example:
        instance of Win32_NetworkAdapterConfiguration
        {
            Caption = "[00000000] Microsoft Kernel Debug Network Adapter";
            Description = "Microsoft Kernel Debug Network Adapter";
            DHCPEnabled = TRUE;
            Index = 0;
            InterfaceIndex = 14;
            IPEnabled = FALSE;
            ServiceName = "kdnic";
            SettingID = "{FD21C621-52A3-47F8-B7F7-3BBC1B726D26}";
        };

        instance of Win32_NetworkAdapterConfiguration
        {
            Caption = "[00000001] Microsoft Hyper-V Network Adapter";
            DatabasePath = "%SystemRoot%\\System32\\drivers\\etc";
            DefaultIPGateway = {"192.168.31.1"};
            Description = "Microsoft Hyper-V Network Adapter";
            DHCPEnabled = FALSE;
            DNSDomainSuffixSearchOrder = {"abc.local"};
            DNSEnabledForWINSResolution = FALSE;
            DNSHostName = "Win10-Dev";
            DNSServerSearchOrder = {"192.168.31.50", "192.168.31.1"};
            DomainDNSRegistrationEnabled = FALSE;
            FullDNSRegistrationEnabled = TRUE;
            GatewayCostMetric = {256};
            Index = 1;
            InterfaceIndex = 4;
            IPAddress = {"192.168.31.60", "fe80::15bc:347b:3e9:8f98"};
            IPConnectionMetric = 35;
            IPEnabled = TRUE;
            IPFilterSecurityEnabled = FALSE;
            IPSecPermitIPProtocols = {};
            IPSecPermitTCPPorts = {};
            IPSecPermitUDPPorts = {};
            IPSubnet = {"255.255.255.0", "64"};
            MACAddress = "00:15:5D:1F:64:0E";
            ServiceName = "netvsc";
            SettingID = "{2B026EAD-077C-4767-8D41-41E4A17D2969}";
            TcpipNetbiosOptions = 0;
            WINSEnableLMHostsLookup = TRUE;
            WINSScopeID = "";
        };

        '''
        query = 'SELECT * FROM Win32_NetworkAdapterConfiguration'
        if update_in_properties:
            self.netadapters = get_win32object_info_wmi(select_body = query)
            return self.netadapters
        else:
            return get_win32object_info_wmi(select_body = query)
    def get_winreg_key (self, reg_path, reg_key):
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,reg_path,0,winreg.KEY_READ)
            reg_key_value, reg_type = winreg.QueryValueEx(registry_key,reg_key)
            winreg.CloseKey(registry_key)
            return str(reg_key_value).lower()
        except WindowsError as ex:
            return False

class ActiveDirectory:
    def __init__(self, dc_server, user, password, auto_connect = True):
        self.dc_server = dc_server
        self.user = user
        self.password = password

    def test_connection (self):
        pass

    def get_ad_attrs (self):
        pass


class InstPackage:
    def __init__(self):
        pass

    def install (self):
        pass

    def uninstall (self):
        pass

    def reinstall (self):
        pass


def data_collector (GLOBAL_DATA):
    # Create Computer object
    this_pc = Computer()
    print(this_pc.nagent_InstallSource, this_pc.nagent_PackageName, this_pc.nagent_InstallDate)
    print(this_pc.av_Installed)
    # print (this_pc.nagent_service_ProcessId)

if __name__ == '__main__':
    GLOBAL_DATA = {'domain':'abc.local',
                   'nagent_inst_path': '',
                   'av_inst_path':''}
    data_collector(GLOBAL_DATA)