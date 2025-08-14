Program that outputs information about Windows network adapters in a tabular format with an option to select output format — CSV or JSON.

Data for each network adapter includes:

- Adapter Name
- MAC Address
- IP Addresses (all assigned)
- Current Adapter State (up/down)
- DHCP Enabled
- DNS Servers
- Gateway
- Data Sources (registry keys from which parameters were retrieved)

Most network parameters are obtained from the Windows system registry. Each adapter's data is located in a separate registry key, the path of which is constructed using the adapter's GUID.

Main adapter registry path:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\**<Adapter GUID>**
```
Here, `**<Adapter GUID>**` is the unique adapter identifier, which can be normalized by removing the `\DEVICE\TCPIP_` prefix if present.

Values extracted from this key:
- `IPAddress` (REG_MULTI_SZ or REG_SZ):  
  Contains one or more IP addresses assigned to the adapter. If missing, it may be empty.
- `DhcpIPAddress` (REG_SZ):  
  The DHCP-assigned IP address. If DHCP is not used or no IP is assigned, this may be absent.
- `NameServer` (REG_SZ):  
  DNS servers manually configured on the adapter.
- `DhcpNameServer` (REG_SZ):  
  DNS servers obtained via DHCP.

Selection logic:
- If `IPAddress` is missing or empty, use `DhcpIPAddress`.
- Presence of `DhcpIPAddress` indicates DHCP is enabled.
- DNS servers are taken from `NameServer` first; if empty, from `DhcpNameServer`.

The program also annotates output with the source of each parameter, indicating the full registry path (e.g., `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<GUID>\IPAddress`).  
If registry retrieval fails, alternative methods (WinAPI) are used.

**Installation**
1. Download all source files and open the project in Code::Blocks (project configured for Code::Blocks 20.03).
2. Download json.hpp module from https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp and add it into project folder.
3. Click *Build and Run* in Code::Blocks.  
   The resulting `.exe` will appear in the `bin` directory.  
   It can also be run via Command Prompt or PowerShell.

Alternatively, build the project manually:
```
g++ -std=c++11 -o network_info.exe New.cpp -liphlpapi -lws2_32
```

**Using the compiled .exe**
Default run:
```
network_info.exe
```
Outputs results in CSV format. Example:
```csv
Name,MAC,IP,Status,DHCP,DNS,Gateway
"Ethernet 2","0A:0A:0A:0A:0A:0A","fe80::fe80:fe80:fe80:fe80%10, 169.254.82.156","Up","No","",""
"Local Area Connection* 1","DC:21:DC:21:DC:21","fe80::19:66ba:38d0:9cf7%17, 169.254.87.1","Down","No","",""
"Local Area Connection* 2","DE:21:DE:21:DE:21","fe80::6e2b:6e2b:6e2b:6e2b%18, 169.254.246.249","Down","No","",""
"outline-tap0","DE:21:DE:21:DE:21","fe80::6e2b:6e2b:6e2b:6e2b%18, 169.254.38.52","Down","No","1.1.1.1,9.9.9.9",""
"Wireless Network","DE:21:DE:21:DE:21","fe80::6e2b:6e2b:6e2b:6e2b%18, 192.168.1.186","Up","Yes","8.8.8.8,8.8.4.4","192.168.1.1"
"Bluetooth Network Connection","DE:21:DE:21:DE:21","fe80::6e2b:6e2b:6e2b:6e2b%18, 169.254.254.158","Down","No","",""
"Loopback Pseudo-Interface 1","","::1, 127.0.0.1","Up","No","",""
```

You can also add the `--json` argument to output in JSON format:
```
.
etwork_info.exe --json
```
Example JSON output:
```json
[
    {
        "dhcp": "No",
        "dns": "",
        "gateway": "",
        "ip": "fe80::fe80:fe80:fe80:fe80%10, 169.254.82.156",
        "mac": "0A:0A:0A:0A:0A:0A",
        "name": "Ethernet 2",
        "sources": {
            "IP": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{61312BEA-CEEC-4D6B-A303-612B864E12B1}",
            "MAC": "GetAdaptersAddresses",
            "Name": "GetAdaptersAddresses",
            "Status": "GetAdaptersAddresses"
        },
        "status": "Up"
    },
    {
        "dhcp": "No",
        "dns": "",
        "gateway": "",
        "ip": "fe80::19:66ba:38d0:9cf7%17, 169.254.87.1",
        "mac": "DC:21:DC:21:DC:21",
        "name": "Local Area Connection* 1",
        "sources": {
            "IP": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{CFB12BAC-A12B-46C1-BAFC-A012B13CEA67}",
            "MAC": "GetAdaptersAddresses",
            "Name": "GetAdaptersAddresses",
            "Status": "GetAdaptersAddresses"
        },
        "status": "Down"
    }
    // ... other adapter entries ...
]
```
