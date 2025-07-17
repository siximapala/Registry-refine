#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600

#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <memory>
#include "json.hpp"

#pragma comment(lib, "Ws2_32.lib")   // WinSock lib required for networking functions
#pragma comment(lib, "Iphlpapi.lib") // IP Helper lib for retrieving network adapter info

using json = nlohmann::json;



// Structure holding adapter information
struct network_adapter_info {
    std::string name;    // adapter name
    std::string mac;     // MAC address
    std::string ip;      // IP address(es)
    std::string status;  // adapter status (Up/Down)
    std::string dhcp;    // DHCP address
    std::string dns;     // DNS servers
    std::string gateway; // default gateway
    std::map<std::string, std::string> sources; // sources of each data field
};

// Convert wchar_t* to UTF-8 std::string
std::string wide_to_string(const wchar_t* wide_str) {
    if (!wide_str) return ""; // if null, return empty string

    // determine required buffer size
    int len = WideCharToMultiByte(CP_UTF8, 0, wide_str, -1, nullptr, 0, nullptr, nullptr);

    std::string result(len, 0); // allocate string of required size

    // convert to UTF-8
    WideCharToMultiByte(CP_UTF8, 0, wide_str, -1, &result[0], len, nullptr, nullptr);

    // remove trailing null character if present
    if (!result.empty() && result.back() == '\0') result.pop_back();

    return result;
}

// Read a string value from the Windows registry
std::string read_registry_string(HKEY key, const std::string& subkey, const std::string& value_name) {
    HKEY h_subkey;
    if (RegOpenKeyExA(key, subkey.c_str(), 0, KEY_READ, &h_subkey) != ERROR_SUCCESS)
        return ""; // failed to open key, return empty

    DWORD type, size = 0;

    // query size of the value
    if (RegQueryValueExA(h_subkey, value_name.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS) {
        RegCloseKey(h_subkey);
        return "";
    }

    std::vector<char> buffer(size); // allocate buffer for value

    // read the value into the buffer
    if (RegQueryValueExA(h_subkey, value_name.c_str(), nullptr, &type,
                         reinterpret_cast<LPBYTE>(buffer.data()), &size) != ERROR_SUCCESS) {
        RegCloseKey(h_subkey);
        return "";
    }

    RegCloseKey(h_subkey);

    // if the type is string and buffer is not empty, return it as std::string
    if ((type == REG_SZ || type == REG_MULTI_SZ) && !buffer.empty()) {
        return std::string(buffer.data());
    }

    return ""; // otherwise return empty string
}

// Convert a SOCKADDR to a string representation of an IP address
std::string sock_addr_to_string(SOCKADDR* sa) {
    if (!sa) return ""; // if null, return empty

    char ip_str[INET6_ADDRSTRLEN] = {0}; // buffer for IP string
    DWORD ip_str_len = sizeof(ip_str);

    // determine structure size based on IP version
    int len = (sa->sa_family == AF_INET) ? sizeof(sockaddr_in) :
              (sa->sa_family == AF_INET6) ? sizeof(sockaddr_in6) : 0;

    if (len == 0) return ""; // unknown family, return empty

    // convert address to string; on error return empty
    if (WSAAddressToStringA(sa, len, nullptr, ip_str, &ip_str_len) != 0) return "";

    return std::string(ip_str);
}

// Gather all IP addresses from a unicast address list, separated by commas
std::string get_all_ip_addresses(PIP_ADAPTER_UNICAST_ADDRESS addr) {
    std::string ips; // will contain comma-separated IPs

    for (; addr; addr = addr->Next) {
        std::string ip = sock_addr_to_string(addr->Address.lpSockaddr);
        if (!ip.empty()) {
            if (!ips.empty()) ips += ", "; // add comma if not first
            ips += ip;
        }
    }
    return ips;
}

// Retrieve gateway for an adapter by index using GetAdaptersInfo
std::string get_gateway_by_adapter_index(ULONG index) {
    IP_ADAPTER_INFO adapter_info[16]; // array to hold adapter info
    DWORD buf_len = sizeof(adapter_info);

    if (GetAdaptersInfo(adapter_info, &buf_len) == NO_ERROR) {
        for (int i = 0; i < 16; i++) {
            if (adapter_info[i].Index == index) {
                std::string gw = adapter_info[i].GatewayList.IpAddress.String;
                return (gw != "0.0.0.0") ? gw : ""; // "0.0.0.0" means no gateway
            }
        }
    }
    return ""; // not found or error
}

// Read registry-based network settings for a specific adapter
void get_adapter_registry_data(network_adapter_info& info, const std::string& adapter_guid) {
    std::string guid = adapter_guid;

    // Remove prefix if present (some registry entries include it)
    if (guid.find("\\DEVICE\\TCPIP_") == 0) {
        guid = guid.substr(strlen("\\DEVICE\\TCPIP_"));
    }

    // build registry path
    std::string reg_path = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" + guid;

    // read IP and DHCP IP from registry
    std::string ip = read_registry_string(HKEY_LOCAL_MACHINE, reg_path, "IPAddress");
    std::string dhcp = read_registry_string(HKEY_LOCAL_MACHINE, reg_path, "DhcpIPAddress");

    if (info.ip.empty()) info.ip = !ip.empty() ? ip : dhcp; // if no IP yet, use registry value

    info.dhcp = dhcp.empty() ? "No" : "Yes"; // set DHCP status

    // read DNS from either manual or DHCP values
    std::string dns = read_registry_string(HKEY_LOCAL_MACHINE, reg_path, "NameServer");
    if (dns.empty()) dns = read_registry_string(HKEY_LOCAL_MACHINE, reg_path, "DhcpNameServer");
    info.dns = dns;

    // record sources for retrieved values
    if (!info.ip.empty()) {
        info.sources["IP"] = "HKLM\\" + reg_path;
    }
    if (!dhcp.empty()) {
        info.sources["DHCP"] = "HKLM\\" + reg_path;
    }
    if (!info.dns.empty()) {
        info.sources["DNS"] = "HKLM\\" + reg_path;
    }
}

// Collect information for all system network adapters
std::vector<network_adapter_info> get_network_adapters_info() {
    std::vector<network_adapter_info> adapters;
    ULONG size = 0;

    // first call to determine buffer size for GetAdaptersAddresses
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW) {
        return adapters; // error or no adapters
    }

    // allocate buffer for adapter data
    std::unique_ptr<BYTE[]> buffer(new BYTE[size]);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());

    // retrieve adapter addresses
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &size) != NO_ERROR) {
        return adapters; // error retrieving
    }

    // iterate through adapter list
    for (auto ptr = addresses; ptr; ptr = ptr->Next) {
        network_adapter_info info;

        // convert friendly name from wide string to UTF-8
        info.name = wide_to_string(ptr->FriendlyName);

        // format MAC if length is 6 bytes
        if (ptr->PhysicalAddressLength == 6) {
            char mac[18];
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     ptr->PhysicalAddress[0], ptr->PhysicalAddress[1],
                     ptr->PhysicalAddress[2], ptr->PhysicalAddress[3],
                     ptr->PhysicalAddress[4], ptr->PhysicalAddress[5]);
            info.mac = mac;
        }

        // adapter operational status
        info.status = (ptr->OperStatus == IfOperStatusUp) ? "Up" :
                      (ptr->OperStatus == IfOperStatusDown) ? "Down" : "Unknown";

        // gather all IP addresses
        info.ip = get_all_ip_addresses(ptr->FirstUnicastAddress);

        // get gateway via adapter index
        info.gateway = get_gateway_by_adapter_index(ptr->IfIndex);

        if (!info.gateway.empty()) {
            info.sources["Gateway"] = "GetAdaptersInfo"; // mark source
        }

        // read registry values for the adapter
        get_adapter_registry_data(info, ptr->AdapterName);

        // record sources for other fields
        if (!info.name.empty()) {
            info.sources["Name"] = "GetAdaptersAddresses";
        }
        if (!info.mac.empty()) {
            info.sources["MAC"] = "GetAdaptersAddresses";
        }
        if (!info.status.empty()) {
            info.sources["Status"] = "GetAdaptersAddresses";
        }

        // add adapter info to result
        adapters.push_back(info);
    }

    return adapters;
}

// Print adapters list in CSV format
void print_adapters_csv(const std::vector<network_adapter_info>& adapters) {
    std::cout << "Name,MAC,IP,Status,DHCP,DNS,Gateway\n"; // header

    for (const auto& a : adapters) {
        std::cout << "\"" << a.name << "\","
                  << "\"" << a.mac << "\","
                  << "\"" << a.ip << "\","
                  << "\"" << a.status << "\","
                  << "\"" << a.dhcp << "\","
                  << "\"" << a.dns << "\","
                  << "\"" << a.gateway << "\"\n";
    }
}

// Print adapters list in JSON format
void print_adapters_json(const std::vector<network_adapter_info>& adapters) {
    json j = json::array();

    for (const auto& a : adapters) {
        j.push_back({
            {"name", a.name},
            {"mac", a.mac},
            {"ip", a.ip},
            {"status", a.status},
            {"dhcp", a.dhcp},
            {"dns", a.dns},
            {"gateway", a.gateway},
            {"sources", a.sources}
        });
    }

    std::cout << j.dump(4) << std::endl; // pretty-print JSON
}

int main(int argc, char* argv[]) {
    WSADATA wsa_data; // structure for WinSock initialization

    SetConsoleOutputCP(CP_UTF8); // enable UTF-8 output
    SetConsoleCP(CP_UTF8);
    std::locale::global(std::locale(""));

    // Initialize WinSock
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        std::cerr << "WinSock WSAStartup failed\n";
        return 1; // exit if initialization fails
    }

    // retrieve adapter information
    auto adapters = get_network_adapters_info();

    // if "--json" argument is provided, output JSON; otherwise CSV
    if (argc > 1 && std::string(argv[1]) == "--json") {
        print_adapters_json(adapters);
    } else {
        print_adapters_csv(adapters);
    }

    WSACleanup(); // cleanup WinSock
    return 0;
}
