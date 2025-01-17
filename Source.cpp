#include <iostream>
#include <windows.h>
#include <Lmcons.h>
#include <string>
#include <iomanip>
#include <vector>

#define RESET       "\033[0m"
#define BLUE        "\033[34m"
#define CYAN        "\033[36m"
#define GREEN       "\033[32m"
#define MAGENTA     "\033[35m"
#define YELLOW      "\033[33m"
#define RED         "\033[31m"

std::string getUserName() {
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    if (GetUserNameA(username, &username_len)) {
        return std::string(username);
    }
    return "Unknown";
}

std::string getHostName() {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD hostname_len = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameA(hostname, &hostname_len)) {
        return std::string(hostname);
    }
    return "Unknown";
}

std::string getOSName() {
    typedef LONG NTSTATUS;
    typedef struct _OSVERSIONINFOEXW {
        DWORD dwOSVersionInfoSize;
        DWORD dwMajorVersion;
        DWORD dwMinorVersion;
        DWORD dwBuildNumber;
        DWORD dwPlatformId;
        WCHAR szCSDVersion[128];
    } OSVERSIONINFOEXW;

    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(OSVERSIONINFOEXW*);
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (!hMod) return "Unknown OS";

    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
    if (!RtlGetVersion) return "Unknown OS";

    OSVERSIONINFOEXW osInfo = {};
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);
    if (RtlGetVersion(&osInfo) == 0) {
        if (osInfo.dwMajorVersion == 10 && osInfo.dwMinorVersion == 0 && osInfo.dwBuildNumber >= 22000) {
            return "Windows 11 (Build " + std::to_string(osInfo.dwBuildNumber) + ")";
        }
        return "Windows " + std::to_string(osInfo.dwMajorVersion) + "." + std::to_string(osInfo.dwMinorVersion) + " (Build " + std::to_string(osInfo.dwBuildNumber) + ")";
    }
    return "Unknown OS";
}

std::string getSystemArchitecture() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" : "x86";
}

std::string getProcessorName() {
    char buffer[256];
    DWORD buffer_size = sizeof(buffer);
    HKEY hKey;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr, (LPBYTE)buffer, &buffer_size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::string(buffer);
        }
        RegCloseKey(hKey);
    }
    return "Unknown Processor";
}

std::string getGPUName() {
    DISPLAY_DEVICEA dd;
    dd.cb = sizeof(dd);
    if (EnumDisplayDevicesA(nullptr, 0, &dd, 0)) {
        return std::string(dd.DeviceString);
    }
    return "Unknown GPU";
}

void getMemoryInfo(DWORDLONG& total, DWORDLONG& available) {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        total = memInfo.ullTotalPhys;
        available = memInfo.ullAvailPhys;
    }
    else {
        total = available = 0;
    }
}

std::pair<DWORDLONG, DWORDLONG> getTotalDiskSpace() {
    DWORDLONG totalSpace = 0, freeSpace = 0;
    char drives[256];
    GetLogicalDriveStringsA(sizeof(drives), drives);

    for (char* drive = drives; *drive; drive += strlen(drive) + 1) {
        ULARGE_INTEGER freeBytesAvailable, totalBytes;
        if (GetDiskFreeSpaceExA(drive, &freeBytesAvailable, &totalBytes, nullptr)) {
            totalSpace += totalBytes.QuadPart;
            freeSpace += freeBytesAvailable.QuadPart;
        }
    }
    return { totalSpace, freeSpace };
}

std::string getResolution() {
    RECT desktop;
    const HWND hDesktop = GetDesktopWindow();
    GetWindowRect(hDesktop, &desktop);
    int width = desktop.right;
    int height = desktop.bottom;
    return std::to_string(width) + "x" + std::to_string(height);
}

std::string getUptime() {
    DWORD uptime = GetTickCount64() / 1000;
    DWORD days = uptime / (24 * 3600);
    uptime %= (24 * 3600);
    DWORD hours = uptime / 3600;
    uptime %= 3600;
    DWORD minutes = uptime / 60;

    return std::to_string(days) + "d " + std::to_string(hours) + "h " + std::to_string(minutes) + "m";
}

std::string getShellName() {
    char* buffer = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buffer, &len, "ComSpec") == 0 && buffer != nullptr) {
        std::string shellName(buffer);
        free(buffer);
        size_t pos = shellName.find_last_of("\\");
        if (pos != std::string::npos) {
            return shellName.substr(pos + 1);
        }
        return shellName;
    }
    return "Unknown Terminal";
}

int main() {
    std::string username = getUserName();
    std::string hostname = getHostName();
    std::string osName = getOSName();
    std::string architecture = getSystemArchitecture();
    std::string processorName = getProcessorName();
    std::string gpuName = getGPUName();
    std::string resolution = getResolution();
    std::string uptime = getUptime();
    std::string shellName = getShellName();

    DWORDLONG totalRAM, availableRAM;
    getMemoryInfo(totalRAM, availableRAM);

    std::pair<DWORDLONG, DWORDLONG> diskSpace = getTotalDiskSpace();
    DWORDLONG totalStorage = diskSpace.first;
    DWORDLONG freeStorage = diskSpace.second;

    std::cout << BLUE;

    for (int i = 0; i < 5; i++) {

        for (int j = 0; j < 10; j++) {
            if (j == 5) {
                std::cout << " ";
            }
            std::cout << (char)219;
        }
        std::cout << "\n";
    }

    std::cout << "\t\t           " << osName << std::endl;

    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 10; j++) {
            if (j == 5) {
                std::cout << " ";
            }
            std::cout << (char)219;
        }
        std::cout << "\n";
    }

	std::cout << "\n";
    std::cout << RESET;

    std::cout << YELLOW << "User:           " << GREEN << username << RESET << std::endl;
    std::cout << CYAN << "OS:             " << RED << osName << RESET << std::endl;
    std::cout << MAGENTA << "Host:           " << GREEN << hostname << RESET << std::endl;
    std::cout << YELLOW << "Kernel:         " << RED << architecture << RESET << std::endl;
    std::cout << CYAN << "Uptime:         " << GREEN << uptime << RESET << std::endl;
    std::cout << MAGENTA << "Resolution:     " << RED << resolution << RESET << std::endl;
    std::cout << YELLOW << "Terminal:       " << GREEN << shellName << RESET << std::endl;
    std::cout << CYAN << "CPU:            " << RED << processorName << RESET << std::endl;
    std::cout << MAGENTA << "GPU:            " << GREEN << gpuName << RESET << std::endl;
    std::cout << YELLOW << "Total RAM:      " << RED << (totalRAM / (1024 * 1024)) << " MB" << RESET << std::endl;
    std::cout << CYAN << "Available RAM:  " << GREEN << (availableRAM / (1024 * 1024)) << " MB" << RESET << std::endl;
    std::cout << MAGENTA << "Total Storage:  " << RED << (totalStorage / (1024 * 1024 * 1024)) << " GB" << RESET << std::endl;
    std::cout << YELLOW << "Free Storage:   " << GREEN << (freeStorage / (1024 * 1024 * 1024)) << " GB" << RESET << std::endl;

	std::cout << std::endl;
    system("pause");

    return 0;
}
