#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <tuple>
#include <cmath>

std::string get_disk_volume_serial_number()
{
    char volumeName[MAX_PATH + 1] = { 0 };
    char fileSystemName[MAX_PATH + 1] = { 0 };
    DWORD serialNumber = 0;
    DWORD maxComponentLength = 0;
    DWORD fileSystemFlags = 0;

    if (GetVolumeInformationA( ("C:\\"), volumeName, ARRAYSIZE(volumeName),
        &serialNumber, &maxComponentLength, &fileSystemFlags,
        fileSystemName, ARRAYSIZE(fileSystemName)))
    {
        std::string serialNumberStr = std::to_string(serialNumber);

        return serialNumberStr;
    }
    else
    {
        DWORD error = GetLastError();
        std::cerr <<  ("Failed to get volume information. Error code: ") << error << std::endl;
        return "";
    }
}