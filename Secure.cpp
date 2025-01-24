#include "Secure.h"
#include "SkCrypt.h"
#include <iostream>


namespace Secure
{
    BOOL WINAPI ReadVirtualMemory(
        _In_ HANDLE DeviceHandle,
        _In_ ULONG_PTR Address,
        _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
        _In_ ULONG NumberOfBytes)
    {
        if (DeviceHandle == INVALID_HANDLE_VALUE)
        {
            std::cerr << "[ERROR] ReadVirtualMemory : Invalid device handle." << std::endl;
            return FALSE;
        }

        PDFW_MEMCPY request;
        RtlSecureZeroMemory(&request, sizeof(request));

        request.Destination = Buffer;
        request.Source = (PVOID)Address;
        request.Size = NumberOfBytes;

        DWORD bytes_returned;

        BOOL status = DeviceIoControl(
            DeviceHandle,
            IOCTL_AMDPDFW_MEMCPY,
            &request,
            sizeof(request),
            &request,
            sizeof(request),
            &bytes_returned, NULL
        );

        if (!status)
        {
            std::cerr << "[ERROR] ReadVirtualMemory : DeviceIoControl failed with error code : " << GetLastError() << std::endl;
        }
        return status;
    }

    BOOL WINAPI WriteVirtualMemory(
        _In_ HANDLE DeviceHandle,
        _In_ ULONG_PTR Address,
        _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
        _In_ ULONG NumberOfBytes)
    {
        if (DeviceHandle == INVALID_HANDLE_VALUE)
        {
            std::cerr << "[ERROR] WriteVirtualMemory : Invalid device handle." << std::endl;
            return FALSE;
        }
        PDFW_MEMCPY request;

        RtlSecureZeroMemory(&request, sizeof(request));

        request.Destination = (PVOID)Address;
        request.Source = Buffer;
        request.Size = NumberOfBytes;

        DWORD bytes_returned;

        BOOL status = DeviceIoControl(
            DeviceHandle,
            IOCTL_AMDPDFW_MEMCPY,
            &request,
            sizeof(request),
            &request,
            sizeof(request),
            &bytes_returned,
            NULL
        );
        if (!status)
        {
            std::cerr << "[ERROR] WriteVirtualMemory : DeviceIoControl failed with error code : " << GetLastError() << std::endl;
        }
        return status;
    }
}