#pragma once
#include "Scan.h"
#include "Utils.h"
#include "Load.h"
#include "Secure.h"

namespace Contourne
{
    enum class Status : int {
        FAILED_LOADING_VULN,
        FAILED_DISABLE_PG,
        FAILED_DISABLED_SE,
        FAILED_LOADING_DRV,
        SUCCESS,
    };


    extern ULONG64 SeValidateImageDataOffset;
    extern ULONG64 SeValidateImageHeaderOffset;
    extern ULONG64 RetOffset;
    extern ULONG64 NtoskrnlBaseAddress;
    extern ULONG64 PatchgaurdValueOffset;
    extern ULONG64 PatchgaurdOffset;
    extern HANDLE  VulnurableDriverHandle;

    bool init();

    bool disable_dse();
    bool disable_pg();

    bool load_vuld(const std::string& pdfw_krnl_path, const std::string& pdfw_krnl_service_name);

    Status load_driver(const std::string& driver_service_name, const std::string& pdfw_krnl_service_name);

    std::string status_to_string(Status status);
}