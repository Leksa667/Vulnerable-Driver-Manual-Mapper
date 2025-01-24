#pragma once
#include <cstdint>
#include <optional>
#include <Windows.h>

namespace KernelUtils
{
    std::optional<uint64_t> get_ntoskrnl_base();
    std::optional<uint64_t> get_se_validate_image_header_offset();
    std::optional<uint64_t> get_se_validate_image_data_offset();
    std::optional<uint64_t> get_return_offset();
    std::optional<uint64_t> get_patch_gaurd_offset();
    std::optional<uint64_t> get_patch_gaurd_value_offset();
}