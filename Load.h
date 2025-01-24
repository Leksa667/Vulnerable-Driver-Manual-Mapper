#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <string>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <tuple>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")
using nt_load_driver_t = NTSTATUS(__fastcall*)(PUNICODE_STRING);
using nt_unload_driver_t = NTSTATUS(__fastcall*)(PUNICODE_STRING);

namespace driver
{
	namespace util
	{
		inline bool delete_service_entry(const std::string& service_name);
		inline bool create_service_entry(const std::string& drv_path, const std::string& service_name);
		inline bool enable_privilege(const std::string& privilege_name);
		inline std::string get_service_image_path(const std::string& service_name);

	}
	std::tuple<NTSTATUS, std::string> load(const std::string& drv_path, const std::string& service_name);
	std::tuple<NTSTATUS, std::string> load(const std::vector<std::uint8_t>& drv_buffer);
	std::tuple<NTSTATUS, std::string> load(const std::uint8_t* buffer, const std::size_t size);
	std::tuple<NTSTATUS, std::string> load(const std::uint8_t* buffer, const std::size_t size, const std::string& service_name);
	bool unload(const std::string& service_name);
}