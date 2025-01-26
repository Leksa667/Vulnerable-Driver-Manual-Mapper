#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <tuple>
#include <cmath>
#include <Winternl.h>
#include "Utils.h"
#include <ntstatus.h>
#include <vector>
#include <memory>
#include <filesystem>
#include "Load.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

namespace driver
{
	namespace util
	{
		inline bool delete_service_entry(const std::string& service_name)
		{
			HKEY reg_handle;
			static const std::string reg_key( ("System\\CurrentControlSet\\Services\\"));

			auto result = RegOpenKeyA(HKEY_LOCAL_MACHINE, reg_key.c_str(), &reg_handle);

			if (result != ERROR_SUCCESS)
			{
				std::cerr <<  ("[ERROR] Failed to open registry key for deletion : ") << result << std::endl;
				return false;
			}

			bool success = ERROR_SUCCESS == RegDeleteKeyA(reg_handle, service_name.data());
			RegCloseKey(reg_handle);
			return success;
		}

		inline bool create_service_entry(const std::string& drv_path, const std::string& service_name)
		{
			HKEY reg_handle;
			std::string reg_key( ("System\\CurrentControlSet\\Services\\"));
			reg_key += service_name;

			auto result = RegCreateKeyA(HKEY_LOCAL_MACHINE, reg_key.c_str(), &reg_handle);

			if (result != ERROR_SUCCESS)
			{
				std::cerr <<  ("[ERROR] Failed to create registry key for service : ") << service_name << std::endl;
				return false;
			}
			constexpr std::uint8_t type_value = 1;
			if (RegSetValueExA(reg_handle,  ("Type"), NULL, REG_DWORD, &type_value, 4u) != ERROR_SUCCESS)
			{
				std::cerr <<  ("[ERROR] Failed to set 'Type' value.") << std::endl;
				return false;
			}

			constexpr std::uint8_t error_control_value = 3;
			if (RegSetValueExA(reg_handle,  ("ErrorControl"), NULL, REG_DWORD, &error_control_value, 4u) != ERROR_SUCCESS)
			{
				std::cerr <<  ("[ERROR] Failed to set 'ErrorControl' value.") << std::endl;
				return false;
			}

			constexpr std::uint8_t start_value = 3;
			if (RegSetValueExA(reg_handle,  ("Start"), NULL, REG_DWORD, &start_value, 4u) != ERROR_SUCCESS)
			{
				std::cerr <<  ("[ERROR] Failed to set 'Start' value.") << std::endl;
				return false;
			}

			if (RegSetValueExA(reg_handle,  ("ImagePath"), NULL, REG_SZ, (std::uint8_t*)drv_path.c_str(), drv_path.size()) != ERROR_SUCCESS)
			{
				std::cerr <<  ("[ERROR] Failed to set 'ImagePath' value.") << std::endl;
				return false;
			}
			return ERROR_SUCCESS == RegCloseKey(reg_handle);
		}

		inline bool enable_privilege(const std::string& privilege_name)
		{
			HANDLE token_handle = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
			{
				std::cerr <<  ("[ERROR] Failed to open process token.") << std::endl;
				return false;
			}

			LUID luid{};
			if (!LookupPrivilegeValueA(nullptr, privilege_name.data(), &luid))
			{
				std::cerr <<  ("[ERROR] Failed to lookup privilege value : ") << privilege_name << std::endl;
				CloseHandle(token_handle);
				return false;
			}

			TOKEN_PRIVILEGES token_state{};
			token_state.PrivilegeCount = 1;
			token_state.Privileges[0].Luid = luid;
			token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (!AdjustTokenPrivileges(token_handle, FALSE, &token_state, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
			{
				std::cerr <<  ("[ERROR] Failed to adjust token privileges.") << std::endl;
				CloseHandle(token_handle);
				return false;
			}

			CloseHandle(token_handle);
			return true;
		}

		inline std::string get_service_image_path(const std::string& service_name)
		{
			HKEY reg_handle;
			DWORD bytes_read;
			char image_path[0xFF] = { 0 };
			static const std::string reg_key( ("System\\CurrentControlSet\\Services\\"));

			auto result = RegOpenKeyA(HKEY_LOCAL_MACHINE, reg_key.c_str(), &reg_handle);

			if (result != ERROR_SUCCESS)
			{
				std::cerr <<  ("[ERROR] Failed to open registry key to get image path for : ") << service_name << std::endl;
				return {};
			}

			result = RegGetValueA(reg_handle, service_name.c_str(),  ("ImagePath"), REG_SZ, NULL, image_path, &bytes_read);

			RegCloseKey(reg_handle);

			if (result != ERROR_SUCCESS)
			{
				std::cerr <<  ("[ERROR] Failed to get 'ImagePath' for service : ") << service_name << std::endl;
				return {};
			}
			return std::string(image_path);
		}
	}
	std::tuple<NTSTATUS, std::string> load(const std::string& drv_path, const std::string& service_name)
	{
		if (!util::enable_privilege( ("SeLoadDriverPrivilege")))
		{
			std::cerr <<  ("[ERROR] Failed to enable 'SeLoadDriverPrivilege'.") << std::endl;
			return { STATUS_PRIVILEGE_NOT_HELD, "" };
		}

		if (!util::create_service_entry( ("\\??\\") + std::filesystem::absolute(std::filesystem::path(drv_path)).string(), service_name))
		{
			std::cerr <<  ("[ERROR] Failed to create service entry.") << std::endl;
			return { STATUS_OBJECT_NAME_NOT_FOUND, "" };
		}

		std::string reg_path( ("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"));
		reg_path += service_name;

		static const auto lp_nt_load_drv =
			::GetProcAddress(GetModuleHandleA( ("ntdll.dll")),  ("NtLoadDriver"));

		if (lp_nt_load_drv)
		{
			ANSI_STRING driver_rep_path_cstr;
			UNICODE_STRING driver_reg_path_unicode;

			RtlInitAnsiString(&driver_rep_path_cstr, reg_path.c_str());
			RtlAnsiStringToUnicodeString(&driver_reg_path_unicode, &driver_rep_path_cstr, true);
			auto status = reinterpret_cast<nt_load_driver_t>(lp_nt_load_drv)(&driver_reg_path_unicode);
			RtlFreeUnicodeString(&driver_reg_path_unicode);
			if (!NT_SUCCESS(status))
				std::cerr <<  ("[ERROR] Failed to load driver, NTSTATUS : ") << std::hex << status << std::dec <<  ("\n");


			return { status,service_name };
		}

		std::cerr <<  ("[ERROR] NtLoadDriver function not found.\n");
		return { STATUS_PROCEDURE_NOT_FOUND, "" };
	}

	std::tuple<NTSTATUS, std::string> load(const std::vector<std::uint8_t>& drv_buffer)
	{
		static const auto random_file_name = [](std::size_t length) -> std::string
			{
				static const auto randchar = []() -> char
					{
						const char charset[] =
							"0123456789"
							"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
							"abcdefghijklmnopqrstuvwxyz";
						const std::size_t max_index = (sizeof(charset) - 1);
						return charset[rand() % max_index];
					};
				std::string str(length, 0);
				std::generate_n(str.begin(), length, randchar);
				return str;
			};

		const auto service_name = random_file_name(16);
		const auto file_path = std::filesystem::temp_directory_path().string() + random_file_name(16);
		std::ofstream output_file(file_path.c_str(), std::ios::binary);

		output_file.write((char*)drv_buffer.data(), drv_buffer.size());
		output_file.close();

		return load(file_path, service_name);
	}
	std::tuple<NTSTATUS, std::string> load(const std::uint8_t* buffer, const std::size_t size)
	{
		std::vector<std::uint8_t> image(buffer, buffer + size);
		return load(image);
	}

	std::tuple<NTSTATUS, std::string> load(const std::uint8_t* buffer, const std::size_t size, const std::string& service_name)
	{
		static const auto random_file_name = [](std::size_t length) -> std::string
			{
				static const auto randchar = []() -> char
					{
						const char charset[] =
							"0123456789"
							"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
							"abcdefghijklmnopqrstuvwxyz";
						const std::size_t max_index = (sizeof(charset) - 1);
						return charset[rand() % max_index];
					};
				std::string str(length, 0);
				std::generate_n(str.begin(), length, randchar);
				return str;
			};

		const auto file_path = std::filesystem::temp_directory_path().string() + random_file_name(16);
		std::ofstream output_file(file_path.c_str(), std::ios::binary);

		output_file.write((char*)buffer, size);
		output_file.close();

		return load(file_path, service_name);
	}

	bool unload(const std::string& service_name)
	{
		std::string reg_path( ("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"));
		reg_path += service_name;

		static const auto lp_nt_unload_drv =
			::GetProcAddress(
				GetModuleHandleA( ("ntdll.dll")),
				 ("NtUnloadDriver")
			);

		if (lp_nt_unload_drv)
		{
			ANSI_STRING driver_rep_path_cstr;
			UNICODE_STRING driver_reg_path_unicode;

			RtlInitAnsiString(&driver_rep_path_cstr, reg_path.c_str());
			RtlAnsiStringToUnicodeString(&driver_reg_path_unicode, &driver_rep_path_cstr, true);

			const auto unload_status = reinterpret_cast<nt_unload_driver_t>(lp_nt_unload_drv)(&driver_reg_path_unicode);
			const auto last_error = GetLastError();

			RtlFreeUnicodeString(&driver_reg_path_unicode);

			const bool delete_reg = util::delete_service_entry(service_name);

			const auto image_path = std::filesystem::temp_directory_path().string() + service_name;


			try
			{
				std::ofstream test_lock(image_path, std::ios::app);
				if (test_lock.is_open())
				{
					test_lock.close();
					std::filesystem::remove(image_path);


				}
				else {
					std::cerr <<  ("[ERROR] Failed To Remove Temp Files or lock , GetLastError was :  ") << GetLastError() <<  ("\n");
					return false;

				}


			}
			catch (const std::exception& e) {
				std::cerr <<  ("[ERROR] Exeception On Removing File :  ") << e.what() <<  ("\n");
				return false;
			}


			return delete_reg;


		}
		std::cerr <<  ("[ERROR] NtUnloadDriver function was not  found  !! (can not unload at all).");

		return false;
	}
}