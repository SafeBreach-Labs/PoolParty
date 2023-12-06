#include "WinApi.hpp"

std::shared_ptr<HANDLE> w_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
	const auto hTargetPid = RAISE_IF_HANDLE_INVALID(
		"OpenProcess", 
		OpenProcess(
			dwDesiredAccess, 
			bInheritHandle, 
			dwProcessId)
	);

	return std::shared_ptr<HANDLE>(new HANDLE(hTargetPid), [](HANDLE* p_handle) {CloseHandle(*p_handle); });
}

std::shared_ptr<HANDLE> w_DuplicateHandle(
	HANDLE hSourceProcessHandle,
	HANDLE hSourceHandle,
	HANDLE hTargetProcessHandle,
	DWORD dwDesiredAccess, 
	BOOL bInheritHandle,
	DWORD dwOptions)
{
	HANDLE hTargetHandle;
	RAISE_IF_FALSE(
		"DuplicateHandle",
		DuplicateHandle(
			hSourceProcessHandle,
			hSourceHandle,
			hTargetProcessHandle,
			&hTargetHandle,
			dwDesiredAccess,
			bInheritHandle,
			dwOptions)
	);

	return std::shared_ptr<HANDLE>(new HANDLE(hTargetHandle), [](HANDLE* p_handle) {CloseHandle(*p_handle); });
}

std::shared_ptr<HANDLE> w_CreateEvent(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitalState, LPWSTR lpName)
{
	const auto hEvent = RAISE_IF_HANDLE_INVALID(
		"CreateEvent",
		CreateEvent(
			lpEventAttributes,
			bManualReset,
			bInitalState,
			lpName)
	);
	
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		std::printf("WARNING: The event `%S` already exists\n", lpName);
	}

	return std::shared_ptr<HANDLE>(new HANDLE(hEvent), [](HANDLE* p_handle){CloseHandle(*p_handle);});
}

std::shared_ptr<HANDLE> w_CreateFile(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	const auto hFile = RAISE_IF_HANDLE_INVALID(
		"CreateFile",
		CreateFile(
			lpFileName, 
			dwDesiredAccess, 
			dwShareMode, 
			lpSecurityAttributes, 
			dwCreationDisposition, 
			dwFlagsAndAttributes, 
			hTemplateFile)
	);

	return std::shared_ptr<HANDLE>(new HANDLE(hFile), [](HANDLE* p_handle) {CloseHandle(*p_handle); });
}

void w_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
	if (!WriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)) 
	{

		/* file flag overlapped wont return true, yet the operation wont fail */
		if (lpOverlapped)
		{
			if (GetLastError() == ERROR_IO_PENDING) 
			{
				return;
			}
		}
		throw std::runtime_error(GetLastErrorString("WriteFile", GetLastError()));
	}

}

std::shared_ptr<HANDLE> w_CreateJobObject(LPSECURITY_ATTRIBUTES lpJobAttributes, LPWSTR lpName)
{
	const auto hJob = RAISE_IF_HANDLE_INVALID("CreateJobObject",
		CreateJobObject(
			lpJobAttributes,
			lpName)
	);

	if (GetLastError() == ERROR_ALREADY_EXISTS) 
	{
		std::printf("WARNING: The job `%S` already exists\n", lpName);
	}

	return std::shared_ptr<HANDLE>(new HANDLE(hJob), [](HANDLE* p_handle) {CloseHandle(*p_handle); });
}

void w_SetInformationJobObject(HANDLE hJob, JOBOBJECTINFOCLASS JobObjectInformationClass, LPVOID lpJobObjectInformation, DWORD cbJobObjectInformationLength)
{
	RAISE_IF_FALSE(
		"SetInformationJobObject",
		SetInformationJobObject(
			hJob, 
			JobObjectInformationClass, 
			lpJobObjectInformation, 
			cbJobObjectInformationLength)
	);

}

void w_AssignProcessToJobObject(HANDLE hJob, HANDLE hProcess)
{
	RAISE_IF_FALSE(
		"AssignProcessToJobObject",
		AssignProcessToJobObject(
			hJob, 
			hProcess)
	);
}

// TODO: Figure out including this in the error handlers
LPVOID w_VirtualAllocEx(HANDLE hTargetPid, SIZE_T szSizeOfChunk, DWORD dwAllocationType, DWORD dwProtect)
{
	const auto AllocatedMemory = VirtualAllocEx(hTargetPid, nullptr , szSizeOfChunk, dwAllocationType, dwProtect);
	if (AllocatedMemory == NULL) 
	{
		throw std::runtime_error(GetLastErrorString("VirtualAllocEx", GetLastError()));
	}
	return AllocatedMemory;
}

// TODO: Add check for lpNumberOfBytesWritten
void w_WriteProcessMemory(HANDLE hTargetPid, LPVOID AllocatedMemory, LPVOID pBuffer, SIZE_T szSizeOfBuffer)
{
	RAISE_IF_FALSE(
		"WriteProcessMemory", 
		WriteProcessMemory(
			hTargetPid, 
			AllocatedMemory, 
			pBuffer, 
			szSizeOfBuffer, 
			nullptr)
	);
}

void w_SetEvent(HANDLE hEvent)
{
	RAISE_IF_FALSE(
		"SetEvent",
		SetEvent(
			hEvent
		)
	);
}
