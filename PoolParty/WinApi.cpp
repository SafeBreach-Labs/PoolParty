#include "WinApi.hpp"

std::shared_ptr<HANDLE> w_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
	auto hTargetPid = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	if (hTargetPid == NULL || hTargetPid == INVALID_HANDLE_VALUE) {
		throw std::runtime_error(GetLastErrorString("OpenProcess"));
	}
	return std::shared_ptr<HANDLE>(new HANDLE(hTargetPid), HandleDeleter());
}

std::shared_ptr<HANDLE> w_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
	HANDLE hTargetHandle;
	if (!DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, &hTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions)) {
		throw std::runtime_error(GetLastErrorString("DuplicateHandle"));
	}
	return std::shared_ptr<HANDLE>(new HANDLE(hTargetHandle), HandleDeleter());
}

std::shared_ptr<HANDLE> w_CreateEvent(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitalState, LPWSTR lpName) {
	auto hEvent = CreateEvent(lpEventAttributes, bManualReset, bInitalState, lpName);
	if (hEvent == NULL) {
		throw std::runtime_error(GetLastErrorString("CreateEvent"));
	}
	
	/* Making sure the consumer is aware of existing events */
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		std::printf("WARNING: The event `%S` already exists\n", lpName);
	}

	return std::shared_ptr<HANDLE>(new HANDLE(hEvent), HandleDeleter());
}

std::shared_ptr<HANDLE> w_CreateFile(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
) {
	auto hFile = CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	if (hFile == INVALID_HANDLE_VALUE) {
		throw std::runtime_error(GetLastErrorString("CreateFile"));
	}

	return std::shared_ptr<HANDLE>(new HANDLE(hFile), HandleDeleter());
}

void w_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	if (!WriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)) 
	{

		/* Making sure to handle file flag overlapped */
		if (lpOverlapped)
		{
			if (GetLastError() == ERROR_IO_PENDING) 
			{
				return;
			}
		}
		throw std::runtime_error(GetLastErrorString("WriteFile"));
	}

}

std::shared_ptr<HANDLE> w_CreateJobObject(LPSECURITY_ATTRIBUTES lpJobAttributes, LPWSTR lpName)
{
	auto hJob = CreateJobObject(lpJobAttributes, lpName);
	if (hJob == NULL) {
		throw std::runtime_error(GetLastErrorString("CreateJobObject"));
	}

	/* Making sure the consumer is aware of existing job objects */
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		std::printf("WARNING: The job `%S` already exists\n", lpName);
	}

	return std::shared_ptr<HANDLE>(new HANDLE(hJob), HandleDeleter());
}

void w_SetInformationJobObject(HANDLE hJob, JOBOBJECTINFOCLASS JobObjectInformationClass, LPVOID lpJobObjectInformation, DWORD cbJobObjectInformationLength)
{
	if (!SetInformationJobObject(hJob, JobObjectInformationClass, lpJobObjectInformation, cbJobObjectInformationLength)) {
		throw std::runtime_error(GetLastErrorString("SetInformationJobObject"));
	}
}

void w_AssignProcessToJobObject(HANDLE hJob, HANDLE hProcess)
{
	if (!AssignProcessToJobObject(hJob, hProcess)) {
		throw std::runtime_error(GetLastErrorString("AssignProcessToJobObject"));
	}
}
