#pragma once

#include <Windows.h>

#include "Misc.hpp"

// ------------//
// Proto types //
// ------------//

std::shared_ptr<HANDLE> w_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

std::shared_ptr<HANDLE> w_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);

std::shared_ptr<HANDLE> w_CreateEvent(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitalState, LPWSTR lpName);

std::shared_ptr<HANDLE> w_CreateFile(
	LPCWSTR lpFileName, 
	DWORD dwDesiredAccess, 
	DWORD dwShareMode, 
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
);

void w_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

std::shared_ptr<HANDLE> w_CreateJobObject(LPSECURITY_ATTRIBUTES lpJobAttributes, LPWSTR lpName);

void w_SetInformationJobObject(HANDLE hJob, JOBOBJECTINFOCLASS JobObjectInformationClass, LPVOID lpJobObjectInformation, DWORD cbJobObjectInformationLength);

void w_AssignProcessToJobObject(HANDLE hJob, HANDLE hProcess);

LPVOID w_VirtualAllocEx(HANDLE hTargetPid, SIZE_T szSizeOfChunk, DWORD dwAllocationType, DWORD dwProtect);

void w_WriteProcessMemory(HANDLE hTargetPid, LPVOID AllocatedMemory, LPVOID pBuffer, SIZE_T szSizeOfBuffer);

void w_SetEvent(HANDLE hEvent);

// ---------------//
// Error handlers //
// ---------------//

inline void RAISE_IF_FALSE(std::string FunctionName, BOOL Status)
{
	if (!Status)
	{
		throw std::runtime_error(GetLastErrorString(FunctionName, GetLastError()));
	}
}

inline HANDLE RAISE_IF_HANDLE_INVALID(std::string FunctionName, HANDLE hObject)
{
	if (NULL == hObject || INVALID_HANDLE_VALUE == hObject)
	{
		throw std::runtime_error(GetLastErrorString(FunctionName, GetLastError()));
	}
	return hObject;
}

// ----------//
// Templates //
// ----------//

template<typename TStruct>
std::unique_ptr<TStruct> w_ReadProcessMemory(HANDLE hTargetPid, LPVOID BaseAddress)
{
	auto Buffer = std::make_unique<TStruct>();
	auto BufferSize = sizeof(TStruct);
	SIZE_T szNumberOfBytesRead;
	RAISE_IF_FALSE(
		"ReadProcessMemory",
		ReadProcessMemory(
			hTargetPid, 
			BaseAddress, 
			Buffer.get(), 
			BufferSize, 
			&szNumberOfBytesRead)
	);

	if (BufferSize != szNumberOfBytesRead) {
		std::printf("WARNING: Read %d bytes instead of %d bytes\n", szNumberOfBytesRead, BufferSize);
	}

	return Buffer;
}