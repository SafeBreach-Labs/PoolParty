/*
	WinApi wrappers file
	Contains WinApi functions wrappers that enables clarity for whoever uses it and makes usage much more convinient
*/

#pragma once

#include <Windows.h>

#include "Exceptions.hpp"

// TODO: Export to a file

class HandleDeleter
{
public:
	void operator()(HANDLE* handle);
};

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
