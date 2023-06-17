#pragma once

#include <Windows.h>

#include "Exceptions.hpp"
#include <memory>


// ------------//
// Proto types //
// ------------//

// TODO: Should I name it with w_ suffix as well?

LPVOID AllocateMemory(HANDLE hTargetPid, SIZE_T szSizeOfChunk, DWORD dwAllocationType, DWORD dwProtect);
void WriteMemory(HANDLE hTargetPid, LPVOID AllocatedMemory, LPVOID pBuffer, SIZE_T szSizeOfBuffer);


template<typename T> std::unique_ptr<T> ReadMemory(HANDLE hTargetPid, LPVOID BaseAddress)
{
	auto Buffer = std::make_unique<T>();
	auto BufferSize = sizeof(T);
	SIZE_T szNumberOfBytesRead;
	if (!ReadProcessMemory(hTargetPid, BaseAddress, Buffer.get(), BufferSize, &szNumberOfBytesRead)) {
		throw WindowsException("ReadProcessMemory");
	}
	
	if (BufferSize != szNumberOfBytesRead) {
		std::printf("WARNING: Read %d bytes instead of %d bytes\n", szNumberOfBytesRead, BufferSize);
	}

	return Buffer;
}
