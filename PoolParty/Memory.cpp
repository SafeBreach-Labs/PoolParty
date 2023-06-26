#include "Memory.hpp"


LPVOID AllocateMemory(HANDLE hTargetPid, SIZE_T szSizeOfChunk, DWORD dwAllocationType, DWORD dwProtect) {
	auto AllocatedMemory = VirtualAllocEx(hTargetPid, NULL, szSizeOfChunk, dwAllocationType, dwProtect);
	if (AllocatedMemory == NULL) {
		throw std::runtime_error(GetLastErrorString("VirtualAllocEx", GetLastError()));
	}
	return AllocatedMemory;
}

void WriteMemory(HANDLE hTargetPid, LPVOID AllocatedMemory, LPVOID pBuffer, SIZE_T szSizeOfBuffer) {
	if (!WriteProcessMemory(hTargetPid, AllocatedMemory, pBuffer, szSizeOfBuffer, NULL)) {
		throw std::runtime_error(GetLastErrorString("WriteProcessMemory", GetLastError()));
	}
}

