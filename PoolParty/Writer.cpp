#include "Writer.h"

void WriteMemory(HANDLE hTargetPid, LPVOID AllocatedMemory, char* cBuffer, SIZE_T szSizeOfShellcode) {
	if (!WriteProcessMemory(hTargetPid, AllocatedMemory, cBuffer, szSizeOfShellcode, NULL)) {
		throw WindowsException("WriteProcessMemory");
	}
}