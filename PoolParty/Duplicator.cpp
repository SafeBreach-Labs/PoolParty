#include "Duplicator.hpp"

WorkerFactoryHandleDuplicator::WorkerFactoryHandleDuplicator(DWORD dwTargetPid, HANDLE hTarget) 
	: dwTargetPid(dwTargetPid), hTargetPid(hTarget) {}

HANDLE WorkerFactoryHandleDuplicator::Duplicate(DWORD dwDesiredPermissions) {

	// TODO: Export to function and use smart pointers
	PSYSTEM_HANDLE_INFORMATION SystemHandleInformation = {0};
	ULONG SystemHandleInformationLength = 1024;
	NTSTATUS Ntstatus = STATUS_INFO_LENGTH_MISMATCH;

    do {
		SystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)realloc(SystemHandleInformation, SystemHandleInformationLength *= 2);

        if (SystemHandleInformationLength == NULL)
        {
			throw WindowsException("realloc");
        }

        Ntstatus = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, SystemHandleInformation, SystemHandleInformationLength, NULL);
    } while (Ntstatus == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(Ntstatus)) {
		throw WindowsException("NtQuerySystemInformation");
	}

    // Actual function

    ULONG HandleNumber = SystemHandleInformation->NumberOfHandles;
    HANDLE hDuplicated;
    ULONG ObjectInformationLength = 1024;
    PPUBLIC_OBJECT_TYPE_INFORMATION ObjectInformation = NULL;
    ULONG ReturnLength;

    for (int i = 0; i < HandleNumber; i++)
    {
        if (SystemHandleInformation->Handles[i].UniqueProcessId != this->dwTargetPid)
        {
            continue;
        }

        // TODO: Remove cast
        if (!DuplicateHandle(this->hTargetPid, (HANDLE)SystemHandleInformation->Handles[i].HandleValue, GetCurrentProcess(), &hDuplicated, dwDesiredPermissions, FALSE, NULL))
        {
            //printf("[-] Failed to duplicate handle\n"); 
            //GetError(L"DuplicateHandle");
            continue;
        }

        ObjectInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)malloc(ObjectInformationLength);
        if (ObjectInformation == NULL)
        {
            //printf("[-] Failed to malloc for NtQueryObject!\n");
            CloseHandle(hDuplicated);
            continue;
        }
        Ntstatus = NtQueryObject(hDuplicated, ObjectTypeInformation, ObjectInformation, ObjectInformationLength, &ReturnLength);
        if (!NT_SUCCESS(Ntstatus))
        {
            //GetError(L"NtQueryObject");
            CloseHandle(hDuplicated);
            free(ObjectInformation);
            continue;
        }

        if (wcscmp(L"TpWorkerFactory", ObjectInformation->TypeName.Buffer) != 0)
        {
            CloseHandle(hDuplicated);
            free(ObjectInformation);
            continue;
        }
        free(ObjectInformation);

        printf("[+] Duplicated TpWorkerFactory handle from remote process with PID: %d\n", this->dwTargetPid, hDuplicated);
        free(SystemHandleInformation);
        return hDuplicated;
    }

    free(SystemHandleInformation);
    printf("[-] No open handles with the desired permissions to PID %d found.\n", this->dwTargetPid);
    throw WindowsException("DuplicateHandle"); // TODO: Change exceptions
}

WorkerFactoryHandleDuplicator::~WorkerFactoryHandleDuplicator(){}
