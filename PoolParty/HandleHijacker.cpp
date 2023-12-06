#include "HandleHijacker.hpp"


std::shared_ptr<HANDLE> HijackProcessHandle(std::wstring wsObjectType, std::shared_ptr<HANDLE> p_hTarget, DWORD dwDesiredAccess)
{
    auto pProcessInformation = w_QueryInformation<decltype(NtQueryInformationProcess), HANDLE, PROCESSINFOCLASS>("NtQueryInformationProcess", NtQueryInformationProcess, *p_hTarget, static_cast<PROCESSINFOCLASS>(ProcessHandleInformation));
    const auto pProcessHandleInformation = reinterpret_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(pProcessInformation.data());

	std::shared_ptr<HANDLE> p_hDuplicatedObject;
    std::vector<BYTE> pObjectInformation;
    PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation;

    for (auto i = 0; i < pProcessHandleInformation->NumberOfHandles; i++)
    {
        try {

            p_hDuplicatedObject = w_DuplicateHandle(
                *p_hTarget,
                pProcessHandleInformation->Handles[i].HandleValue,
                GetCurrentProcess(),
                dwDesiredAccess,
                FALSE,
                NULL);

            pObjectInformation = w_QueryInformation<decltype(NtQueryObject), HANDLE, OBJECT_INFORMATION_CLASS>("NtQueryObject", NtQueryObject, *p_hDuplicatedObject, ObjectTypeInformation);
            pObjectTypeInformation = reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(pObjectInformation.data());

            if (wsObjectType != std::wstring(pObjectTypeInformation->TypeName.Buffer)) {
                continue;
            }

            return p_hDuplicatedObject;
        }
        catch (std::runtime_error){}
    }

    throw std::runtime_error("Failed to hijack object handle");
}

std::shared_ptr<HANDLE> HijackWorkerFactoryProcessHandle(std::shared_ptr<HANDLE> p_hTarget)
{
    return HijackProcessHandle(std::wstring(L"TpWorkerFactory"), p_hTarget, WORKER_FACTORY_ALL_ACCESS);
}

std::shared_ptr<HANDLE> HijackIoCompletionProcessHandle(std::shared_ptr<HANDLE> p_hTarget)
{
    return HijackProcessHandle(std::wstring(L"IoCompletion"), p_hTarget, IO_COMPLETION_ALL_ACCESS);
}

std::shared_ptr<HANDLE> HijackIRTimerProcessHandle(std::shared_ptr<HANDLE> p_hTarget)
{
    return HijackProcessHandle(std::wstring(L"IRTimer"), p_hTarget, TIMER_ALL_ACCESS);
}

