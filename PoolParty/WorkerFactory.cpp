#include "WorkerFactory.hpp"

void w_NtQueryInformationWorkerFactory(
    HANDLE hWorkerFactory,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, 
    PVOID WorkerFactoryInformation, 
    ULONG WorkerFactoryInformationLength, 
    PULONG ReturnLength
) 
{
    auto Ntstatus = NtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryInformationClass, WorkerFactoryInformation, WorkerFactoryInformationLength, ReturnLength);
    if (!NT_SUCCESS(Ntstatus))
    {
        throw std::runtime_error(GetLastErrorString("NtQueryInformationWorkerFactory")); // TODO: Convert to NativeWindowsException which will display status string representation
    }
}

void w_NtSetInformationWorkerFactory(
    HANDLE hWorkerFactory,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
)
{
    auto Ntstatus = NtSetInformationWorkerFactory(hWorkerFactory, WorkerFactoryInformationClass, WorkerFactoryInformation, WorkerFactoryInformationLength);
    if (!NT_SUCCESS(Ntstatus))
    {
        throw std::runtime_error(GetLastErrorString("NtSetInformationWorkerFactory")); // TODO: Convert to NativeWindowsException which will display status string representation
    }
}