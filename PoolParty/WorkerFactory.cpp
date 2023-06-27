#include "WorkerFactory.hpp"

void w_NtQueryInformationWorkerFactory(
    HANDLE hWorkerFactory,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, 
    PVOID WorkerFactoryInformation, 
    ULONG WorkerFactoryInformationLength, 
    PULONG ReturnLength
) 
{
    const auto Ntstatus = NtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryInformationClass, WorkerFactoryInformation, WorkerFactoryInformationLength, ReturnLength);
    if (!NT_SUCCESS(Ntstatus))
    {
        throw std::runtime_error(GetLastErrorString("NtQueryInformationWorkerFactory", RtlNtStatusToDosError(Ntstatus)));
    }
}

void w_NtSetInformationWorkerFactory(
    HANDLE hWorkerFactory,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
)
{
    const auto Ntstatus = NtSetInformationWorkerFactory(hWorkerFactory, WorkerFactoryInformationClass, WorkerFactoryInformation, WorkerFactoryInformationLength);
    if (!NT_SUCCESS(Ntstatus))
    {
        throw std::runtime_error(GetLastErrorString("NtSetInformationWorkerFactory", RtlNtStatusToDosError(Ntstatus)));
    }
}