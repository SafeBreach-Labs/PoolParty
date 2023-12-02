#include "WorkerFactory.hpp"

void w_NtQueryInformationWorkerFactory(
    HANDLE hWorkerFactory,
    QUERY_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, 
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
    SET_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
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

void w_NtReleaseWorkerFactoryWorker(
    HANDLE hWorkerFactory
) 
{
    const auto Ntstatus = NtReleaseWorkerFactoryWorker(hWorkerFactory);
    if (!NT_SUCCESS(Ntstatus))
    {
        throw std::runtime_error(GetLastErrorString("NtReleaseWorkerFactoryWorker", RtlNtStatusToDosError(Ntstatus)));
    }
}