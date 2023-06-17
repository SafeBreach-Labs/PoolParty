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
        throw WindowsException("NtQueryInformationWorkerFactory"); // TODO: Convert to NativeWindowsException which will display status string representation
    }
}