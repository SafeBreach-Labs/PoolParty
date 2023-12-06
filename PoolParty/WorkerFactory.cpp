#include "WorkerFactory.hpp"

void w_NtQueryInformationWorkerFactory(
    HANDLE hWorkerFactory,
    QUERY_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, 
    PVOID WorkerFactoryInformation, 
    ULONG WorkerFactoryInformationLength, 
    PULONG ReturnLength
) 
{
    NT_SUCCESS_OR_RAISE(
        "NtQueryInformationWorkerFactory",
        NtQueryInformationWorkerFactory(
            hWorkerFactory, 
            WorkerFactoryInformationClass, 
            WorkerFactoryInformation, 
            WorkerFactoryInformationLength, 
            ReturnLength)
    );
}

void w_NtSetInformationWorkerFactory(
    HANDLE hWorkerFactory,
    SET_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
)
{
    NT_SUCCESS_OR_RAISE(
        "NtSetInformationWorkerFactory", 
        NtSetInformationWorkerFactory(
            hWorkerFactory, 
            WorkerFactoryInformationClass, 
            WorkerFactoryInformation, 
            WorkerFactoryInformationLength)
    );
}