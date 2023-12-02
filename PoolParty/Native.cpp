#include "Native.hpp"

void w_ZwAssociateWaitCompletionPacket(
    HANDLE WaitCopmletionPacketHandle,
    HANDLE IoCompletionHandle,
    HANDLE TargetObjectHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation,
    PBOOLEAN AlreadySignaled
) 
{
    const auto Ntstatus = ZwAssociateWaitCompletionPacket(
        WaitCopmletionPacketHandle,
        IoCompletionHandle,
        TargetObjectHandle,
        KeyContext, 
        ApcContext,
        IoStatus,
        IoStatusInformation,
        AlreadySignaled);
    if (!NT_SUCCESS(Ntstatus)) 
    {
        throw std::runtime_error(GetLastErrorString("ZwAssociateWaitCompletionPacket", RtlNtStatusToDosError(Ntstatus)));
    }
}

void w_ZwSetInformationFile(
    HANDLE hFile,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass
)
{
    const auto Ntstatus = ZwSetInformationFile(hFile, IoStatusBlock, FileInformation, Length, FileInformationClass);
    if (!NT_SUCCESS(Ntstatus))
    {
        throw std::runtime_error(GetLastErrorString("ZwSetInformationFile", RtlNtStatusToDosError(Ntstatus)));
    }
}

HANDLE w_NtAlpcCreatePort(POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes) {
    HANDLE hAlpc;
    const auto Ntstatus = NtAlpcCreatePort(&hAlpc, ObjectAttributes, PortAttributes);
    if (!NT_SUCCESS(Ntstatus))
    {
        throw std::runtime_error(GetLastErrorString("NtAlpcCreatePort", RtlNtStatusToDosError(Ntstatus)));
    }

    return hAlpc;
}

void w_NtAlpcSetInformation(HANDLE hAlpc, ULONG PortInformationClass, PVOID PortInformation, ULONG Length) 
{
    const auto Ntstatus = NtAlpcSetInformation(hAlpc, PortInformationClass, PortInformation, Length);
    if (!NT_SUCCESS(Ntstatus))
    {
        throw std::runtime_error(GetLastErrorString("NtAlpcSetInformation", RtlNtStatusToDosError(Ntstatus)));
    }
}


HANDLE w_NtAlpcConnectPort(
    PUNICODE_STRING PortName,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes,
    DWORD ConnectionFlags,
    PSID RequiredServerSid,
    PPORT_MESSAGE ConnectionMessage,
    PSIZE_T ConnectMessageSize,
    PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    PLARGE_INTEGER Timeout
) 
{
    HANDLE hAlpc;
    const auto Ntstatus = NtAlpcConnectPort(
        &hAlpc,
        PortName, 
        ObjectAttributes,
        PortAttributes,
        ConnectionFlags, 
        RequiredServerSid,
        ConnectionMessage,
        ConnectMessageSize,
        OutMessageAttributes,
        InMessageAttributes, 
        Timeout);
    if (!NT_SUCCESS(Ntstatus)) 
    {
        throw std::runtime_error(GetLastErrorString("NtAlpcConnectPort", RtlNtStatusToDosError(Ntstatus)));
    }

    return hAlpc;
}

BOOLEAN w_RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread)
{
    BOOLEAN Enabled = NULL;
    const auto Ntstatus = RtlAdjustPrivilege(Privilege, Enable, CurrentThread, &Enabled);
    if (!NT_SUCCESS(Ntstatus))
    {
        throw std::runtime_error(GetLastErrorString("RtlAdjustPrivilege", RtlNtStatusToDosError(Ntstatus)));
    }
    return Enabled;
}

void w_ZwSetIoCompletion(HANDLE IoCompletionHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, ULONG_PTR IoStatusInformation)
{
    const auto Ntstatus = ZwSetIoCompletion(IoCompletionHandle, KeyContext, ApcContext, IoStatus, IoStatusInformation);
    if (!NT_SUCCESS(Ntstatus))
    {
        throw std::runtime_error(GetLastErrorString("ZwSetIoCompletion", RtlNtStatusToDosError(Ntstatus)));
    }
}

void w_NtSetTimer2(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PLARGE_INTEGER Period, PT2_SET_PARAMETERS Parameters) 
{
    const auto Ntstatus = NtSetTimer2(TimerHandle, DueTime, Period, Parameters);
    if (!NT_SUCCESS(Ntstatus))
    {
        throw std::runtime_error(GetLastErrorString("NtSetTimer2", RtlNtStatusToDosError(Ntstatus)));
    }
}