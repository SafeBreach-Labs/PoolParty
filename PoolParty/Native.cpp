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
    NT_SUCCESS_OR_RAISE(
        "ZwAssociateWaitCompletionPacket",
        ZwAssociateWaitCompletionPacket(
            WaitCopmletionPacketHandle,
            IoCompletionHandle,
            TargetObjectHandle,
            KeyContext,
            ApcContext,
            IoStatus,
            IoStatusInformation,
            AlreadySignaled)
    );
}

void w_ZwSetInformationFile(
    HANDLE hFile,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass
)
{
    NT_SUCCESS_OR_RAISE(
        "ZwSetInformationFile",
        ZwSetInformationFile(
            hFile,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass)
    );
}

HANDLE w_NtAlpcCreatePort(POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes) {
    HANDLE hAlpc;
    NT_SUCCESS_OR_RAISE(
        "NtAlpcCreatePort",
        NtAlpcCreatePort(&hAlpc, ObjectAttributes, PortAttributes)
    );
    return hAlpc;
}

void w_NtAlpcSetInformation(HANDLE hAlpc, ULONG PortInformationClass, PVOID PortInformation, ULONG Length) 
{
    NT_SUCCESS_OR_RAISE(
        "NtAlpcSetInformation", 
         NtAlpcSetInformation(hAlpc, PortInformationClass, PortInformation, Length)
    );
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
    NT_SUCCESS_OR_RAISE(
        "NtAlpcConnectPort",
        NtAlpcConnectPort(
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
            Timeout)
    );

    return hAlpc;
}

BOOLEAN w_RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread)
{
    BOOLEAN Enabled = NULL;
    NT_SUCCESS_OR_RAISE(
        "RtlAdjustPrivilege", 
        RtlAdjustPrivilege(
            Privilege, 
            Enable,
            CurrentThread,
            &Enabled)
    );
    return Enabled;
}

void w_ZwSetIoCompletion(HANDLE IoCompletionHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, ULONG_PTR IoStatusInformation)
{
    NT_SUCCESS_OR_RAISE(
        "ZwSetIoCompletion",
        ZwSetIoCompletion(
            IoCompletionHandle,
            KeyContext,
            ApcContext,
            IoStatus,
            IoStatusInformation)
    );
}

void w_NtSetTimer2(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PLARGE_INTEGER Period, PT2_SET_PARAMETERS Parameters) 
{
    NT_SUCCESS_OR_RAISE(
        "NtSetTimer2",
        NtSetTimer2(
            TimerHandle,
            DueTime,
            Period,
            Parameters)
    );

}