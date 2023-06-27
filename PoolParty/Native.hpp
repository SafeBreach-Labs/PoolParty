
// TODO: The structs and stuff used in this file should be moved to the place used

#pragma once

#include <vector>
#include <Windows.h>
#include <emmintrin.h>
#include <ntstatus.h>
#include <winternl.h>

#include "Misc.hpp"

#pragma comment(lib, "ntdll")

// ---------//
// Structs //
// --------//

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
    PVOID KeyContext;
    PVOID ApcContext;
    IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, * PFILE_IO_COMPLETION_INFORMATION;

typedef struct _FILE_COMPLETION_INFORMATION {
    HANDLE Port;
    PVOID  Key;
} FILE_COMPLETION_INFORMATION, * PFILE_COMPLETION_INFORMATION;


typedef struct _ALPC_PORT_ATTRIBUTES
{
	unsigned long Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	unsigned __int64 MaxMessageLength;
	unsigned __int64 MemoryBandwidth;
	unsigned __int64 MaxPoolUsage;
	unsigned __int64 MaxSectionSize;
	unsigned __int64 MaxViewSize;
	unsigned __int64 MaxTotalSectionSize;
	ULONG DupObjectTypes;
#ifdef _WIN64
	ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			USHORT DataLength;
			USHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			USHORT Type;
			USHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
		ULONG CallbackId; // only valid for LPC_REQUEST messages
	};
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE {
	PORT_MESSAGE PortHeader;
	BYTE PortMessage[1000]; // Hard limit for this is 65488. An Error is thrown if AlpcMaxAllowedMessageLength() is exceeded
} ALPC_MESSAGE, * PALPC_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	ULONG AllocatedAttributes;
	ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ASSOCIATE_COMPLETION_PORT
{
	PVOID CompletionKey;
	HANDLE CompletionPort;
} ALPC_PORT_ASSOCIATE_COMPLETION_PORT, * PALPC_PORT_ASSOCIATE_COMPLETION_PORT;

// -------------//
// Enumerations //
// ------------//

typedef enum
{
	SeDebugPrivilege = 20
} Privileges;

// ------------------------//
// System call definitions //
// ------------------------//

EXTERN_C
NTSTATUS NTAPI ZwAssociateWaitCompletionPacket(
	_In_ HANDLE 		WaitCompletionPacketHandle,
	_In_ HANDLE 		IoCompletionHandle,
	_In_ HANDLE 		TargetObjectHandle,
	_In_opt_ PVOID 		KeyContext,
	_In_opt_ PVOID 		ApcContext,
	_In_ NTSTATUS 		IoStatus,
	_In_ ULONG_PTR 		IoStatusInformation,
	_Out_opt_ PBOOLEAN 	AlreadySignaled
);

EXTERN_C
NTSTATUS NTAPI ZwSetInformationFile(
	_In_ HANDLE hFile,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ PVOID FileInformation,
	_In_ ULONG Length,
	_In_ ULONG FileInformationClass
);

EXTERN_C
NTSTATUS NTAPI NtAlpcCreatePort(
	_Out_ PHANDLE PortHandle,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
);

EXTERN_C
NTSTATUS NTAPI NtAlpcSetInformation(
	_In_ HANDLE PortHandle,
	_In_ ULONG PortInformationClass,
	_In_opt_ PVOID PortInformation,
	_In_ ULONG Length
);

EXTERN_C
NTSTATUS NTAPI NtAlpcConnectPort(
	_Out_ PHANDLE PortHandle,
	_In_ PUNICODE_STRING PortName,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
	_In_ DWORD ConnectionFlags,
	_In_opt_ PSID RequiredServerSid,
	_In_opt_ PPORT_MESSAGE ConnectionMessage,
	_Inout_opt_ PSIZE_T ConnectMessageSize,
	_In_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
	_In_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
	_In_opt_ PLARGE_INTEGER Timeout
);

EXTERN_C
NTSTATUS NTAPI RtlAdjustPrivilege(
	_In_ ULONG Privilege,
	_In_ BOOLEAN Enable,
	_In_ BOOLEAN CurrentThread,
	_Out_ PBOOLEAN Enabled
);

// ------------//
// Proto types //
// ------------//

void w_ZwAssociateWaitCompletionPacket(
    HANDLE WaitCopmletionPacketHandle,
    HANDLE IoCompletionHandle,
    HANDLE TargetObjectHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation,
    PBOOLEAN AlreadySignaled
);

void w_ZwSetInformationFile(
    HANDLE hFile,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass
);

HANDLE w_NtAlpcCreatePort(POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes);

void w_NtAlpcSetInformation(HANDLE hAlpc, ULONG PortInformationClass, PVOID PortInformation, ULONG Length);

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
);

BOOLEAN w_RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread);

template <typename QueryFunction, typename... QueryFunctionArguments>
std::vector<BYTE> w_QueryInformation(const std::string& r_QueryFunctionName, QueryFunction fQueryFunction, QueryFunctionArguments... QueryFunctionArgs)
{
	ULONG InformationLength = 0;
	auto Ntstatus = STATUS_INFO_LENGTH_MISMATCH;
	std::vector<BYTE> Information;

	do {
		Information.resize(InformationLength);
		Ntstatus = fQueryFunction(QueryFunctionArgs..., Information.data(), InformationLength, &InformationLength);
	} while (Ntstatus == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(Ntstatus)) {
		throw std::runtime_error(GetLastErrorString(r_QueryFunctionName, RtlNtStatusToDosError(Ntstatus)));
	}

	return Information;
}
