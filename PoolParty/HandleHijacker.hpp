#pragma once

#include <Windows.h>

#include "WinApi.hpp"
#include "Native.hpp"
#include "Misc.hpp"

class HandleHijacker {
protected:
	std::wstring m_wsObjectType;
public:
	HandleHijacker(std::wstring wsObjectType);
	std::shared_ptr<HANDLE> Hijack(DWORD dwDesiredAccess);
	virtual bool IsDesiredOwnerProcess(DWORD dwOwnerProcessId);
	virtual bool IsDesiredHandle(std::shared_ptr<HANDLE> p_hHijackedObject);
	virtual ~HandleHijacker() = default;
};

// TODO: Make object name static
class WorkerFactoryHandleHijacker : public HandleHijacker {
protected:
	DWORD m_dwTargetPid;
public:
	WorkerFactoryHandleHijacker(DWORD dwTargetPid);
	bool IsDesiredOwnerProcess(DWORD dwOwnerProcessId) override;
	~WorkerFactoryHandleHijacker() override = default;
};
