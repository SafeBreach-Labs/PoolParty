#pragma once

#include <Windows.h>

#include "WinApi.hpp"
#include "Native.hpp"
#include "Misc.hpp"

// TODO: Make class impossible to instantiate
class HandleHijacker {
private:
	std::wstring m_wsObjectType;
public:
	HandleHijacker(std::wstring wsObjectType);
	std::shared_ptr<HANDLE> Hijack(DWORD dwDesiredPermissions);
	virtual bool IsDesiredOwnerProcess(DWORD dwOwnerProcessId);
	virtual bool IsDesiredHandle(std::shared_ptr<HANDLE> p_hHijackedObject);
	~HandleHijacker();
};

class WorkerFactoryHandleHijacker : public HandleHijacker {
private:
	DWORD m_dwTargetPid;
public:
	WorkerFactoryHandleHijacker(DWORD dwTargetPid);
	bool IsDesiredOwnerProcess(DWORD dwOwnerProcessId) override;
	~WorkerFactoryHandleHijacker();
};
