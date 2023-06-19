#pragma once

#include <Windows.h>

#include "WinApi.hpp"
#include "Native.hpp"
#include "Misc.hpp"

class WorkerFactoryHandleDuplicator {
private: 
	DWORD m_dwTargetPid;
	HANDLE m_hTargetPid;

public:
	WorkerFactoryHandleDuplicator(DWORD dwTargetPid, HANDLE hTargetPid);
	HANDLE Duplicate(DWORD dwDesiredPermissions);
	~WorkerFactoryHandleDuplicator();
};