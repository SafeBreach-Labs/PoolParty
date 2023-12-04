#pragma once

#include <Windows.h>

#include "WinApi.hpp"
#include "Native.hpp"
#include "WorkerFactory.hpp"
#include "Misc.hpp"

// ------------//
// Proto types //
// ------------//

std::shared_ptr<HANDLE> HijackProcessHandle(std::wstring wsObjectType, std::shared_ptr<HANDLE> p_hTarget, DWORD dwDesiredAccess);

std::shared_ptr<HANDLE> HijackWorkerFactoryProcessHandle(std::shared_ptr<HANDLE> p_hTarget);

std::shared_ptr<HANDLE> HijackIoCompletionProcessHandle(std::shared_ptr<HANDLE> p_hTarget);

std::shared_ptr<HANDLE> HijackIRTimerProcessHandle(std::shared_ptr<HANDLE> p_hTarget);