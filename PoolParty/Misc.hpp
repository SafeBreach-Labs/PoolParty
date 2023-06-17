#pragma once

#include <Windows.h>

#include <iostream>

void GetError(std::string FailedFunctionName);
PVOID GetProcAddressFromModule(WCHAR* Module, CHAR* ProcName);