#pragma once

#include <Windows.h>

#include <sstream>
#include <string>

std::string GetLastErrorString(std::string FailedFunctionName, DWORD dwLastError);
