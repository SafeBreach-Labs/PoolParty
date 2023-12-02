#pragma once

#include <Windows.h>

#include <sstream>
#include <string>

std::string GetLastErrorString(std::string FailedFunctionName, DWORD dwLastError);
std::string w_FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, DWORD nSize, va_list* Arguments);
