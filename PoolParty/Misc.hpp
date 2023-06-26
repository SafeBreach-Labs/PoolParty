#pragma once

#include <Windows.h>

#include <iostream>
#include <sstream>
#include <string>

std::string GetLastErrorString(std::string FailedFunctionName, DWORD dwLastError);
