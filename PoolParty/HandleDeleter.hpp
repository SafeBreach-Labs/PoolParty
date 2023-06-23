#pragma once

#include <Windows.h>

class HandleDeleter
{
public:
	void operator()(HANDLE* handle);
};