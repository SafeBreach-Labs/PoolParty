#include "HandleDeleter.hpp"

void HandleDeleter::operator()(HANDLE* p_handle)
{
	if (*p_handle != NULL && *p_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(*p_handle);
	}
}