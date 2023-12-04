#include "Misc.hpp"

// TODO: Move to WinApi.hpp
std::string w_FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, DWORD nSize, va_list* Arguments)
{
	LPSTR pErrorText = nullptr;

	auto szErrorText = FormatMessageA(
		dwFlags,
		lpSource,
		dwMessageId,
		dwLanguageId,
		reinterpret_cast<LPSTR>(&pErrorText),
		nSize,
		Arguments);
	if (0 == szErrorText) 
	{
		std::ostringstream oss;
		oss << "FormatMessageA failed: " << GetLastError();
		throw std::runtime_error(oss.str());
	}

	const auto sErrorText = std::string(pErrorText);

	/* if FORMAT_MESSAGE_ALLOCATE_BUFFER is used, the buffer is allocated using LocalAlloc, so after the std::string initialization we should free it */
	if (dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER)
	{
		LocalFree(pErrorText);
		pErrorText = nullptr;
	}

	return sErrorText;
}

std::string GetLastErrorString(std::string FailedFunctionName, DWORD dwLastError)
{
	auto sErrorText = w_FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		dwLastError,
		LANG_SYSTEM_DEFAULT,
		0,
		nullptr);

	std::ostringstream oss;
	oss << FailedFunctionName << " failed: " << sErrorText;
	return oss.str();
}