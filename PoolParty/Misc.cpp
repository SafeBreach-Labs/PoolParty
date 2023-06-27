#include "Misc.hpp"

std::string GetLastErrorString(std::string FailedFunctionName, DWORD dwLastError)
{
    LPSTR pErrorText = nullptr;

    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        dwLastError,
        LANG_SYSTEM_DEFAULT,
        (LPSTR)&pErrorText,
        0,
        nullptr);

    const auto sErrorText = std::string(pErrorText);

    LocalFree(pErrorText);
    pErrorText = nullptr;

    std::ostringstream oss;
    oss << FailedFunctionName << " failed: " << sErrorText;
    return oss.str();
}