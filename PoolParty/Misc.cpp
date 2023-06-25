#include "Misc.hpp"

std::string GetLastErrorString(std::string FailedFunctionName)
{
    LPSTR pErrorText = NULL;

    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        LANG_SYSTEM_DEFAULT,
        (LPSTR)&pErrorText,
        0,
        NULL);

    auto sErrorText = std::string(pErrorText);

    LocalFree(pErrorText);
    pErrorText = NULL;

    std::ostringstream oss;
    oss << FailedFunctionName << " failed: " << sErrorText;
    return oss.str();
}