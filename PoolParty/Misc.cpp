#include "Misc.hpp"

//TODO: This needs to be fixed, to have WCHAR and not std::string that is OK with CHAR *

void GetError(std::string FailedFunctionName)
{
    DWORD dwErrorCode = GetLastError();
    WCHAR * ErrorText = NULL;

    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dwErrorCode,
        LANG_SYSTEM_DEFAULT,
        (LPWSTR)&ErrorText,
        0,
        NULL);

    std::printf("ERROR: The function %s failed with error code %d - %S", FailedFunctionName.c_str(), dwErrorCode, ErrorText);
    LocalFree(ErrorText);
}