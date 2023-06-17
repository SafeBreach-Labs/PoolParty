#pragma once

#include <iostream>

// TODO: Add error code and message
class WindowsException : public std::exception {
private:
    std::string ErrorMessage;

public:
    WindowsException(std::string err);
    const char* what();
};