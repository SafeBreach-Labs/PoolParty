#include "Exceptions.hpp"

WindowsException::WindowsException(std::string err): ErrorMessage(err){}

const char * WindowsException::what() {
	return ErrorMessage.c_str();
}