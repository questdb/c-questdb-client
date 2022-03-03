#include "wsastartup_guard.hpp"

#ifdef PLATFORM_WINDOWS

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>

/**
 * Starts and shuts down Winsock 2.2.
 * See: https://docs.microsoft.com/en-us/windows/win32/api/winsock/
 *        nf-winsock-wsastartup
 */
WSAStartupGuard::WSAStartupGuard()
{
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;
    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        // Tell the user that we could not find a usable
        // Winsock DLL.
        std::cerr << "WSAStartup failed with error: " << err << std::endl;
        abort();
    }
}

WSAStartupGuard::~WSAStartupGuard()
{
    if (WSACleanup() != 0)
        std::cerr
            << "WSACleanup failed with error: "
            << WSAGetLastError()
            << std::endl;
}

#endif
