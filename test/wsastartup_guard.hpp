#pragma once

#include "../src/build_env.h"

#ifdef PLATFORM_WINDOWS
struct WSAStartupGuard
{
    WSAStartupGuard();
    ~WSAStartupGuard();
};
#define WSASTARTUP_GUARD WSAStartupGuard wsastartup_guard
#else
#define WSASTARTUP_GUARD
#endif
