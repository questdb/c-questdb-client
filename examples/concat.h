#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

char* concat_(const char* first, ...);

// A macro that passes the list of arguments to concat_ and adds a NULL
// terminator.
#define concat(...) concat_(__VA_ARGS__, NULL)
