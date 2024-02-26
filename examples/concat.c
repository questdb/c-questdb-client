#include "concat.h"

/** Concatenate a list of nul-terminated strings. Pass an extra NULL arg to terminate. */
char* concat_(const char* first, ...) {
    va_list args;
    size_t totalLength = strlen(first) + 1;
    va_start(args, first);
    const char* str;
    while((str = va_arg(args, char*)) != NULL) totalLength += strlen(str);
    va_end(args);
    char* result = calloc(totalLength, sizeof(char));
    if(!result) return NULL;
    strcpy(result, first);
    va_start(args, first);
    while((str = va_arg(args, char*)) != NULL) strcat(result, str);
    va_end(args);
    return result;
}

