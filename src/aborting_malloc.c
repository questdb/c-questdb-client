#include <stdlib.h>

void* aborting_malloc(size_t size)
{
    void* buf = malloc(size);
    if (buf)
        return buf;
    else
        abort();
}

void* aborting_realloc(void *ptr, size_t size)
{
    void* buf = realloc(ptr, size);
    if (buf)
        return buf;
    else
        abort();
}
