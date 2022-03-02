#pragma once

#include <stdint.h>

void* aborting_malloc(size_t size);

void* aborting_realloc(void *ptr, size_t size);
