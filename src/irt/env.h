#pragma once

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

extern "C" void env_stdout(const void* buf, size_t length);
extern "C" void env_dump(unsigned long);
extern "C" void env_exit(int);
extern "C" long env_brk(long);
extern "C" uint32_t env_get_args_buffer_size();
extern "C" void env_get_args(void*);
