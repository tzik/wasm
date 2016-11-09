
#include <stdint.h>
#include <stdlib.h>
#include <unwind.h>
#include <setjmp.h>

extern "C" void env_exit(int);
extern "C" uint32_t env_get_args_buffer_size();
extern "C" void env_get_args(void*);

extern "C" int main(int, char**);

extern "C" void (*__init_array_start)() = nullptr;
extern "C" void (*__init_array_end)() = nullptr;
extern "C" void (*__fini_array_start)() = nullptr;
extern "C" void (*__fini_array_end)() = nullptr;
extern "C" char __cp_begin[1] = {0};
extern "C" char __cp_end[1] = {0};
extern "C" char __cp_cancel[1] = {0};

extern "C" long __syscall_cp_asm() {
  return 0;
}

extern "C" void __unmapself(void *base, size_t size) {
}

extern "C" uintptr_t _Unwind_GetIP(struct _Unwind_Context *context) {
  return 0;
}

extern "C" void _Unwind_SetIP(struct _Unwind_Context *context,
                              uintptr_t new_value) {
}

extern "C" uintptr_t _Unwind_GetLanguageSpecificData(struct _Unwind_Context *context) {
  return 0;
}

extern "C" uintptr_t _Unwind_GetGR(struct _Unwind_Context *context,
                                   int index) {
  return 0;
}

extern "C" void _Unwind_SetGR(struct _Unwind_Context *context, int index,
                              uintptr_t new_value) {
}

extern "C" void _Unwind_DeleteException(_Unwind_Exception *exception_object) {
}

extern "C" _Unwind_Reason_Code _Unwind_RaiseException(_Unwind_Exception *exception_object) {
  return _URC_NO_REASON;
}

extern "C" int setjmp(jmp_buf env) {
  return 0;
}

extern "C" void longjmp(jmp_buf env, int val) {
  abort();
}

extern "C" int _start() {
  void* args = malloc(env_get_args_buffer_size());
  if (!args)
    abort();
  env_get_args(args);

  int* argc_ptr = static_cast<int*>(args);
  int argc = *argc_ptr;
  char** argv = reinterpret_cast<char**>(argc_ptr + 1);
  return main(argc, argv);
}
