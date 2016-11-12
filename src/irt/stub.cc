
#include <unwind.h>
#include <stdlib.h>
#include <stdint.h>
#include <setjmp.h>

extern "C" void (*__init_array_start)() = nullptr;
extern "C" void (*__init_array_end)() = nullptr;
extern "C" void (*__fini_array_start)() = nullptr;
extern "C" void (*__fini_array_end)() = nullptr;
extern "C" char __cp_begin[1] = {0};
extern "C" char __cp_end[1] = {0};
extern "C" char __cp_cancel[1] = {0};

extern "C" long __syscall_cp_asm() {
  abort();
}

extern "C" void __unmapself(void *base, size_t size) {
  abort();
}

extern "C" _Unwind_FunctionContext* __Unwind_SjLj_GetTopOfFunctionStack() {
  abort();
}

extern "C" void __Unwind_SjLj_SetTopOfFunctionStack(struct _Unwind_FunctionContext *fc) {
  abort();
}

extern "C" _Unwind_Reason_Code _Unwind_RaiseException(_Unwind_Exception *exception_object) {
  abort();
}

extern "C" int setjmp(jmp_buf env) {
  return 0;
}

extern "C" void longjmp(jmp_buf env, int val) {
  abort();
}
