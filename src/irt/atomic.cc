
#include <stdint.h>

extern "C" {
#include <atomic_arch.h>
}

extern "C" int a_cas(volatile int *p, int t, int s) {
  // __asm__ __volatile__ (
  //     "lock ; cmpxchg %3, %1"
  //     : "=a"(t), "=m"(*p) : "a"(t), "r"(s) : "memory" );
  // return t;

  if (*p != t)
    return *p;
  *p = s;
  return t;
}

int a_swap(volatile int *p, int v) {
  // __asm__ __volatile__(
  //     "xchg %0, %1"
  //     : "=r"(v), "=m"(*p) : "0"(v) : "memory" );  
  // return v;

  int t = *p;
  *p = v;
  return t;
}

int a_fetch_add(volatile int *p, int v) {
  // __asm__ __volatile__(
  //     "lock ; xadd %0, %1"
  //     : "=r"(v), "=m"(*p) : "0"(v) : "memory" );
  // return v;

  int t = *p;
  *p += v;
  return t;
}

void a_and(volatile int *p, int v) {
  // __asm__ __volatile__(
  //     "lock ; and %1, %0"
  //     : "=m"(*p) : "r"(v) : "memory" );
  *p &= v;
}

void a_or(volatile int *p, int v) {
  // __asm__ __volatile__(
  //     "lock ; or %1, %0"
  //     : "=m"(*p) : "r"(v) : "memory" );
  *p |= v;
}

void a_inc(volatile int *p) {
  // __asm__ __volatile__(
  //     "lock ; incl %0"
  //     : "=m"(*p) : "m"(*p) : "memory" );
  ++*p;
}

void a_dec(volatile int *p) {
  // __asm__ __volatile__(
  //     "lock ; decl %0"
  //     : "=m"(*p) : "m"(*p) : "memory" );
  --*p;
}

void a_store(volatile int *p, int x) {
  // __asm__ __volatile__(
  //     "mov %1, %0 ; lock ; orl $0,(%%esp)"
  //     : "=m"(*p) : "r"(x) : "memory" );
  *p = x;
}

void a_barrier() {
  // __asm__ __volatile__( "" : : : "memory" );
}

void a_spin() {
  // __asm__ __volatile__( "pause" : : : "memory" );
}

extern "C" void crash();
void a_crash() {
  // __asm__ __volatile__( "hlt" : : : "memory" );
  crash();
}

int a_ctz_64(uint64_t x) {
  // int r;
  // __asm__(
  //     "bsf %1,%0 ; jnz 1f ; bsf %2,%0 ; add $32,%0\n1:"
  //     : "=&r"(r) : "r"((unsigned)x), "r"((unsigned)(x>>32)) );
  // return r;

  volatile uint64_t r = 0;
  __asm__ volatile("i64.ctz %0=, %1" : "=r"(r) : "r"(x));
  return r;
}

extern "C" int a_ctz_l(unsigned long x) {
  // long r;
  // __asm__( "bsf %1,%0" : "=r"(r) : "r"(x) );
  // return r;

  volatile int r = 0;
  __asm__ volatile("i32.ctz %0=, %1" : "=r"(r) : "r"(x));
  return r;
}
