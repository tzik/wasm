
#include <pthread.h>

extern "C" pthread_t __pthread_self() {
  return 0;
}
