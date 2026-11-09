/** @file runtime_heap.h
 * @brief Bound the libc heap; kernel/services use only static user buffers.
 */
#ifndef RUNTIME_HEAP_H
#define RUNTIME_HEAP_H

/** @brief Strong replacement for the SDK's weak, whole-RAM libc heap hook. */
void * _sbrk(int increment);

#endif /* RUNTIME_HEAP_H */

/*** end of file ***/
