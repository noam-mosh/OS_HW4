#include <iostream>
#include <unistd.h>

#define MAX_ALOC_SIZE (100000000)

//Tries to allocate ‘size’ bytes.
//Return value:
//Success: a pointer to the first allocated byte within the allocated block.
//Failure:
//a. If ‘size’ is 0 returns NULL.
//b. If ‘size’ is more than 10^8 return NULL
//c. If sbrk fails, return NULL.
void* smalloc(size_t size)
{
     if (size == 0 || size > MAX_ALOC_SIZE)
         return nullptr;
     void* start_p = sbrk(size);
     if (start_p == (void*)(-1))
         return nullptr;
     return start_p;

}