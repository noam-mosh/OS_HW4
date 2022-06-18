#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <cstring>

#define MAX_ALOC_SIZE (100000000)

class MallocMetadata {
    size_t size;
    bool is_free;
    MallocMetadata* next;
    MallocMetadata* prev;
    void* address;
    friend List;
};

class BlockList {
    MallocMetadata* head = nullptr;
    MallocMetadata* tail = nullptr;
    size_t num_free_blocks = 0;
    size_t num_free_bytes = 0;
    size_t num_allocated_blocks = 0;
    size_t num_allocated_bytes = 0;

    void* Insert(start_p, size)
    {
        MallocMetadata* new_block = (MallocMetadata*) sbrk(sizeof(*new_block));
        if (new_block == (void*)(-1)){
            return nullptr;
        }
        new_block->size = size;
        new_block->is_free = false;
        new_block->address = start_p;
        new_block->prev = nullptr;
        new_block->next = nullptr;

        num_allocated_blocks++;
        num_allocated_bytes += size;

        if (head == nullptr){
            head = new_block;
            tail = new_block;
            return new_block->address;
        }

        MallocMetadata* current = head;
        while (current && current->size < size) {
            current = current->next;
            if (current == nullptr)
                return nullptr;
        }
        size_t tmp_size = current->size;

        while (current && current->size == tmp_size) {
            if (current == tail){
                current->next = new_block;
                new_block->prev = current;
                tail = new_block;
                return new_block->address;
            }
            current = current->next;
        }

        if (current == head){
            current->prev = new_block;
            new_block->next = current;
            head = new_block;
            return new_block->address;
        }

        current->prev->next = new_block;
        current->prev = new_block;
        new_block->prev = current->prev;
        new_block->next = current;

        return new_block->address;
    }

    void* AssignBlock(size_t size)
    {
        if (head == nullptr)
            return nullptr;
        MallocMetadata* current = head;
        while ((current && current->size < size) || (current && !(current->is_free))) {
            current = current->next;
        }

        if (current == nullptr)
            return nullptr;

        current->is_free = false;
        num_free_blocks--;
        num_free_bytes -= current->size;
        return current->address;
    }

    void* AssignBlock(void* address)
    {
        if (head == nullptr)
            return nullptr;
        MallocMetadata* current = head;
        while (current)
        {
            if (current->is_free && current->address == address)
            {
                current->is_free = false;
                num_free_blocks--;
                num_free_bytes -= current->size;
                return current->address;
            }
            current = current->next;
        }
        return nullptr;
    }

    void SetToFree (void* address)
    {
        if (head == nullptr)
            return;
        MallocMetadata* current = head;
        while (current)
        {
            if (current->address == address)
            {
                current->is_free = true;
                num_free_blocks++;
                num_free_bytes += current->size;
                return;
            }
            current = current->next;
        }
    }

};


BlockList* block_list = (BlockList*) sbrk(sizeof(*block_list));

//Searches for a free block with at least‘size’ bytes or allocates (sbrk()) one if none are found.
//Return value:
//Success: returns pointer to the first byte in the allocated block (excluding the meta-data of course)
//Failure:
//a. If size is 0 returns NULL.
//b. If ‘size’ is more than 10^8 return NULL.
//c. If sbrk fails in allocating the needed space, return NULL.
void* smalloc(size_t size)
{
    if (size == 0 || size > MAX_ALOC_SIZE)
        return nullptr;

    void* start_p = block_list->AssignBlock(size);
    if (start_p == nullptr)
    {
        // no free block available in free list- need to create a new one
        if ((start_p = sbrk(size) == (void*)(-1)))
            return nullptr;
        start_p = block_list->Insert(start_p, size);
    }
    return start_p;
}



//Searches for a free block of at least ‘num’ elements, each ‘size’ bytes that are all set to
//0 or allocates if none are found. In other words, find/allocate size * num bytes and set all bytes to 0.
//Return value:
//Success: returns pointer to the first byte in the allocated block.
//Failure:
//a. If size or num is 0 returns NULL.
//b. If ‘size * num’ is more than 10^8 return NULL.
//c. If sbrk fails in allocating the needed space, return NULL
void* scalloc(size_t num, size_t size)
{
    void* start_p = smalloc(num * sizeof);
    if (start_p != nullptr)
        memset(start_p, 0, num * size);
    return start_p;
}

//Releases the usage of the block that starts with the pointer ‘p’.
//If ‘p’ is NULL or already released, simply returns.
//Presume that all pointers ‘p’ truly points to the beginning of an allocated block.
void sfree(void* p)
{
    if (p == nullptr)
        return;
    block_list->SetToFree(p);
}

//If ‘size’ is smaller than or equal to the current block’s size, reuses the same block.
//Otherwise, finds/allocates ‘size’ bytes for a new space, copies content of oldp into the new allocated space and frees the oldp.
//Return value:
//Success:
//a. Returns pointer to the first byte in the (newly) allocated space.
//b. If ‘oldp’ is NULL, allocates space for ‘size’ bytes and returns a pointer to it.
//Failure:
//a. If size is 0 returns NULL.
//b. If ‘size’ if more than 1^8 return NULL.
//c. If sbrk fails in allocating the needed spa
void* srealloc(void* oldp, size_t size)
{
    if (size == 0 | size > MAX_ALOC_SIZE)
        return nullptr;

    if (oldp != nullptr && block_list->GetBlockSizeByAddr(oldp) >= size)
        return block_list->AssignBlock(oldp);

    void* address = smalloc(size);
    if (address != nullptr)
        address = memmove(address, oldp, size);

    return address;
}

//Returns the number of allocated blocks in the heap that are currently free
size_t _num_free_blocks()
{
    return block_list->num_free_blocks;
}

//Returns the number of bytes in all allocated blocks in the heap that are currently free,
//excluding the bytes used by the meta-data structs.
size_t _num_free_bytes()
{
    return block_list->num_free_bytes;
}

//Returns the overall (free and used) number of allocated blocks in the heap.
size_t _num_allocated_blocks()
{
    return block_list->num_allocated_blocks;
}

//Returns the overall number (free and used) of allocated bytes in the heap, excluding
//the bytes used by the meta-data structs.
size_t _num_allocated_bytes()
{
    return block_list->num_allocated_bytes;
}

//Returns the overall number of meta-data bytes currently in the heap.
size_t _num_meta_data_bytes()
{
    return block_list->num_allocated_blocks * sizeof(MallocMetadata);
}

//Returns the number of bytes of a single meta-data structure in your system.
size_t _size_meta_data()
{
    return sizeof(MallocMetadata);
}