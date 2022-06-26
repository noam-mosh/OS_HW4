#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <cstring>
#include <sys/mman.h>

#define MAX_ALOC_SIZE (100000000)
#define MMAP_MIN_ALOC_SIZE (128*1024)

typedef struct MallocMetadata_t {
    size_t size;
    bool is_free;
    MallocMetadata_t* next;
    MallocMetadata_t* prev;
    void* address;
    friend class BlockList;
    friend class mmapList;
}MallocMetadata;

class BlockList {
public:
    MallocMetadata* head = nullptr;
    MallocMetadata* tail = nullptr;
    size_t num_free_blocks = 0;
    size_t num_free_bytes = 0;
    size_t num_allocated_blocks = 0;
    size_t num_allocated_bytes = 0;

    void *Insert(MallocMetadata* new_block, void* start_p, size_t size);
    void *Insert(void* start_p, size_t size);
    void Remove(MallocMetadata* block);
    void *AssignAndSplitBlock(size_t size);
    void *AssignBlock(size_t size);
    void *AssignBlockRealloc(void* address, size_t new_size, bool* split);
    void* MergeBlocks(void* address, size_t new_size);
    void SetToFree(void *address);
    MallocMetadata* FindWilderness();
    void *AssignWildernessBlock(size_t size);
    size_t GetBlockSizeByAddr(void *address);
    bool GetBlockStatByAddr(void *address);
    MallocMetadata* GetBlockByAddr(void *address);
    MallocMetadata* GetBlockEndInAddr(void *address);

};

BlockList* block_list = (BlockList*) sbrk(sizeof(*block_list));

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


void* BlockList::Insert(MallocMetadata* new_block, void* start_p, size_t size)
{
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
        if (current == tail){
            current->next = new_block;
            new_block->prev = current;
            tail = new_block;
            return new_block->address;
        }
        current = current->next;
    }
    size_t tmp_size =  current->size;
    if (current && current->prev){
        current = current->prev;
        tmp_size = (current->next)->size;
    }
    else
        tmp_size = current->size;

    current = head;
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
    new_block->prev = current->prev;
    current->prev = new_block;
    new_block->next = current;

    return new_block->address;
}

void* BlockList::Insert(void* start_p, size_t size)
{
    MallocMetadata* new_block = (MallocMetadata*) sbrk(sizeof(*new_block));
    if (new_block == (void*)(-1)){
        return nullptr;
    }
    return Insert(new_block, start_p, size);
}

void BlockList::Remove(MallocMetadata* block)
{
    if (block == nullptr)
        return;

    if (block->prev && block->next)
    {
        block->prev->next = block->next;
        block->next->prev = block->prev;
        return;
    }
    if (block == head)
    {
        head = block->next;
        if (block->next)
            block->next->prev = nullptr;
    }

    if (block == tail)
    {
        tail = block->prev;
        if (block->prev)
            block->prev->next = nullptr;
    }
}

void* BlockList::AssignAndSplitBlock(size_t size)
{
    if (head == nullptr)
        return nullptr;
    MallocMetadata* current = head;
    while ((current && current->size < size + 128 + _size_meta_data()) || (current && !(current->is_free))) {
        current = current->next;
    }

    if (current == nullptr)
        return nullptr;

    num_allocated_bytes -= current->size ;
    num_free_blocks--;
    num_free_bytes -= current->size;
    num_allocated_blocks--;
    //current->is_free = false;

    size_t old_size = current->size;
    void* curr_addr = current->address;
    //current->size = size;
    Remove(current);
    void* address = Insert(curr_addr, size);
    address = Insert(curr_addr + size + _size_meta_data(), old_size - size - _size_meta_data());

    SetToFree(address);

    return current->address;
}

void* BlockList::AssignBlock(size_t size)
{
    if (head == nullptr)
        return nullptr;
    MallocMetadata* current = head;
    while (current)
    {
        if (current->is_free && current->size >= size)
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

void* BlockList::AssignBlockRealloc(void* address, size_t new_size, bool *split)
{
    if (head == nullptr)
        return nullptr;
    MallocMetadata* current = head;
    while (current)
    {
        if (current->address == address && current->size >= new_size + 128 + _size_meta_data()) {
            if (current->is_free) {
                num_free_blocks--;
                num_free_bytes -= current->size;
                current->is_free = false;
            }
            num_allocated_bytes -= current->size;
            num_allocated_blocks--;
            //num_free_bytes += _size_meta_data();

            size_t old_size = current->size;
            void* curr_addr = current->address;

            Remove(current);

            address = Insert(curr_addr, new_size);
            address = Insert(curr_addr + new_size + _size_meta_data(), old_size - new_size - _size_meta_data());

            SetToFree(address);
            *split = true;
            return current;
        }
        if (current->address == address) {
            *split = false;
            return current;
        }
        current = current->next;
    }
    return nullptr;
}

void* BlockList::MergeBlocks(void* address, size_t new_size) {
    if (head == nullptr)
        return nullptr;
    MallocMetadata *current = head;
    while (current) {
        if (current->address == address) {
            MallocMetadata* to_remove = GetBlockByAddr(address+current->size+_size_meta_data());
            Remove(to_remove);
            Remove(current);
            //current->size = new_size;
            num_allocated_bytes -= (new_size - _size_meta_data());
            num_allocated_blocks -=2;
            address = Insert(address, new_size);
            return address;
        }
        current = current->next;
    }
    return nullptr;
}

void BlockList::SetToFree (void* address)
{
    if (head == nullptr)
        return;
    MallocMetadata* current = head;
    while (current){
        if (current->address == address) {
            current->is_free = true;
            num_free_blocks++;
            num_free_bytes += current->size;
            if (GetBlockStatByAddr(address + current->size + _size_meta_data()) == 1) {
                MallocMetadata *next_block = GetBlockByAddr(address + current->size + _size_meta_data());
                if (next_block != nullptr) {
                    size_t new_size = current->size + next_block->size + _size_meta_data();
                    Remove(current);
                    Remove(next_block);
                    num_free_blocks--;
                    num_free_bytes += _size_meta_data();
                    num_allocated_bytes += _size_meta_data();
                    num_allocated_blocks -= 2;
                    num_allocated_bytes -= new_size;
                    void *addr = Insert(address, new_size);
                    current = GetBlockByAddr(addr);
                    current->is_free = true;
                }
            }
            if (GetBlockEndInAddr(current->address) != nullptr) {
                MallocMetadata *prev_block = GetBlockEndInAddr(current->address);
                if (prev_block->is_free == 1){
                    size_t new_size = current->size + prev_block->size + _size_meta_data();
                    void *new_addr = prev_block->address;
                    Remove(current);
                    Remove(prev_block);
                    num_free_blocks--;
                    num_free_bytes += _size_meta_data();
                    num_allocated_bytes += _size_meta_data();
                    num_allocated_blocks -= 2;
                    num_allocated_bytes -= new_size;
                    void *addr = Insert(new_addr, new_size);
                    current = GetBlockByAddr(addr);
                    current->is_free = true;
                }
            }
        return;
        }
    current = current->next;
    }
}

MallocMetadata* BlockList::FindWilderness()
{
    MallocMetadata* current = head;
    void* max = current->address;
    MallocMetadata* wilderness = head;
    while (current)
    {
        if (current->address > max) {
            max = current->address;
            wilderness = current;
        }
        current = current->next;
    }
    return wilderness;
}

void* BlockList::AssignWildernessBlock(size_t size) {
    if (head == nullptr)
        return nullptr;
    MallocMetadata* wilderness = block_list->FindWilderness();
    if (wilderness && wilderness->is_free) {
        // Increase the size of the wilderness block
        void *address = sbrk(size - wilderness->size);
        if (address == (void *) (-1)) {
            return nullptr;
        }
        num_free_bytes -= wilderness->size;
        num_free_blocks--;
        num_allocated_bytes -= wilderness->size;
        //wilderness->size += (size - wilderness->size);
        wilderness->size = size;
        num_allocated_bytes += size;
        return wilderness->address;
    }
    return nullptr;
}

size_t BlockList::GetBlockSizeByAddr(void *address)
{
    if (head == nullptr)
        return 0;
    MallocMetadata* current = head;
    while (current)
    {
        if (current->address == address)
        {
            return current->size;
        }
        current = current->next;
    }
    return 0;

}

bool BlockList::GetBlockStatByAddr(void *address)
{
    if (head == nullptr)
        return 0;
    MallocMetadata* current = head;
    while (current)
    {
        if (current->address == address)
        {
            return current->is_free;
        }
        current = current->next;
    }
    return 0;
}

MallocMetadata* BlockList::GetBlockByAddr(void *address)
{
    if (head == nullptr)
        return 0;
    MallocMetadata* current = head;
    while (current)
    {
        if (current->address == address)
        {
            return current;
        }
        current = current->next;
    }
    return nullptr;
}

MallocMetadata* BlockList::GetBlockEndInAddr(void *address)
{
    if (head == nullptr)
        return 0;
    MallocMetadata* current = head;
    while (current)
    {
        if (current->address + current->size + _size_meta_data() == address)
        {
            return current;
        }
        current = current->next;
    }
    return nullptr;
}

//todo:not sure about inheritance
class mmapList:BlockList {
    MallocMetadata *head = nullptr;
    MallocMetadata *tail = nullptr;
    size_t num_allocated_blocks = 0;
    size_t num_allocated_bytes = 0;
    size_t num_of_metadata_blocks = 0;

public:
    void* mmapInsert(size_t size);
    void mmapFree(void* address);
};

void* mmapList::mmapInsert(size_t size) {
    void *address = mmap(NULL, size + _size_meta_data(), PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (address == (void *) (-1)) {
        return nullptr;
    }
    MallocMetadata *new_block = (MallocMetadata *) address;
    void *data_address = (char *) address + _size_meta_data();

    return Insert(new_block, data_address, size);
}

void mmapList::mmapFree(void* address) {
    MallocMetadata* current = head;
    while (current) {
        if (current->address == address) {
            munmap(address - _size_meta_data(), current->size + _size_meta_data());
            Remove(current);
            return;
        }
        current = current->next;
    }
}

mmapList* mmap_list = (mmapList*) sbrk(sizeof(*mmap_list));

size_t align_size(size_t size)
{
    if((size % 8) == 0)
        return size;
    int x = size/8;
    size = 8* (x+1);
    return size;

}
//Searches for a free block with at least‘size’ bytes or allocates (sbrk()) one if none are found.
//Return value:
//Success: returns pointer to the first byte in the allocated block (excluding the meta-data of course)
//Failure:
//a. If size is 0 returns NULL.
//b. If ‘size’ is more than 10^8 return NULL.
//c. If sbrk fails in allocating the needed space, return NULL.
void* smalloc(size_t size)
{
    size = align_size(size);
    if (size == 0 || size > MAX_ALOC_SIZE)
        return nullptr;

    if (size >= MMAP_MIN_ALOC_SIZE)
        return mmap_list->mmapInsert(size);

    void* start_p = block_list->AssignAndSplitBlock(size);
    if (start_p != nullptr) {
        return start_p;
    }

    start_p = block_list->AssignBlock(size);
    if (start_p != nullptr) {
        return start_p;
    }

    start_p = block_list->AssignWildernessBlock(size);
    if (start_p != nullptr) {
        return start_p;
    }

    // no free block available in free list- need to create a new one
    start_p = sbrk(size);
    if (start_p == (void*)(-1))
        return nullptr;
    start_p = block_list->Insert(start_p, size);

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
    size = align_size(size);
    void* start_p = smalloc(num * size);
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
    size = align_size(size);
    if (size == 0 | size > MAX_ALOC_SIZE)
        return nullptr;
    bool split = false;
    void *address = nullptr;
    MallocMetadata *old_block = block_list->GetBlockByAddr(oldp);
    size_t org_size = old_block->size;
    if (oldp != nullptr && block_list->GetBlockSizeByAddr(oldp) >= size)
        return block_list->AssignBlockRealloc(oldp, size, &split);

    MallocMetadata* prev = block_list->GetBlockEndInAddr(oldp);
    size_t new_size = block_list->GetBlockSizeByAddr(oldp) + prev->size + _size_meta_data();
    if (prev != nullptr && prev->is_free) {
        if (new_size >= size) {
            address = block_list->MergeBlocks(prev->address, new_size);
            block_list->num_free_blocks--;
            block_list->num_free_bytes -= prev->size;
            address = block_list->AssignBlockRealloc(prev->address, size, &split);
            if (!split) {
                prev->is_free = false;
                //block_list->num_free_blocks--;
            }
            address = memmove(prev->address, oldp, org_size);
            return address;
        }
        MallocMetadata *wilderness = block_list->FindWilderness();
        if (wilderness->address == oldp) {
            address = block_list->MergeBlocks(prev->address, new_size);
            block_list->num_free_bytes -= prev->size;
            block_list->num_free_blocks--;
            address = sbrk(size - new_size);
            if (address == (void *) (-1)) {
                return nullptr;
            }
            block_list->num_allocated_bytes += (size - new_size);
            //wilderness->size += (size - wilderness->size);
            prev->size = size;
            return prev->address;
        }
    }
    MallocMetadata *wilderness = block_list->FindWilderness();
    if (wilderness->address == oldp) {  //willderness==old_block
        address = sbrk(size - wilderness->size);
        if (address == (void *) (-1)) {
            return nullptr;
        }
        block_list->num_allocated_bytes += (size - wilderness->size);
        wilderness->size += (size - wilderness->size);
        return wilderness->address;
    }
    MallocMetadata *next = block_list->GetBlockByAddr(oldp + block_list->GetBlockSizeByAddr(oldp) + _size_meta_data());
    if (next && next->is_free)
    {
        new_size = next->size + block_list->GetBlockSizeByAddr(oldp) + _size_meta_data();
        if (new_size >= size)
        {
            address = block_list->MergeBlocks(oldp, new_size);
            block_list->num_free_blocks--;
            block_list->num_free_bytes -= next->size;
            address = block_list->AssignBlockRealloc(old_block->address, size, &split);
            if (!split) {
                next->is_free = false;
                //block_list->num_free_blocks--;
            }
            address = memmove(oldp, oldp, org_size); //TODO: NEED?
            return address;
        }
        if (prev && prev->is_free) {
            new_size += prev->size + _size_meta_data();
            if (new_size >= size){
                address = block_list->MergeBlocks(old_block->address, new_size - prev->size - _size_meta_data());
                block_list->num_free_blocks--;
                block_list->num_free_bytes -= prev->size;
                address = block_list->MergeBlocks(prev->address, new_size);
                block_list->num_free_blocks--;
                block_list->num_free_bytes -= next->size;
                address = block_list->AssignBlockRealloc(prev->address, size, &split);
                if (!split) {
                    prev->is_free = false;
                    //block_list->num_free_blocks -= 2;
                }
                address = memmove(prev->address, oldp, org_size);
                return address;
            }
            MallocMetadata *wilderness = block_list->FindWilderness();
            if (wilderness->address == next->address) {
                address = block_list->MergeBlocks(old_block->address, new_size - next->size - _size_meta_data());
                block_list->num_free_blocks--;
                block_list->num_free_bytes -= next->size;
                address = block_list->MergeBlocks(prev->address, new_size);
                block_list->num_free_blocks--;
                block_list->num_free_bytes -= prev->size;
                address = sbrk(size - new_size);
                if (address == (void *) (-1)) {
                    return nullptr;
                }
                block_list->num_allocated_bytes += (size - new_size);
                //wilderness->size += (size - wilderness->size);
                prev->size = size;
                return prev->address;
            }
        }
        MallocMetadata *wilderness = block_list->FindWilderness();
        if (wilderness->address == next->address) {
            address = block_list->MergeBlocks(oldp, new_size);
            block_list->num_free_blocks--;
            block_list->num_free_bytes -= next->size;
            address = sbrk(size - new_size);
            if (address == (void *) (-1)) {
                return nullptr;
            }
            block_list->num_allocated_bytes += (size - new_size);
            //wilderness->size += (size - wilderness->size);
            old_block->size = size;
            return old_block->address;
        }

    }

    address = smalloc(size);
    if (address != nullptr && oldp != nullptr)
        address = memmove(address, oldp, org_size);
    if (oldp != nullptr)
        sfree(oldp);
    return address;
}

//todo: perhaps this functions should be private?

//#define ASSERT_EQUAL(a,b)  \
//if(a != b){  \
//    printf("fail\n"); \
//    exit(0);               \
//}
//
//
//int main()
//{
//    void* p0 = smalloc(5000);
//    void* p1 = smalloc(5000);
//    void* p2 = smalloc(5000);
//    void* p3 = smalloc(5000);
//    sfree(p3);
//
//    void* p4 = srealloc(p2, 20000);
//    sfree(p4);
//
//    void* p5 = srealloc(p1,30000);
//
//    ASSERT_EQUAL(_num_free_blocks(), 0);
//    ASSERT_EQUAL(_num_free_bytes(),0);
//    ASSERT_EQUAL(_num_allocated_blocks(),3);
//    ASSERT_EQUAL(_num_allocated_bytes(), 30000);
//    ASSERT_EQUAL(_num_meta_data_bytes(), 3 * _size_meta_data());
//    ASSERT_EQUAL(_size_meta_data(), _size_meta_data());
//
//    return 0;
//}