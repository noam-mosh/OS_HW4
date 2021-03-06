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
}MallocMetadata;

class BlockList {
public:
    MallocMetadata* head = nullptr;
    MallocMetadata* tail = nullptr;
    size_t num_free_blocks = 0;
    size_t num_free_bytes = 0;
    size_t num_allocated_blocks = 0;
    size_t num_allocated_bytes = 0;

    void *Insert(MallocMetadata* new_block, void* start_p, size_t size, bool not_new);
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
    friend class mmapList;

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


void* BlockList::Insert(MallocMetadata* new_block, void* start_p, size_t size, bool not_new)
{
    if (new_block == (void*)(-1)){
        return nullptr;
    }
    if (not_new)
        Remove(new_block);

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
//    if (current && current->prev){
//        current = current->prev;
//        tmp_size = (current->next)->size;
//    }
//    else
//        tmp_size = current->size;

    if (size == tmp_size){
        current = head;
        while (current && current->size <= tmp_size) {
            //if (current == tail && current != new_block){
            if (current == tail){
                current->next = new_block;
                new_block->prev = current;
                tail = new_block;
                return new_block->address;
            }
            current = current->next;
        }
    }
    else{
        current = head;
        while (current && current->size < tmp_size) {
            //if (current == tail && current != new_block){
            if (current == tail){
                current->next = new_block;
                new_block->prev = current;
                tail = new_block;
                return new_block->address;
            }
            current = current->next;
        }
    }

    if (current == head){
        current->prev = new_block;
        new_block->next = current;
        head = new_block;
        return new_block->address;
    }
    if (current && current->prev){
        current->prev->next = new_block;
        new_block->prev = current->prev;
        current->prev = new_block;
        new_block->next = current;
    }

    return new_block->address;
}

void* BlockList::Insert(void* start_p, size_t size)
{
    MallocMetadata* new_block = (MallocMetadata*) sbrk(sizeof(*new_block));
    if (new_block == (void*)(-1)){
        return nullptr;
    }
    void* addr = (void*)((unsigned long)new_block + _size_meta_data());
    //void* addr_ = (void*)_size_meta_data();
    return Insert(new_block, addr, size, false);
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
    current->is_free = false;

    size_t old_size = current->size;
    void* curr_addr = current->address;

    void* address = Insert(current, curr_addr, size, true);

    MallocMetadata* new_block = (MallocMetadata*) ((unsigned long) current+ _size_meta_data()+size);
    address = Insert(new_block, (void*)((unsigned long)curr_addr + size + _size_meta_data()), old_size - size - _size_meta_data(), false);

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

            //Remove(current);
            address = Insert(current, curr_addr, new_size, true);

            MallocMetadata* new_block = (MallocMetadata*) ((unsigned long) current + _size_meta_data()+ new_size);
            //address = Insert(new_block, curr_addr + size + _size_meta_data(), old_size - size - _size_meta_data(), false);

            address = Insert(new_block, (void*)((unsigned long)curr_addr + new_size + _size_meta_data()), old_size - new_size - _size_meta_data(), false);

            SetToFree(address);
            *split = true;
            return current->address;
        }
        if (current->address == address) {
            *split = false;
            return current->address;
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
            MallocMetadata* to_remove = GetBlockByAddr((void*)((unsigned long)address+current->size+_size_meta_data()));
            Remove(to_remove);
            //Remove(current);
            //current->size = new_size;
            num_allocated_bytes -= (new_size - _size_meta_data());
            num_allocated_blocks -=2;
            address = Insert(current, address, new_size, true);
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
            if (GetBlockStatByAddr((void*)((unsigned long)address + current->size + _size_meta_data())) == 1) {
                MallocMetadata *next_block = GetBlockByAddr((void*)((unsigned long)address + current->size + _size_meta_data()));
                if (next_block != nullptr) {
                    size_t new_size = current->size + next_block->size + _size_meta_data();
                    //Remove(current);
                    Remove(next_block);
                    num_free_blocks--;
                    num_free_bytes += _size_meta_data();
                    num_allocated_bytes += _size_meta_data();
                    num_allocated_blocks -= 2;
                    num_allocated_bytes -= new_size;
                    void *addr = Insert(current, address, new_size, true);

                    //void *addr = Insert(address, new_size);
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
                    //Remove(prev_block);
                    num_free_blocks--;
                    num_free_bytes += _size_meta_data();
                    num_allocated_bytes += _size_meta_data();
                    num_allocated_blocks -= 2;
                    num_allocated_bytes -= new_size;
                    void *addr = Insert(prev_block, new_addr, new_size, true);
                    //void *addr = Insert(new_addr, new_size);
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
        num_allocated_bytes += (size - wilderness->size);
        //wilderness->size += (size - wilderness->size);
        wilderness->size = size;
        wilderness->is_free = false;
        //num_allocated_bytes += size;
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
        return nullptr;
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
        if ((void*)((unsigned long)current->address + current->size + _size_meta_data()) == address)
        {
            return current;
        }
        current = current->next;
    }
    return nullptr;
}

//todo:not sure about inheritance
class mmapList : public BlockList {
public:
//    MallocMetadata *head = nullptr;
//    MallocMetadata *tail = nullptr;
//    size_t num_allocated_blocks = 0;
//    size_t num_allocated_bytes = 0;
//    size_t num_of_metadata_blocks = 0;
//
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

    address = Insert(new_block, data_address, size, false);
    if (address != nullptr){
        block_list->num_allocated_blocks++;
        block_list->num_allocated_bytes += size;
        return address;
    }
    return address;

}

void mmapList::mmapFree(void* address) {
    MallocMetadata* current = head;
    while (current) {
        if (current->address == address) {
            size_t size = current->size;
            block_list->num_allocated_blocks--;
            block_list->num_allocated_bytes -= current->size;
            Remove(current);
            munmap((void*)((unsigned long)address - _size_meta_data()), size + _size_meta_data());

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
//Searches for a free block with at least???size??? bytes or allocates (sbrk()) one if none are found.
//Return value:
//Success: returns pointer to the first byte in the allocated block (excluding the meta-data of course)
//Failure:
//a. If size is 0 returns NULL.
//b. If ???size??? is more than 10^8 return NULL.
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
    start_p = block_list->Insert(start_p, size);
    void* res = sbrk(size);
    if (res == (void*)(-1))
        return nullptr;

    return start_p;
}



//Searches for a free block of at least ???num??? elements, each ???size??? bytes that are all set to
//0 or allocates if none are found. In other words, find/allocate size * num bytes and set all bytes to 0.
//Return value:
//Success: returns pointer to the first byte in the allocated block.
//Failure:
//a. If size or num is 0 returns NULL.
//b. If ???size * num??? is more than 10^8 return NULL.
//c. If sbrk fails in allocating the needed space, return NULL
void* scalloc(size_t num, size_t size)
{
    size_t total_size = align_size(num * size);
    void* start_p = smalloc(total_size);
    if (start_p != nullptr)
        memset(start_p, 0, num * size);
    return start_p;
}

//Releases the usage of the block that starts with the pointer ???p???.
//If ???p??? is NULL or already released, simply returns.
//Presume that all pointers ???p??? truly points to the beginning of an allocated block.
void sfree(void* p)
{
    if (p == nullptr)
        return;
    block_list->SetToFree(p);
    mmap_list->mmapFree(p);
}

//If ???size??? is smaller than or equal to the current block???s size, reuses the same block.
//Otherwise, finds/allocates ???size??? bytes for a new space, copies content of oldp into the new allocated space and frees the oldp.
//Return value:
//Success:
//a. Returns pointer to the first byte in the (newly) allocated space.
//b. If ???oldp??? is NULL, allocates space for ???size??? bytes and returns a pointer to it.
//Failure:
//a. If size is 0 returns NULL.
//b. If ???size??? if more than 1^8 return NULL.
//c. If sbrk fails in allocating the needed spa
void* srealloc(void* oldp, size_t size)
{
    size = align_size(size);
    if (size == 0 || size > MAX_ALOC_SIZE)
        return nullptr;
    if (oldp == nullptr)
        return smalloc(size);
    bool split = false;
    void *address = nullptr;
    size_t org_size;
    size_t new_size;
    MallocMetadata *old_block = mmap_list->GetBlockByAddr(oldp);
    if (old_block != nullptr)
    {
        size_t old_size = mmap_list->GetBlockSizeByAddr(oldp);
        if (old_size == size)
            return oldp;

        mmap_list->SetToFree(oldp);
        void *new_block = smalloc(size);
        if (new_block == nullptr)
            return nullptr;
        if (old_size < size)
            size = old_size;
        memmove(new_block, oldp, size);
        return new_block;
    }
    old_block = block_list->GetBlockByAddr(oldp);
    if (old_block != nullptr)
        org_size = old_block->size;
    if (oldp != nullptr && block_list->GetBlockSizeByAddr(oldp) >= size)
        return block_list->AssignBlockRealloc(oldp, size, &split);

    MallocMetadata* prev = block_list->GetBlockEndInAddr(oldp);
    if (prev != nullptr && prev->is_free) {
        new_size  = block_list->GetBlockSizeByAddr(oldp) + prev->size + _size_meta_data();
        if (new_size >= size) {
            block_list->num_free_blocks--;
            block_list->num_free_bytes -= prev->size;
            address = block_list->MergeBlocks(prev->address, new_size);
            address = block_list->AssignBlockRealloc(prev->address, size, &split);
//            if (!split) {
//                prev->is_free = false;
//                //block_list->num_free_blocks--;
//            }
            address = memmove(prev->address, oldp, org_size);
            return address;
        }
        MallocMetadata *wilderness = block_list->FindWilderness();
        if (wilderness->address == oldp) {
            block_list->num_free_bytes -= prev->size;
            block_list->num_free_blocks--;
            address = block_list->MergeBlocks(prev->address, new_size);

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
    MallocMetadata *next = block_list->GetBlockByAddr((void*)((unsigned long)oldp + block_list->GetBlockSizeByAddr(oldp) + _size_meta_data()));
    if (next && next->is_free)
    {
        new_size = next->size + block_list->GetBlockSizeByAddr(oldp) + _size_meta_data();
        if (new_size >= size)
        {
            block_list->num_free_blocks--;
            block_list->num_free_bytes -= next->size;
            address = block_list->MergeBlocks(oldp, new_size);
            address = block_list->AssignBlockRealloc(old_block->address, size, &split);
//            if (!split) {
//                next->is_free = false;
//                //block_list->num_free_blocks--;
//            }
            address = memmove(oldp, oldp, org_size); //TODO: NEED?
            return address;
        }
        if (prev && prev->is_free) {
            new_size += prev->size + _size_meta_data();
            if (new_size >= size){
                void* prev_addr = prev->address;
                block_list->num_free_blocks--;
                block_list->num_free_bytes -= prev->size;
                address = block_list->MergeBlocks(old_block->address, new_size - prev->size - _size_meta_data());
                block_list->num_free_blocks--;
                block_list->num_free_bytes -= next->size;
                address = block_list->MergeBlocks(prev_addr, new_size);

                address = block_list->AssignBlockRealloc(prev_addr, size, &split);
//                if (!split) {
//                    prev->is_free = false;
//                    //block_list->num_free_blocks -= 2;
//                }
                address = memmove(prev_addr, oldp, org_size);
                return address;
            }
            MallocMetadata *wilderness = block_list->FindWilderness();
            if (wilderness->address == next->address) {
                block_list->num_free_blocks--;
                block_list->num_free_bytes -= next->size;
                address = block_list->MergeBlocks(old_block->address, new_size - next->size - _size_meta_data());

                block_list->num_free_blocks--;
                block_list->num_free_bytes -= prev->size;
                address = block_list->MergeBlocks(prev->address, new_size);

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
            MallocMetadata *new_block = block_list->GetBlockByAddr(oldp);
            new_block->size = size;
            return new_block->address;
        }

    }
    address = smalloc(size);
    if (address != nullptr && oldp != nullptr)
        address = memmove(address, oldp, org_size);
    if (oldp != nullptr)
        sfree(oldp);
    return address;
}

static inline size_t aligned_size(size_t size)
{
    return (size % 8) ? (size & (size_t)(-8)) + 8 : size;
}

template <typename T>
void populate_array(T *array, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        array[i] = (T)i;
    }
}

template <typename T>
void validate_array(T *array, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        REQUIRE((array[i] == (T)i));
    }
}
int main() {

    char *a = (char *)smalloc(32);
    char *b = (char *)smalloc(32);

    populate_array(b, 32);

    char *new_b = (char *)srealloc(b, 32 * 3 + _size_meta_data());
    sfree(new_b);
    return 0;
}
