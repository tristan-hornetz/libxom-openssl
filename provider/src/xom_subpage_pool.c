#include <stdlib.h>
#include <string.h>
#include "aes_xom.h"

#define countof(x) (sizeof(x)/sizeof(*(x)))
#define page_addr(x) ((unsigned long)(x) & ~(PAGE_SIZE - 1))
#define bytes_to_subpages(x) (((x) / SUBPAGE_SIZE) + (((x) & (SUBPAGE_SIZE-1)) ? SUBPAGE_SIZE : 0))
#define POOL_BUFFER_SIZE (PAGE_SIZE << 6)
#define POOL_FREE_THRESHOLD ((POOL_BUFFER_SIZE / SUBPAGE_SIZE) * 3 / 4)

struct lhead {
    struct lhead* next;
    struct lhead* prev;
};

struct subpage_list_entry {
    struct lhead head;
    struct xom_subpages* subpages;
    size_t num_buffers;
    size_t buffer_offset;
    size_t last_page_marked;
    size_t subpages_used;
    void* buffers_allocated [POOL_BUFFER_SIZE / SUBPAGE_SIZE];
};

static struct subpage_list_entry subpage_pool = {
        {&subpage_pool.head, &subpage_pool.head},
        NULL,
        .num_buffers = 0,
        .buffer_offset = 0,
        .last_page_marked = 0,
        .subpages_used = 0,
        .buffers_allocated = {0, }
};

static struct subpage_list_entry* add_to_pool(struct xom_subpages* subpages) {
    struct subpage_list_entry* entry = calloc(1, sizeof(*entry));

    if (!entry)
        return NULL;

    *entry = (struct subpage_list_entry) {
            {subpage_pool.head.next, &subpage_pool.head},
            subpages
    };

    subpage_pool.head.next->prev = &(entry->head);
    subpage_pool.head.next = &(entry->head);

    return entry;
}

static void remove_from_pool(struct subpage_list_entry* entry) {
    entry->head.prev->next = entry->head.next;
    entry->head.next->prev = entry->head.prev;
    free(entry);
}

static int vptrcmp(const void* a, const void* b) {
    if (*(void**)a == *(void**)b)
        return 0;

    return *(void**)a < *(void**)b ? -1 : 1;
}


void* subpage_pool_lock_into_xom (unsigned char* data, size_t size) {
    void* ret = NULL;
    struct xom_subpages* new_subpages;
    struct subpage_list_entry* curr_entry = &subpage_pool;

    while (curr_entry->head.next != &subpage_pool.head) {
        curr_entry = (struct subpage_list_entry*) curr_entry->head.next;
        if(!curr_entry->subpages)
            break;

        if(curr_entry->num_buffers >= countof(curr_entry->buffers_allocated))
            continue;

        if((POOL_BUFFER_SIZE / SUBPAGE_SIZE) - curr_entry->subpages_used < bytes_to_subpages(size))
            continue;

        ret = xom_fill_and_lock_subpages(curr_entry->subpages, size, data);
        if (ret)
            break;
    }


    if (!ret) {
        new_subpages = xom_alloc_subpages(POOL_BUFFER_SIZE);
        if (!new_subpages)
            return ret;
        curr_entry = add_to_pool(new_subpages);
        ret = xom_fill_and_lock_subpages(curr_entry->subpages, size, data);
    }

    curr_entry->subpages_used += bytes_to_subpages(size);

    if (get_xom_mode() == XOM_MODE_SLAT && curr_entry->last_page_marked < page_addr(ret) ) {
        xom_mark_register_clear_subpage(curr_entry->subpages, 0, ((unsigned char*)ret - *((unsigned char**) curr_entry->subpages)) / PAGE_SIZE);
        curr_entry->last_page_marked = page_addr(ret);
    }

    if (ret && curr_entry != &subpage_pool) {
        curr_entry->buffers_allocated[curr_entry->buffer_offset++] = ret;
        curr_entry->num_buffers += 1;
    }

    return ret;
}

void subpage_pool_free(void* data) {
    void** buffer_entry;
    struct subpage_list_entry* curr_entry = &subpage_pool;
    unsigned i;

    if(!data)
        return;

    while (curr_entry->head.next != &subpage_pool.head) {
        curr_entry = (struct subpage_list_entry*) curr_entry->head.next;
        if (!curr_entry->subpages || !curr_entry->num_buffers)
            break;

        for(i = 0; i < countof(curr_entry->buffers_allocated); i++){
            if (curr_entry->buffers_allocated[i] == data){
                buffer_entry = &curr_entry->buffers_allocated[i];
                break;
            }
        }
        if (buffer_entry)
            break;
    }

    if (!buffer_entry)
        return;

    *buffer_entry = NULL;
    curr_entry->num_buffers -= 1;
    if(!curr_entry->num_buffers && curr_entry->subpages_used >= POOL_FREE_THRESHOLD) {
        xom_free_all_subpages(curr_entry->subpages);
        remove_from_pool(curr_entry);
    }
}

void destroy_subpage_pool(void) {
    struct subpage_list_entry* curr_entry = (struct subpage_list_entry*) subpage_pool.head.next;
    void* entry_addr;

    while (curr_entry != &subpage_pool) {
        if(curr_entry->subpages)
            xom_free_all_subpages(curr_entry->subpages);
        entry_addr = curr_entry;
        curr_entry = (struct subpage_list_entry*) curr_entry->head.next;
        free(entry_addr);
    }
}
