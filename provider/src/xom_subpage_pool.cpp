#include <cstdlib>
#include "aes_xom.h"

#include <unordered_set>
#include <algorithm>
#include <vector>

#define countof(x) (sizeof(x)/sizeof(*(x)))
#define page_addr(x) ((unsigned long)(x) & ~(PAGE_SIZE - 1))
#define bytes_to_subpages(x) (((x) / SUBPAGE_SIZE) + (((x) & (SUBPAGE_SIZE-1)) ? SUBPAGE_SIZE : 0))
#define POOL_BUFFER_SIZE (PAGE_SIZE << 4)
#define POOL_FREE_THRESHOLD ((POOL_BUFFER_SIZE / SUBPAGE_SIZE) * 4 / 5)

struct subpage_list_entry {
    struct xom_subpages* subpages;
    size_t last_page_marked;
    size_t subpages_used;
    std::unordered_set<uintptr_t> buffers_used;

    subpage_list_entry() : subpages(nullptr), last_page_marked(0), subpages_used(0), buffers_used(std::unordered_set<uintptr_t>()) {}
    explicit subpage_list_entry(struct xom_subpages* subpages) : subpages(subpages), last_page_marked(0), subpages_used(0), buffers_used(std::unordered_set<uintptr_t>()) {}
};

static std::vector<subpage_list_entry> subpage_pool;

static void update_entry(subpage_list_entry& curr_entry, size_t size, const void* ret) {
    curr_entry.subpages_used += bytes_to_subpages(size);

    if (get_xom_mode() == XOM_MODE_SLAT && curr_entry.last_page_marked < page_addr(ret) ) {
        xom_mark_register_clear_subpage(curr_entry.subpages, 0, ((unsigned char*)ret - *((unsigned char**) curr_entry.subpages)) / PAGE_SIZE);
        curr_entry.last_page_marked = page_addr(ret);
    }

    curr_entry.buffers_used.emplace(reinterpret_cast<uintptr_t>(ret));
}

extern "C" void* subpage_pool_lock_into_xom (const unsigned char* data, size_t size) {
    void* ret;
    struct xom_subpages *new_subpages;

    for (auto curr_entry = subpage_pool.rbegin(); curr_entry != subpage_pool.rend(); curr_entry++) {

        if((POOL_BUFFER_SIZE / SUBPAGE_SIZE) - curr_entry->subpages_used < bytes_to_subpages(size))
            continue;

        ret = xom_fill_and_lock_subpages(curr_entry->subpages, size, data);
        if (ret) {
            update_entry(*curr_entry, size, ret);
            return ret;
        }
    }

    new_subpages = xom_alloc_subpages(POOL_BUFFER_SIZE);
    if (!new_subpages)
        return nullptr;
    auto curr_entry = subpage_list_entry(new_subpages);
    ret = xom_fill_and_lock_subpages(curr_entry.subpages, size, data);
    if(ret) {
        update_entry(curr_entry, size, ret);
        subpage_pool.push_back(curr_entry);
        return ret;
    }

    xom_free_all_subpages(curr_entry.subpages);
    return nullptr;
}

extern "C" void subpage_pool_free(void* const data) {
    if(!data)
        return;

    auto it = std::find_if(subpage_pool.begin(), subpage_pool.end(),
                           [data] (const subpage_list_entry& e) -> bool {
        return e.buffers_used.find(reinterpret_cast<uintptr_t>(data)) == e.buffers_used.end();
    });

    if (it == subpage_pool.end())
        return;

    it->buffers_used.erase(reinterpret_cast<uintptr_t>(data));
    if (xom_free_subpages(it->subpages, data) == 1 && it->subpages_used >= POOL_FREE_THRESHOLD)
        subpage_pool.erase(it);
}

extern "C" void destroy_subpage_pool(void) {
    for (const auto& entry: subpage_pool)
        xom_free_all_subpages(entry.subpages);

    subpage_pool.clear();
}
