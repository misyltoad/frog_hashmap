#ifndef FROG_HASHMAP_H
#define FROG_HASHMAP_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifndef __cplusplus
#include <stdbool.h>
#endif

#include "rapidhash.h"

#if !defined(__has_builtin)
# define __has_builtin(x) 0
#endif

#if defined(HAVE___BUILTIN_EXPECT) || __has_builtin(__builtin_expect)
# define frog_hashmap_likely(x)   __builtin_expect(!!(x),1)
# define frog_hashmap_unlikely(x) __builtin_expect(!!(x),0)
#else
# define frog_hashmap_likely(x)   (x)
# define frog_hashmap_unlikely(x) (x)
#endif

#ifdef __cplusplus
  #define FROG_HASHMAP_NOEXCEPT noexcept
  #ifndef FROG_HASHMAP_INLINE
    #define FROG_HASHMAP_INLINE inline
  #endif
#else
  #define FROG_HASHMAP_NOEXCEPT
  #ifndef FROG_HASHMAP_INLINE
    #define FROG_HASHMAP_INLINE static inline
  #endif
#endif

typedef void *(*frog_hashmap_malloc_func)(size_t size);
typedef void *(*frog_hashmap_calloc_func)(size_t num, size_t size);
typedef void *(*frog_hashmap_realloc_func)(void *ptr, size_t size);
typedef void (*frog_hashmap_free_func)(void *mem);

struct frog_hashmap_alloc_callbacks
{
    /* these functions MUST NOT throw, and should return NULL on alloc failure. */

    frog_hashmap_malloc_func malloc;
    frog_hashmap_calloc_func calloc;
    frog_hashmap_realloc_func realloc;
    frog_hashmap_free_func free;
};

static const struct frog_hashmap_alloc_callbacks frog_hashmap_alloc_callbacks_default =
{
    .malloc = malloc,
    .calloc = calloc,
    .realloc = realloc,
    .free = free,
};

struct frog_hashmap_key
{
    const void *data;
    size_t size;
};

FROG_HASHMAP_INLINE struct frog_hashmap_key frog_hashmap_key_null(void) FROG_HASHMAP_NOEXCEPT
{
    return (struct frog_hashmap_key){};
}

FROG_HASHMAP_INLINE uint64_t frog_hashmap_key_is_null(struct frog_hashmap_key data) FROG_HASHMAP_NOEXCEPT
{
    return data.size == 0;
}

FROG_HASHMAP_INLINE bool frog_hashmap_key_compare_eq(struct frog_hashmap_key a, struct frog_hashmap_key b) FROG_HASHMAP_NOEXCEPT
{
    if (a.size != b.size)
        return false;

    /* fast path */
    if (a.data == b.data)
        return true;

    return memcmp(a.data, b.data, a.size) == 0;
}

FROG_HASHMAP_INLINE uint64_t frog_hashmap_key_hash(struct frog_hashmap_key data) FROG_HASHMAP_NOEXCEPT
{
    return rapidhash(data.data, data.size);
}

FROG_HASHMAP_INLINE struct frog_hashmap_key frog_hashmap_key_from_c_str_n(const char *str, size_t len) FROG_HASHMAP_NOEXCEPT
{
    return (struct frog_hashmap_key){ (void *)str, len };
}

FROG_HASHMAP_INLINE struct frog_hashmap_key frog_hashmap_key_from_c_str(const char *str) FROG_HASHMAP_NOEXCEPT
{
    return frog_hashmap_key_from_c_str_n(str, strlen(str));
}

struct frog_hashmap_entry
{
    struct frog_hashmap_key key;
    void *value;

    struct frog_hashmap_entry *next;

    uint64_t hash;
};

struct frog_hashmap
{
    struct frog_hashmap_entry *entries;
    size_t capacity;
    size_t length;

    const struct frog_hashmap_alloc_callbacks *alloc;
};

FROG_HASHMAP_INLINE size_t frog_hashmap_next_pow2(size_t v) FROG_HASHMAP_NOEXCEPT
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    if (sizeof(size_t) > 4)
    {
        v |= v >> 32;
    }
    v++;

    return v;
}

/* expected_length -> capacity */
FROG_HASHMAP_INLINE size_t frog_hashmap_growth_strategy(size_t expected_length) FROG_HASHMAP_NOEXCEPT
{
    return frog_hashmap_next_pow2(expected_length * 2);
}

/* capacity -> expected_length */
FROG_HASHMAP_INLINE size_t frog_hashmap_inv_growth_strategy(size_t capacity) FROG_HASHMAP_NOEXCEPT
{
    return capacity / 2;
}

FROG_HASHMAP_INLINE bool frog_hashmap_init_advanced(struct frog_hashmap *map, size_t expected_length, const struct frog_hashmap_alloc_callbacks *alloc) FROG_HASHMAP_NOEXCEPT
{
    if (!alloc)
        alloc = &frog_hashmap_alloc_callbacks_default;

    size_t initial_capacity = frog_hashmap_growth_strategy(expected_length);
    struct frog_hashmap_entry *entries = (struct frog_hashmap_entry *) alloc->calloc(initial_capacity, sizeof(struct frog_hashmap_entry));
    if (frog_hashmap_unlikely(!entries))
        return false;

    *map = (struct frog_hashmap)
    {
        .entries  = entries,
        .capacity = initial_capacity,

        .alloc = alloc,
    };

    return true;
}

FROG_HASHMAP_INLINE bool frog_hashmap_init(struct frog_hashmap *map) FROG_HASHMAP_NOEXCEPT
{
    return frog_hashmap_init_advanced(map, 16, &frog_hashmap_alloc_callbacks_default);
}

FROG_HASHMAP_INLINE size_t frog_hashmap_hash_to_index_advanced(struct frog_hashmap *map, size_t capacity, uint64_t hash) FROG_HASHMAP_NOEXCEPT
{
    return (size_t)(hash & (uint64_t)(capacity - 1));
}

FROG_HASHMAP_INLINE size_t frog_hashmap_hash_to_index(struct frog_hashmap *map, uint64_t hash) FROG_HASHMAP_NOEXCEPT
{
    return frog_hashmap_hash_to_index_advanced(map, map->capacity, hash);
}

FROG_HASHMAP_INLINE struct frog_hashmap_entry *frog_hashmap_hash_to_entry_advanced(struct frog_hashmap *map, struct frog_hashmap_entry *entries, size_t capacity, uint64_t hash) FROG_HASHMAP_NOEXCEPT
{
    size_t index = frog_hashmap_hash_to_index_advanced(map, capacity, hash);
    return &entries[index];
}

FROG_HASHMAP_INLINE struct frog_hashmap_entry *frog_hashmap_hash_to_entry(struct frog_hashmap *map, uint64_t hash) FROG_HASHMAP_NOEXCEPT
{
    return frog_hashmap_hash_to_entry_advanced(map, map->entries, map->capacity, hash);
}

/* get the current number of collisions for a given hash. */
FROG_HASHMAP_INLINE size_t frog_hashmap_collisions(struct frog_hashmap *map, uint64_t hash) FROG_HASHMAP_NOEXCEPT
{
    struct frog_hashmap_entry *entry = frog_hashmap_hash_to_entry(map, hash);
    if (!entry)
        return 0;

    size_t collisions = 0;
    entry = entry->next;
    while (entry)
    {
        collisions++;
        entry = entry->next;
    }

    return collisions;
}

struct frog_hashmap_entry_and_prev
{
    struct frog_hashmap_entry *entry;
    struct frog_hashmap_entry *prev;
};
FROG_HASHMAP_INLINE struct frog_hashmap_entry_and_prev frog_hashmap_get_entry_and_prev(struct frog_hashmap *map, struct frog_hashmap_key key, uint64_t hash) FROG_HASHMAP_NOEXCEPT
{
    struct frog_hashmap_entry *entry = frog_hashmap_hash_to_entry(map, hash);
    struct frog_hashmap_entry *prev = NULL;
    
    if (frog_hashmap_key_is_null(entry->key))
        return (struct frog_hashmap_entry_and_prev){};

    do
    {
        /* compare hash as well as everything, to avoid potentially expensive comparisons on collisions. */
        if (entry->hash == hash)
        {
            /* if the hashes match exactly, it's very likely this will be true.
             * note: this above is comparing full hashes.
             */
            if (frog_hashmap_likely(frog_hashmap_key_compare_eq(entry->key, key)))
                return (struct frog_hashmap_entry_and_prev){ entry, prev };
        }

        prev = entry;
        entry = entry->next;
    } while (entry);

     return (struct frog_hashmap_entry_and_prev){};;
}

FROG_HASHMAP_INLINE struct frog_hashmap_entry *frog_hashmap_get_entry(struct frog_hashmap *map, struct frog_hashmap_key key, uint64_t hash) FROG_HASHMAP_NOEXCEPT
{
    return frog_hashmap_get_entry_and_prev(map, key, hash).entry;
}

FROG_HASHMAP_INLINE void *frog_hashmap_get_advanced(struct frog_hashmap *map, struct frog_hashmap_key key, uint64_t hash) FROG_HASHMAP_NOEXCEPT
{
    struct frog_hashmap_entry *entry = frog_hashmap_get_entry(map, key, hash);
    if (!entry)
        return NULL;

    return entry->value;
}

FROG_HASHMAP_INLINE void *frog_hashmap_get(struct frog_hashmap *map, struct frog_hashmap_key key) FROG_HASHMAP_NOEXCEPT
{
    return frog_hashmap_get_advanced(map, key, frog_hashmap_key_hash(key));
}

FROG_HASHMAP_INLINE void frog_hashmap_internal_add_entry(struct frog_hashmap *map, struct frog_hashmap_entry *entries, size_t capacity, struct frog_hashmap_key key, uint64_t hash, void *value) FROG_HASHMAP_NOEXCEPT
{
    struct frog_hashmap_entry *entry = frog_hashmap_hash_to_entry_advanced(map, entries, capacity, hash);
    if (!frog_hashmap_key_is_null(entry->key))
    {
        while (entry->next)
            entry = entry->next;
        entry->next = (struct frog_hashmap_entry *)map->alloc->calloc(1, sizeof(struct frog_hashmap_entry));
        entry = entry->next;
    }

    entry->key = key;
    entry->hash = hash;
    entry->value = value;
}

/* Note: You probably don't want to call this. It takes capacity. Use expected length functions below. */
FROG_HASHMAP_INLINE bool frog_hashmap_resize_capacity(struct frog_hashmap *map, size_t new_capacity) FROG_HASHMAP_NOEXCEPT
{
    struct frog_hashmap_entry *new_entries = (struct frog_hashmap_entry *)map->alloc->calloc(new_capacity, sizeof(struct frog_hashmap_entry));
    if (!new_entries)
        return false;

    for (size_t i = 0; i < map->capacity; i++)
    {
        struct frog_hashmap_entry *entry = &map->entries[i];
        if (frog_hashmap_key_is_null(entry->key))
            continue;

        do
        {
            frog_hashmap_internal_add_entry(map, new_entries, new_capacity, entry->key, entry->hash, entry->value);
            entry = entry->next;
        } while (entry);
    }

    map->alloc->free(map->entries);
    map->entries = new_entries;
    map->capacity = new_capacity;
    return true;
}

FROG_HASHMAP_INLINE bool frog_hashmap_reserve_advanced(struct frog_hashmap *map, size_t expected_length, bool allow_shrink) FROG_HASHMAP_NOEXCEPT
{
    size_t new_capacity = frog_hashmap_growth_strategy(expected_length);
    if (frog_hashmap_unlikely(!allow_shrink && new_capacity < map->capacity))
        new_capacity = map->capacity;

    /* Protect against overflow on 32-bit platforms */
    if (frog_hashmap_unlikely(sizeof(size_t) < 8 && new_capacity < map->capacity)) 
        return false;

    return frog_hashmap_resize_capacity(map, new_capacity);
}

FROG_HASHMAP_INLINE bool frog_hashmap_reserve(struct frog_hashmap *map, size_t expected_length) FROG_HASHMAP_NOEXCEPT
{
    return frog_hashmap_reserve_advanced(map, expected_length, false);
}

FROG_HASHMAP_INLINE bool frog_hashmap_expand(struct frog_hashmap *map) FROG_HASHMAP_NOEXCEPT
{
    /* Expected length would be our new capacity
     * -> double the capacity by our strategy.
     */
    return frog_hashmap_reserve_advanced(map, map->capacity, false);
}

FROG_HASHMAP_INLINE bool frog_hashmap_compact(struct frog_hashmap *map) FROG_HASHMAP_NOEXCEPT
{
    return frog_hashmap_reserve_advanced(map, map->length, true);
}

FROG_HASHMAP_INLINE bool frog_hashmap_set_advanced(struct frog_hashmap *map, struct frog_hashmap_key key, uint64_t hash, void *value) FROG_HASHMAP_NOEXCEPT
{
    struct frog_hashmap_entry *entry = frog_hashmap_get_entry(map, key, hash);
    if (entry)
    {
        entry->value = value;
        return true;
    }

    if (frog_hashmap_unlikely(map->length >= frog_hashmap_inv_growth_strategy(map->capacity)))
    {
        if (!frog_hashmap_expand(map))
            return false;
    }

    frog_hashmap_internal_add_entry(map, map->entries, map->capacity, key, hash, value);
    map->length++;

    return true;
}

FROG_HASHMAP_INLINE bool frog_hashmap_set(struct frog_hashmap *map, struct frog_hashmap_key key, void *value) FROG_HASHMAP_NOEXCEPT
{
    return frog_hashmap_set_advanced(map, key, frog_hashmap_key_hash(key), value);
}

FROG_HASHMAP_INLINE void frog_hashmap_remove_advanced(struct frog_hashmap *map, struct frog_hashmap_key key, uint64_t hash) FROG_HASHMAP_NOEXCEPT
{
    struct frog_hashmap_entry_and_prev entry_and_prev = frog_hashmap_get_entry_and_prev(map, key, hash);
    struct frog_hashmap_entry *entry = entry_and_prev.entry;
    if (!entry)
        return;

    struct frog_hashmap_entry *prev = entry_and_prev.prev;
    if (!prev)
    {
        if (entry->next)
        {
            /* move entry->next to us, at the base of the list */
            *entry = *entry->next;
            map->alloc->free(entry->next);
        }
        else
        {
            /* a lone child, null me out. */
            entry->key = frog_hashmap_key_null();
            entry->hash = 0;
            entry->value = NULL;
        }
    }
    else
    {
        /* replace prev's reference with out next and free ourselves. */
        prev->next = entry->next;
        map->alloc->free(entry);
    }
}

FROG_HASHMAP_INLINE void frog_hashmap_remove(struct frog_hashmap *map, struct frog_hashmap_key key) FROG_HASHMAP_NOEXCEPT
{
    return frog_hashmap_remove_advanced(map, key, frog_hashmap_key_hash(key));
}

FROG_HASHMAP_INLINE size_t frog_hashmap_capacity(struct frog_hashmap *map) FROG_HASHMAP_NOEXCEPT
{
    return map->capacity;
}

FROG_HASHMAP_INLINE size_t frog_hashmap_length(struct frog_hashmap *map) FROG_HASHMAP_NOEXCEPT
{
    return map->length;
}

FROG_HASHMAP_INLINE void frog_hashmap_destroy(struct frog_hashmap *map) FROG_HASHMAP_NOEXCEPT
{
    if (!map->capacity)
    {
        *map = (struct frog_hashmap){};

        assert(map->entries == NULL);
        assert(map->length == 0);
        return;
    }

    assert(map->alloc); /* if you hit this assert, you probably called this on uninitialized memory */
    
    for (size_t i = 0; i < map->capacity; i++)
    {
        /* remove any allocated collision entries */
        struct frog_hashmap_entry *entry = &map->entries[i];
        entry = entry->next; /* only ->next are dynamically allocated on collisions. */

        while (entry)
        {
            /* store off so we don't use after free. */
            struct frog_hashmap_entry *next = entry->next;
            map->alloc->free(entry);
            entry = next;
        }
    }
    map->alloc->free(map->entries);

    *map = (struct frog_hashmap){};
}

/* this is an init-like function, it does NOT destroy your "new-map" before cloning to it.
 * you must do that yourself!
 */
FROG_HASHMAP_INLINE bool frog_hashmap_clone(struct frog_hashmap *new_map, struct frog_hashmap *old_map) FROG_HASHMAP_NOEXCEPT
{
    *new_map = (struct frog_hashmap){};

    struct frog_hashmap_entry *new_entries = (struct frog_hashmap_entry *)old_map->alloc->malloc(old_map->capacity * sizeof(struct frog_hashmap_entry));
    if (frog_hashmap_unlikely(!new_entries))
        return false;

    new_map->entries = new_entries;
    new_map->capacity = old_map->capacity;
    new_map->length = old_map->length;
    new_map->alloc = old_map->alloc;

    bool failed = false;

    /* duplicate entries + collision lists */
    for (size_t i = 0; i < old_map->capacity; i++)
    {
        struct frog_hashmap_entry *old_entry = &old_map->entries[i];
        struct frog_hashmap_entry *new_entry = &new_map->entries[i];

        do
        {
            *new_entry = *old_entry;
            new_entry->next = NULL;

            if (old_entry->next && frog_hashmap_likely(!failed))
            {
                old_entry = old_entry->next;
                new_entry->next = (struct frog_hashmap_entry *)new_map->alloc->malloc(sizeof(struct frog_hashmap_entry));
                /* alloc failed? keep going with the copy and just free at the end.
                 * we need to remove all the uninitialized memory in the new_entries array
                 * before calling frog_hashmap_destroy
                 */
                if (!new_entry->next)
                    failed = true;
                new_entry = new_entry->next;
            }
            else
            {
                new_entry = NULL;
            }
        } while (new_entry);
    }

    if (frog_hashmap_unlikely(failed))
    {
        frog_hashmap_destroy(new_map);
        return false;
    }

    return true;
}

FROG_HASHMAP_INLINE void frog_hashmap_swap(struct frog_hashmap *a, struct frog_hashmap *b) FROG_HASHMAP_NOEXCEPT
{
    struct frog_hashmap tmp = *a;

    *a = *b;
    *b = tmp;
}

#endif
