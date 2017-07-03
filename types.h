#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef std::array<u8, 16> md5_digest;
typedef std::array<u8, 20> sha1_digest;
typedef std::array<u8, 32> sha256_digest;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))
#define ALIGN_UP(x, align) ALIGN_DOWN((x) + ((align) - 1), (align))

inline void *memmem(const void *haystack, size_t haystack_len, const void *needle,
	size_t needle_len) {
	u8 *p = (u8 *)haystack;
	u8 *e = (u8 *)haystack + haystack_len - needle_len;
	while (p <= e) {
		if (!memcmp(p, needle, needle_len)) {
			return p;
		}
		p++;
	}
	return nullptr;
}

inline int memcmp_m(const void *ptr1, const void *ptr2, const void *mask, size_t len) {
	const u8 *a = (const u8 *)ptr1;
	const u8 *b = (const u8 *)ptr2;
	const u8 *m = (const u8 *)mask;
	u8 x = 0;
	while (len-- && !x) {
		x = (*a++ ^ *b++) & *m++;
	}
	return x;
}

inline void *memmem_m(const void *haystack, size_t haystack_len, const void *needle,
	const void *mask, size_t needle_len) {
	u8 *p = (u8 *)haystack;
	u8 *e = (u8 *)haystack + haystack_len - needle_len;
	while (p <= e) {
		if (!memcmp_m(p, needle, mask, needle_len)) {
			return p;
		}
		p++;
	}
	return nullptr;
}

inline void *memmemr(const void *haystack, size_t haystack_len, const void *needle,
	size_t needle_len) {
	u8 *p = (u8 *)haystack + haystack_len - needle_len;
	u8 *e = (u8 *)haystack;
	while (p >= e) {
		if (!memcmp(p, needle, needle_len)) {
			return p;
		}
		p--;
	}
	return nullptr;
}
