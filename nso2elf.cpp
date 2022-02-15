#include <string>
#include <unordered_map>
#include <vector>

#include "elf.h"
#include "elf_eh.h"
#include "lz4.h"
#include "types.h"

#define MAGIC_NSO0 0x304F534E

typedef enum {
    NSO0_SEGMENT_TEXT   = 0,
    NSO0_SEGMENT_RODATA = 1,
    NSO0_SEGMENT_DATA   = 2,
    LAST_NSO0_SEGMENT
} nso0_segment_type_t;

typedef struct {
    uint32_t file_off;
    uint32_t dst_off;
    uint32_t decomp_size;
    uint32_t align_or_total_size;
} nso0_segment_t;

typedef struct {
    uint32_t off;
    uint32_t size;
} nso0_relative_segment_t;

typedef struct {
    uint32_t _0x0;
    uint32_t magic_offset;
    uint32_t magic;
    uint32_t dynamic_offset;
    uint32_t bss_start_offset;
    uint32_t bss_end_offset;
    uint32_t eh_frame_hdr_start_offset;
    uint32_t eh_frame_hdr_end_offset;
    uint32_t load_addr;
} nso0_mod0_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t _0x8;
    uint32_t flags;
    nso0_segment_t segments[3];
    uint8_t build_id[0x20];
    uint32_t compressed_sizes[3];
    uint8_t _0x6C[0x1C];
    nso0_relative_segment_t api_info_extents;
    nso0_relative_segment_t dynstr_extents;
    nso0_relative_segment_t dynsym_extents;
    uint8_t section_hashes[3][0x20];
    unsigned char data[];
} nso0_header_t;

class StringTable {
public:
    StringTable() : watermark(0) {}

    void AddString(std::string &str)
    {
        if (!entries.count(str)) {
            entries[str] = watermark;
            watermark += str.length() + 1;
        }
    }

    uint32_t GetOffset(std::string &str)
    {
        if (!entries.count(str))
            return 0;
        else
            return entries[str];
    }

    std::vector<char> GetBuffer() {
        std::vector<char> buffer(watermark);

        for (const auto &entry : entries) {
            strcpy(&buffer[entry.second], entry.first.c_str());
        }

        return buffer;
    }

private:
    uint32_t watermark;
    std::unordered_map<std::string, uint32_t> entries;
    std::vector<char> buffer;
};
