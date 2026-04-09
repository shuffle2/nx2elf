#include <cstdio>

#include "elf_eh.h"
#include "types.h"
#include <cstdio>

#define DW_EH_PE_absptr 0x00
#define DW_EH_PE_omit 0xff

#define DW_EH_PE_uleb128 0x01
#define DW_EH_PE_udata2 0x02
#define DW_EH_PE_udata4 0x03
#define DW_EH_PE_udata8 0x04
#define DW_EH_PE_sleb128 0x09
#define DW_EH_PE_sdata2 0x0A
#define DW_EH_PE_sdata4 0x0B
#define DW_EH_PE_sdata8 0x0C
#define DW_EH_PE_signed 0x08

#define DW_EH_PE_pcrel 0x10
#define DW_EH_PE_textrel 0x20
#define DW_EH_PE_datarel 0x30
#define DW_EH_PE_funcrel 0x40
#define DW_EH_PE_aligned 0x50

#define DW_EH_PE_indirect 0x80

bool ElfEHInfo::MeasureFrame(const eh_frame_hdr* hdr,
                             uintptr_t* eh_frame_ptr,
                             u64* eh_frame_len) {
  if (hdr->version != 1) {
    return false;
  }
#define READ_RAW(type, ptr) \
  *(type*)ptr;              \
  ptr += sizeof(type);
  auto dw_decode = [&hdr](u8 enc, const u8*& buf, uintptr_t base = 0) {
    uintptr_t val = 0;
    if (base == 0) {
      base = (uintptr_t)buf;
    }
    if (enc == DW_EH_PE_omit) {
      // XXX hack for "nonexistant" value
      return (uintptr_t)0;
    }
    switch (enc & 0x70) {
    case DW_EH_PE_absptr:
      break;
    case DW_EH_PE_pcrel:
      val += base;
      break;
    case DW_EH_PE_datarel:
      val += (uintptr_t)hdr;
      break;
    default:
      fprintf(stderr, "unexpected enc base %02x\n", enc);
      break;
    }
    switch (enc & 0x0f) {
    case DW_EH_PE_udata2:
      val += READ_RAW(u16, buf);
      break;
    case DW_EH_PE_udata4:
      val += READ_RAW(u32, buf);
      break;
    case DW_EH_PE_sdata4:
      val += READ_RAW(s32, buf);
      break;
    default:
      fprintf(stderr, "unexpected enc type %02x\n", enc);
      break;
    }
    if (enc & DW_EH_PE_indirect) {
      val = *(uintptr_t*)val;
    }
    return val;
  };
  auto dw_fde_len = [](u32* fde_len, const u8* buf) {
    u32 len = READ_RAW(u32, buf);
    if (len == 0xffffffff) {
      return false;
    }
    *fde_len = len;
    return true;
  };
#undef READ_RAW

  const u8* ptr = (const u8*)&hdr[1];
  *eh_frame_ptr = dw_decode(hdr->eh_frame_ptr_enc, ptr);
  // XXX hack: default to len(eh_frame) == 8 if fde_count == 0
  *eh_frame_len = 8;
  size_t fde_count = dw_decode(hdr->fde_count_enc, ptr);
  uintptr_t max_ptr = 0;
  for (size_t i = 0; i < fde_count; i++) {
    auto func = dw_decode(hdr->table_enc, ptr);
    auto desc = dw_decode(hdr->table_enc, ptr);
    u32 fde_len;
    if (!dw_fde_len(&fde_len, (const u8*)desc)) {
      fprintf(stderr, "reading fde %zi failed\n", i);
      continue;
    }
    max_ptr = std::max(max_ptr, desc + fde_len);
  }
  if (max_ptr) {
    *eh_frame_len = max_ptr - *eh_frame_ptr;
  }
  return true;
}
