#pragma once

#include "types.h"

struct eh_frame_hdr {
  u8 version;
  u8 eh_frame_ptr_enc;
  u8 fde_count_enc;
  u8 table_enc;
};
struct eh_cie {
  uintptr_t caf;
  intptr_t daf;
  u8 fde_enc;
  const u8* insns;
  size_t insns_len;
};
struct eh_fde {
  eh_cie cie;
  uintptr_t start;
  uintptr_t end;
  const u8* insns;
  size_t insns_len;
};
struct eh_fde_rel {
  u32 start;
  u32 end;
  uintptr_t caf;
  intptr_t daf;
  u32 init_insns;
  u32 init_insns_len;
  u32 insns;
  u32 insns_len;
};

struct ElfEHInfo {
  bool MeasureFrame(const eh_frame_hdr* hdr,
                    uintptr_t* eh_frame_ptr,
                    uint32_t* eh_frame_len);
};
