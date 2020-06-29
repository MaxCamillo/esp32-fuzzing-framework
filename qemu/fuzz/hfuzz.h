#ifndef FUZZ_HONGGFUZZ_H
#define FUZZ_HONGGFUZZ_H

#include "fuzz/config.h"

// /**
//  * Point at which the memory and register dump should be loaded
// */
// const target_ulong hfuzz_qemu_setup_point = 0x400D2640; //<-main_task (generic) | 0x400d6778 <- app_main;

// /**
//  * Point, where the memory dump was taken
//  */
// const target_ulong hfuzz_qemu_entry_point = 0x400f403d; //httpd_parse_req+29 (add a8, a3, a10)...
// //TODO maybe try at beginning of http_parse_req


// //target_ulong hfuzz_qemu_exit_point = 400F406C; <- should be hit by all 

// /**
//  * Points where to exit the execution if child flag is set
//  */ 
// const target_ulong hfuzz_qemu_exit_points[] = { 
//                                                 0x400f48b0, //httpd_resp_send (after successful parsing)
//                                                 0x400f4b44, //httpd_resp_send_err (after unsuccessful parsing)
//                                                 0x400f406c, //httpd_parse_req+58 fallback, if no response is sent
//                                               };

//*****************WIFI_AP***************************//

extern target_ulong hfuzz_qemu_setup_point;
extern target_ulong hfuzz_qemu_entry_point;
extern target_ulong hfuzz_qemu_exit_points[];
extern size_t hfuzz_qemu_n_exit_points;
extern char *hfuzz_dump_file;
extern char *hfuzz_regs_file;

extern const target_ulong hfuzz_qemu_start_code;
extern const target_ulong hfuzz_qemu_end_code;


extern bool childProcess;

extern void hfuzz_qemu_setup(CPUState *cpu);

extern void hfuzz_trace_pc(uintptr_t pc);

extern void hfuzz_trace_edge(uintptr_t pc, uintptr_t prev_pc);

extern void hfuzz_trace_strcmp(uint64_t callee, uint64_t calleeCallee, uint8_t *str1, uint8_t *str2, uint64_t size);


static inline void hfuzz_qemu_trace_pc(target_ulong pc) {
  //static __thread target_ulong prev_loc = 0;
  if (pc > hfuzz_qemu_end_code || pc < hfuzz_qemu_start_code) {
    return;
  }
  hfuzz_trace_pc(pc);
  //hfuzz_trace_edge(pc, prev_loc);
  //prev_loc = pc;
}


static inline void hfuzz_qemu_trace_strcmp(target_ulong callee, target_ulong calleeCallee, uint8_t *str1, uint8_t *str2, target_ulong size) {
  if (callee > hfuzz_qemu_end_code || callee < hfuzz_qemu_start_code) {
    return;
  }
  hfuzz_trace_strcmp(callee, calleeCallee, str1, str2, size);
}

#ifdef HFUZZ_FORKSERVER
extern void hfuzz_qemu_handle_argv(char **argv);
#endif // HFUZZ_FORKSERVER

#endif
