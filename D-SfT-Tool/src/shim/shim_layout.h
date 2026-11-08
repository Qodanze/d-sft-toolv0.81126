// Shared memory layout used by BOTH the LD_PRELOAD shim (C) and the GUI.
// Keep this struct byte-identical on both sides.
#ifndef DSFT_SHIM_LAYOUT_H
#define DSFT_SHIM_LAYOUT_H

#define DSFT_MAX_FILES 1024
#define DSFT_PATHBUF   4096

#include <pthread.h>
#include <stdint.h>

struct SharedState {
    pthread_mutex_t lock;     /* robust + process-shared */
    uint64_t written;         /* NET live disk bytes written by the tree */
    uint64_t gross;           /* cumulative bytes ever written (meter)   */
    uint64_t ram;             /* NET live heap bytes (malloc - free)     */
    uint64_t ram_peak;        /* highest live heap bytes ever seen       */
    uint32_t over;            /* disk quota reached flag */
    uint32_t limit_mb;        /* disk limit, 0 = unlimited */
    uint32_t ram_limit_mb;    /* ram limit, 0 = unlimited */
    uint8_t  ram_mode;        /* 0 off, 1 terminate, 2 own-sandbox jail */
    uint8_t  disk_block;      /* 1 = writes fail with ENOSPC when over  */
    uint8_t  pad2[2];
    uint32_t nfiles;
    uint64_t pad;
    char files[DSFT_MAX_FILES][DSFT_PATHBUF];
    uint32_t filepid[DSFT_MAX_FILES];     /* creator pid of each entry    */
    uint64_t filecontrib[DSFT_MAX_FILES]; /* bytes this file added to written */
};

#endif
