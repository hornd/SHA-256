/**********************************************************************************
/*    Copyright 2011 Douglas Horn
/*
/*    Licensed under the Apache License, Version 2.0 (the "License");
/*    you may not use this file except in compliance with the License.
/*    You may obtain a copy of the License at
/* 
/*    http://www.apache.org/licenses/LICENSE-2.0
/* 
/*    Unless required by applicable law or agreed to in writing, software
/*    distributed under the License is distributed on an "AS IS" BASIS,
/*    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/*    See the License for the specific language governing permissions and
/*    limitations under the License.
 **********************************************************************************/

#ifndef _SHA256_H
#define _SHA256_H

#include <sys/types.h>

#define SHA_256_BLOCKSIZE        64
#define SHA_256_BLOCKSIZEBITS    (SHA_256_BLOCKSIZE * 8)

typedef uint8_t       U8;
typedef uint32_t      U32;
typedef uint64_t      U64;

typedef struct
{
    U64 bits;
    U32 holdlength;
    U32 state[8];
    U8 buffer[SHA_256_BLOCKSIZE];
} sha256_context;

static void 
sha256_start (sha256_context*);

static void
sha256_process (sha256_context*, U8*);

static void
sha256_update (sha256_context*, U8*, U32);

static void
sha256_finish (sha256_context*, U8*);

static void
sha256_tohex (sha256_context*, U8*);

#endif /* _sha256_h */
