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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sha_256.h"
 
#define SHIFT_RIGHT(x, y)           ((x) >> (y))
#define SHIFT_LEFT(x, y)            ((x) << (y))
// Circular shift 
#define ROTATE_RIGHT(x, y)          (SHIFT_RIGHT(x,y) | ((x) << (32 - (y))))

#define U8_TO_U32(e)                (SHIFT_LEFT(*e, 24) |      \
				     SHIFT_LEFT(*(e+1), 16) |  \
				     SHIFT_LEFT(*(e+2), 8)  |  \
				     (*(e+3)))

//Defend against if(a) macro;.
#define U32_TO_U8(n,b,i)        	do { \
					    *(b+i) = (U8)SHIFT_RIGHT(n, 24);   \
					    *(b+i+1) = (U8)SHIFT_RIGHT(n, 16); \
					    *(b+i+2) = (U8)SHIFT_RIGHT(n, 8);  \
					    *(b+i+3) = (U8)(n);                \
                                        } while(0)
	

#define SIGMA0(e) 		 	(ROTATE_RIGHT(e, 2) ^  \
					 ROTATE_RIGHT(e, 13) ^ \
					 ROTATE_RIGHT(e, 22))
#define SIGMA1(e) 			(ROTATE_RIGHT(e, 6) ^  \
					 ROTATE_RIGHT(e, 11) ^ \
					 ROTATE_RIGHT(e, 25))
#define S_SIGMA0(e) 			(ROTATE_RIGHT(e, 7) ^  \
					 ROTATE_RIGHT(e, 18) ^ \
					 SHIFT_RIGHT(e, 3))
#define S_SIGMA1(e) 			(ROTATE_RIGHT(e, 17) ^ \
					 ROTATE_RIGHT(e, 19) ^ \
					 SHIFT_RIGHT(e, 10))
//TODO: Cleanup these macros.									
#define SHA256_CALCTEMP(n) 		values[(127-(n))%8] + SIGMA1(values[(124-(n))%8]) + CH(values[(124-(n))%8], \
					 values[(125-(n))%8], values[(126-(n))%8]) + k_vals[n] + W[(n)]
								
//Defend against if(a) macro;.
#define SHA256_GOROUND(n) 			do {                                                            \
						t = SHA256_CALCTEMP(n);                                         \
						values[(123-n)%8] += t;                                         \
						values[(127-n)%8] = t + SIGMA0(values[(120-n)%8]) +             \
                                                MA(values[(120-n)%8],values[(121-n)%8],values[(122-n)%8]);	\
						}while(0)
						
						
// This string is used to index into to convert to a hex string.
static const char *hex_digits = "0123456789abcdef";

#define NUM_K_VALUES 64
static const U32 k_vals[NUM_K_VALUES] = { 
                                0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
				0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
				0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
				0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
				0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
				0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
				0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
				0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2 
                                };

#define NUM_H_VALUES 8
static const U32 sha256_hvals[NUM_H_VALUES] = { 
                                      0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 
				      0xa54ff53aUL, 0x510e527fUL, 0x9b05688cUL,
				      0x1f83d9abUL, 0x5be0cd19UL 
                                      };
	
static inline U32 CH(U32 e, U32 f, U32 g)
{
	return (e & (f ^ g)) ^ g;
}

static inline U32 MA(U32 e, U32 f, U32 g)
{
	return ((e & (f | g)) | (f & g));
}

/******************************************************************************
/* sha256_start
/*
/* Sets up the data structure by initializing all of the data.
/******************************************************************************/
void sha256_start (sha256_context *cur )
{						   
    cur->holdlength = 0;
    cur->bits = 0;
    memcpy(cur->state, sha256_hvals, sizeof(cur->state));
    memset(cur->buffer, 0, sizeof(cur->buffer));
}

/******************************************************************************
/* sha256_process
/*
/* Handles the transformation of a block. Calculates 64 rounds of the SHA-256
/*  compression function. This function is called internally by the main SHA-256
/*  driver, sha256_update. Data should contain 64 bytes.
/******************************************************************************/
void sha256_process (sha256_context *cur, U8 *data )
{
    U32 t;
    U32 W[64];
    U32 values[8];
	
    // Initialize our a through h values with the values
    // we've stored in the current state.
    values[0] = cur->state[0];
    values[1] = cur->state[1];
    values[2] = cur->state[2];
    values[3] = cur->state[3];
    values[4] = cur->state[4];
    values[5] = cur->state[5];
    values[6] = cur->state[6];
    values[7] = cur->state[7];
	
    // Initialize W's
    // TODO: We can probably do this at the same time we do the round
    //  calculations, and it should give us a bit of speedup.
    W[0] = U8_TO_U32(data);
    W[1] = U8_TO_U32((data + 4));
    W[2] = U8_TO_U32((data + 8));
    W[3] = U8_TO_U32((data + 12));
    W[4] = U8_TO_U32((data + 16));
    W[5] = U8_TO_U32((data + 20));
    W[6] = U8_TO_U32((data + 24));
    W[7] = U8_TO_U32((data + 28));
    W[8] = U8_TO_U32((data + 32));
    W[9] = U8_TO_U32((data + 36));
    W[10] = U8_TO_U32((data + 40));
    W[11] = U8_TO_U32((data + 44));
    W[12] = U8_TO_U32((data + 48));
    W[13] = U8_TO_U32((data + 52));
    W[14] = U8_TO_U32((data + 56));
    W[15] = U8_TO_U32((data + 60));
    W[16] = S_SIGMA1(W[14]) + W[9] +  S_SIGMA0(W[1]) + W[0];
    W[17] = S_SIGMA1(W[15]) + W[10] +  S_SIGMA0(W[2]) + W[1];
    W[18] = S_SIGMA1(W[16]) + W[11] +  S_SIGMA0(W[3]) + W[2];
    W[19] = S_SIGMA1(W[17]) + W[12] +  S_SIGMA0(W[4]) + W[3];
    W[20] = S_SIGMA1(W[18]) + W[13] +  S_SIGMA0(W[5]) + W[4];
    W[21] = S_SIGMA1(W[19]) + W[14] +  S_SIGMA0(W[6]) + W[5];
    W[22] = S_SIGMA1(W[20]) + W[15] +  S_SIGMA0(W[7]) + W[6];
    W[23] = S_SIGMA1(W[21]) + W[16] +  S_SIGMA0(W[8]) + W[7];
    W[24] = S_SIGMA1(W[22]) + W[17] +  S_SIGMA0(W[9]) + W[8];
    W[25] = S_SIGMA1(W[23]) + W[18] +  S_SIGMA0(W[10]) + W[9];	
    W[26] = S_SIGMA1(W[24]) + W[19] +  S_SIGMA0(W[11]) + W[10];
    W[27] = S_SIGMA1(W[25]) + W[20] +  S_SIGMA0(W[12]) + W[11];
    W[28] = S_SIGMA1(W[26]) + W[21] +  S_SIGMA0(W[13]) + W[12];
    W[29] = S_SIGMA1(W[27]) + W[22] +  S_SIGMA0(W[14]) + W[13];
    W[30] = S_SIGMA1(W[28]) + W[23] +  S_SIGMA0(W[15]) + W[14];
    W[31] = S_SIGMA1(W[29]) + W[24] +  S_SIGMA0(W[16]) + W[15];
    W[32] = S_SIGMA1(W[30]) + W[25] +  S_SIGMA0(W[17]) + W[16];
    W[33] = S_SIGMA1(W[31]) + W[26] +  S_SIGMA0(W[18]) + W[17];
    W[34] = S_SIGMA1(W[32]) + W[27] +  S_SIGMA0(W[19]) + W[18];
    W[35] = S_SIGMA1(W[33]) + W[28] +  S_SIGMA0(W[20]) + W[19];
    W[36] = S_SIGMA1(W[34]) + W[29] +  S_SIGMA0(W[21]) + W[20];
    W[37] = S_SIGMA1(W[35]) + W[30] +  S_SIGMA0(W[22]) + W[21];
    W[38] = S_SIGMA1(W[36]) + W[31] +  S_SIGMA0(W[23]) + W[22];
    W[39] = S_SIGMA1(W[37]) + W[32] +  S_SIGMA0(W[24]) + W[23];
    W[40] = S_SIGMA1(W[38]) + W[33] +  S_SIGMA0(W[25]) + W[24];
    W[41] = S_SIGMA1(W[39]) + W[34] +  S_SIGMA0(W[26]) + W[25];
    W[42] = S_SIGMA1(W[40]) + W[35] +  S_SIGMA0(W[27]) + W[26];
    W[43] = S_SIGMA1(W[41]) + W[36] +  S_SIGMA0(W[28]) + W[27];
    W[44] = S_SIGMA1(W[42]) + W[37] +  S_SIGMA0(W[29]) + W[28];
    W[45] = S_SIGMA1(W[43]) + W[38] +  S_SIGMA0(W[30]) + W[29];
    W[46] = S_SIGMA1(W[44]) + W[39] +  S_SIGMA0(W[31]) + W[30];
    W[47] = S_SIGMA1(W[45]) + W[40] +  S_SIGMA0(W[32]) + W[31];
    W[48] = S_SIGMA1(W[46]) + W[41] +  S_SIGMA0(W[33]) + W[32];
    W[49] = S_SIGMA1(W[47]) + W[42] +  S_SIGMA0(W[34]) + W[33];
    W[50] = S_SIGMA1(W[48]) + W[43] +  S_SIGMA0(W[35]) + W[34];
    W[51] = S_SIGMA1(W[49]) + W[44] +  S_SIGMA0(W[36]) + W[35];
    W[52] = S_SIGMA1(W[50]) + W[45] +  S_SIGMA0(W[37]) + W[36];
    W[53] = S_SIGMA1(W[51]) + W[46] +  S_SIGMA0(W[38]) + W[37];
    W[54] = S_SIGMA1(W[52]) + W[47] +  S_SIGMA0(W[39]) + W[38];
    W[55] = S_SIGMA1(W[53]) + W[48] +  S_SIGMA0(W[40]) + W[39];
    W[56] = S_SIGMA1(W[54]) + W[49] +  S_SIGMA0(W[41]) + W[40];
    W[57] = S_SIGMA1(W[55]) + W[50] +  S_SIGMA0(W[42]) + W[41];
    W[58] = S_SIGMA1(W[56]) + W[51] +  S_SIGMA0(W[43]) + W[42];
    W[59] = S_SIGMA1(W[57]) + W[52] +  S_SIGMA0(W[44]) + W[43];
    W[60] = S_SIGMA1(W[58]) + W[53] +  S_SIGMA0(W[45]) + W[44];
    W[61] = S_SIGMA1(W[59]) + W[54] +  S_SIGMA0(W[46]) + W[45];
    W[62] = S_SIGMA1(W[60]) + W[55] +  S_SIGMA0(W[47]) + W[46];
    W[63] = S_SIGMA1(W[61]) + W[56] +  S_SIGMA0(W[48]) + W[47];
	
    // Each transformation is 64 rounds.
    SHA256_GOROUND(0);
    SHA256_GOROUND(1);
    SHA256_GOROUND(2);
    SHA256_GOROUND(3);
    SHA256_GOROUND(4);
    SHA256_GOROUND(5);
    SHA256_GOROUND(6);
    SHA256_GOROUND(7);
    SHA256_GOROUND(8);
    SHA256_GOROUND(9);
    SHA256_GOROUND(10);
    SHA256_GOROUND(11);
    SHA256_GOROUND(12);
    SHA256_GOROUND(13);
    SHA256_GOROUND(14);
    SHA256_GOROUND(15);
    SHA256_GOROUND(16);
    SHA256_GOROUND(17);
    SHA256_GOROUND(18);
    SHA256_GOROUND(19);
    SHA256_GOROUND(20);
    SHA256_GOROUND(21);
    SHA256_GOROUND(22);
    SHA256_GOROUND(23);
    SHA256_GOROUND(24);
    SHA256_GOROUND(25);
    SHA256_GOROUND(26);
    SHA256_GOROUND(27);
    SHA256_GOROUND(28);
    SHA256_GOROUND(29);
    SHA256_GOROUND(30);
    SHA256_GOROUND(31);
    SHA256_GOROUND(32);
    SHA256_GOROUND(33);
    SHA256_GOROUND(34);
    SHA256_GOROUND(35);
    SHA256_GOROUND(36);
    SHA256_GOROUND(37);
    SHA256_GOROUND(38);
    SHA256_GOROUND(39);
    SHA256_GOROUND(40);
    SHA256_GOROUND(41);
    SHA256_GOROUND(42);
    SHA256_GOROUND(43);
    SHA256_GOROUND(44);
    SHA256_GOROUND(45);
    SHA256_GOROUND(46);
    SHA256_GOROUND(47);
    SHA256_GOROUND(48);
    SHA256_GOROUND(49);
    SHA256_GOROUND(50);
    SHA256_GOROUND(51);
    SHA256_GOROUND(52);
    SHA256_GOROUND(53);
    SHA256_GOROUND(54);
    SHA256_GOROUND(55);
    SHA256_GOROUND(56);
    SHA256_GOROUND(57);
    SHA256_GOROUND(58);
    SHA256_GOROUND(59);
    SHA256_GOROUND(60);
    SHA256_GOROUND(61);
    SHA256_GOROUND(62);
    SHA256_GOROUND(63);
		
    // Store the currently calculated a through h values back into
    // our struct.
    cur->state[0] += values[0];
    cur->state[1] += values[1];
    cur->state[2] += values[2];
    cur->state[3] += values[3];
    cur->state[4] += values[4];
    cur->state[5] += values[5];
    cur->state[6] += values[6];
    cur->state[7] += values[7]; 
}

/******************************************************************************
/* sha256_update
/*
/* This is the main driver of the hash algorithm. It will shoot off calls to the
/*  compression function based on how many bytes we have left to process as well
/*  keep track of the total number of bits we've processed so far.
/******************************************************************************/
void sha256_update (sha256_context *cur, U8 *data, U32 len)
{
    // If our current length is bigger than a block, just keep on 
    // processing it until it isn't.
    while (len >= SHA_256_BLOCKSIZE)
    {
 	sha256_process(cur, data);
	cur->bits += SHA_256_BLOCKSIZEBITS;
	data += SHA_256_BLOCKSIZE;
        len -= SHA_256_BLOCKSIZE;
    }
	
    // So we need to deal with whatever is leftover. We know the current
    // buffer location, and we want to store the smaller of the leftover
    // length or the rest of the buffer. Find that value and then store
    // the leftovers.
    if (len > 0)
    {
 	U32 avail_space = len < SHA_256_BLOCKSIZE - cur->holdlength ?
		len : SHA_256_BLOCKSIZE - cur->holdlength;

	memcpy(&cur->buffer[cur->holdlength], data, avail_space);
	cur->holdlength += avail_space;
	data += avail_space;
	len -= avail_space;
	
	// If that just left our buffer with a full block, process it.
	if (cur->holdlength == SHA_256_BLOCKSIZE)
	{
		sha256_process(cur, cur->buffer);
		cur->bits += SHA_256_BLOCKSIZEBITS;
		cur->holdlength = 0;
	}	
    }
	
    // Right now holdlength holds the leftover bytes that we need to process,
    // so be sure to increment our bit count.
    cur->bits += cur->holdlength * 8;
}
 
/******************************************************************************
/* sha256_finish
/*
/* Handles the final few transformations. This includes taking care of extra 
/*  bytes that did not reach a full block by A) padding them with zeroes and
/*  transforming if > 56, AND/OR B) padding with zeroes and the number of bits
/*  and transforming.
/*
/******************************************************************************/
void sha256_finish (sha256_context *cur, U8 *res )
{
    // We need to pad the start of our data with a 1 and the end of our
    // data with a bunch of zeroes
    cur->buffer[cur->holdlength++] = 0x80;

    // If our buffer holds more than 56 bytes (64-8) we are going to 
    // pad it with zeros and shove it off for compression.
    if (cur->holdlength > SHA_256_BLOCKSIZE - 8)
    {
	memset(&cur->buffer[cur->holdlength++], (U8)0, (SHA_256_BLOCKSIZE - cur->holdlength));
	sha256_process(cur, cur->buffer);
	cur->holdlength = 0;
    }
	
    // Prepare for the final compression step. Pad zeros until we have just
    // enough room to pad the number of bits onto the end.
    memset(&cur->buffer[cur->holdlength++], (U8)0, (56 - cur->holdlength));

    // Pad our data with the length, fire off a transformation and we are
    // done!
    //TODO: Fix this, this is not as easy as it should be. 
    U32 length_high = cur->bits >> 32;
    U32 length_low = cur->bits & 0xffffffff;
								
    U32_TO_U8(length_high, cur->buffer, 56);
    U32_TO_U8(length_low, cur->buffer, 60);

    sha256_process(cur, cur->buffer);
	
    // Transfer our result (in cur->state) to our result pointer.
    U8 i;
    for (i = 0; i <8; i++)
    {
    	U32_TO_U8 (cur->state[i], res, i*4);
    }
}

/******************************************************************************
/* sha256_tohex
/*
/* Reuse our buffer to maintain a readable hex string of the result.
/*
/******************************************************************************/
static 
void sha256_tohex(sha256_context *cur, U8* res)
{
    U8 i;
    //Reuse the buffer space to store a "hex-converted" version
    //of the hash result.
    for(i=0; i<32; i++)
    {
	cur->buffer[i*2] = hex_digits[res[i] >> 0x4];
	cur->buffer[i*2+1] = hex_digits[res[i] & 0xF];
    }
}
