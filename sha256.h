#ifndef SHIZC_SHA
#define SHIZC_SHA

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BIG_S1(x) (ROTR((x), 6) ^ ROTR((x), 11) ^ ROTR((x), 25))
#define BIG_S0(x) (ROTR((x), (2)) ^ ROTR((x), 13) ^ ROTR((x), 22))
#define SMALL_S0(x) (ROTR((x),7) ^ ROTR((x), 18) ^ ((x) >> 3))
#define SMALL_S1(x) (ROTR((x), 17) ^ ROTR((x), 19) ^ ((x) >> 10))


const uint32_t k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
			0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
			0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
			0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
			0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
			0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void sha256(unsigned char *hash, const char *msg_proto, size_t msg_length_bytes){
  uint32_t * digest = (uint32_t*)hash;
  digest[0] = 0x6a09e667;
  digest[1] = 0xbb67ae85;
  digest[2] = 0x3c6ef372;
  digest[3] = 0xa54ff53a;
  digest[4] = 0x510e527f;
  digest[5] = 0x9b05688c;
  digest[6] = 0x1f83d9ab;
  digest[7] = 0x5be0cd19;

  uint32_t L = msg_length_bytes*8; // begin with the original message of length L bits
  uint32_t buffer_size = 64*((L+65)/512+1); // Magic calculations derived from the K equation
  unsigned char *msg = (unsigned char*)calloc(buffer_size, sizeof(char));
  memcpy(msg, msg_proto, msg_length_bytes);
  
  msg[L/8] = 0b10000000; // Append a single 1 bit
  //The K bits need not be calculated due to calloc

  msg[buffer_size-4] = *((unsigned char*)&L+3);// [0]
  msg[buffer_size-3] = *((unsigned char*)&L+2);// [1]
  msg[buffer_size-2] = *((unsigned char*)&L+1);// [2]
  msg[buffer_size-1] = *((unsigned char*)&L);  // [3] // TODO :endian?

  for(unsigned char* token = &msg[0]; token<&msg[buffer_size]; token+=64){
    uint32_t w[64];

    for(int i=0; i<16; ++i){ // memcpy(&w[0], &msg[0], 64); with endianess
      *((unsigned char*)&w[i]+3) = token[i*4];
      *((unsigned char*)&w[i]+2) = token[i*4+1];
      *((unsigned char*)&w[i]+1) = token[i*4+2];
      *(unsigned char*)&w[i]     = token[i*4+3];
    }
    
    for(int i=16; i<64; ++i)
      w[i] = w[i-16] + SMALL_S0(w[i-15]) + w[i-7] + SMALL_S1(w[i-2]);

    uint32_t a = digest[0];
    uint32_t b = digest[1];
    uint32_t c = digest[2];
    uint32_t d = digest[3];
    uint32_t e = digest[4];
    uint32_t f = digest[5];
    uint32_t g = digest[6];
    uint32_t h = digest[7];  

    for(int i=0; i<64; ++i){
      uint32_t temp1 = h + BIG_S1(e) + CH(e, f, g) + k[i] + w[i];
      uint32_t temp2 = BIG_S0(a) + MAJ(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    digest[0]+=a;    
    digest[1]+=b;
    digest[2]+=c;
    digest[3]+=d;
    digest[4]+=e;
    digest[5]+=f;
    digest[6]+=g;
    digest[7]+=h;
  }
  unsigned char tmp;

  for(int i=0; i<8; ++i){ // convert to hex stream
    tmp = *((unsigned char*)&digest[i]);
    *((unsigned char*)&digest[i]) = *((unsigned char*)&digest[i]+3);
    *((unsigned char*)&digest[i]+3) = tmp;
  
    tmp = *((unsigned char*)&digest[i]+1);
    *((unsigned char*)&digest[i]+1) = *((unsigned char*)&digest[i]+2);
    *((unsigned char*)&digest[i]+2) = tmp;
  }
  free(msg);
}

#define sha256_inline(digest, msg_proto) sha256(digest, msg_proto, strlen(msg_proto))

#define CAT(A, B) CAT2(A, B)
#define CAT2(A, B) A ## B
#define COUNT_PARMS2(_1, _2, _3, _, ...) _
#define COUNT_PARMS(...) COUNT_PARMS2(__VA_ARGS__, , _inline, 1)
#define sha256(...) CAT(sha256, COUNT_PARMS(__VA_ARGS__))(__VA_ARGS__)

#endif
