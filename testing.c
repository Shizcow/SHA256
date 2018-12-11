#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define MASK32 0

uint32_t mask_32bit(uint32_t x) { // TODO: inline?
  return x
#if (MASK32==1)
    & 0xffffffff
#endif
    ;
}

uint32_t rotr(uint32_t x, size_t n) { // TODO: inline?
  return mask_32bit((x >> n) | (x << (32 - n)));
}


const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
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

int main(){
  uint32_t digest[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
			0xa54ff53a, 0x510e527f, 0x9b05688c,
			0x1f83d9ab, 0x5be0cd19};

  
  unsigned char msg[64] = "";
  uint32_t L = strlen(msg)*8; // begin with the original message of length L bits
  msg[L/8] = 0b10000000; // Append a single 1 bit
  //The K bits need not be calculated due to calloc

  
  { uint16_t x = 1;   // Append L as a 64-bit big-endian integer
    if((int)(((char *)&x)[0])){ // on a big-endian system (typical)
      // L = [0][1][2][3];
      *(uint32_t*)&msg[56] = L;
    } else {                    // on a little-endian system
      // L = [3][2][1][0];
      msg[56] = *((unsigned char*)&L+3);// [0]
      msg[57] = *((unsigned char*)&L+2);// [1]
      msg[58] = *((unsigned char*)&L+1);// [2]
      msg[59] = *((unsigned char*)&L);  // [3]
    }
    //The last (largest) bits are already zero and thus don't need to be written
  }

  uint32_t w[64];
  memcpy(&w[0], &msg[0], 64);

  for(int i=16; i<64; ++i){
    uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
    uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
    w[i] = mask_32bit(w[i-16] + s0 + w[i-7] + s1); // mask32bit?
  }

  uint32_t a = digest[0];
  uint32_t b = digest[1];
  uint32_t c = digest[2];
  uint32_t d = digest[3];
  uint32_t e = digest[4];
  uint32_t f = digest[5];
  uint32_t g = digest[6];
  uint32_t h = digest[7];

  for(int i=0; i<64; ++i){
    uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp1 = h + S1 + ch + k[i] + w[i];
    uint32_t temp2 = S0 + maj;
    h = g;
    g = f;
    f = e;
    e = mask_32bit(d + temp1);
    d = c;
    c = b;
    b = a;
    a = mask_32bit(temp1 + temp2);
  }

  digest[0]+=a;
  digest[1]+=b;
  digest[2]+=c;
  digest[3]+=d;
  digest[4]+=e;
  digest[5]+=f;
  digest[6]+=g;
  digest[7]+=h;

  for(int i=0; i<8; ++i)
    digest[i]=mask_32bit(digest[i]);

  unsigned char *print = (unsigned char*)&digest[0];

  for(int i=0; i<8*4; ++i)
    printf("%x ", print[i]);
  putchar('\n');

  
  return 0;
}
