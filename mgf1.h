#ifndef SHIZC_MGF
#define SHIZC_MGF

#include "sha256.h"
#include <string.h>

unsigned char* __mgf1(const unsigned char* input, size_t input_size, size_t length){
  unsigned char *output = (unsigned char*)malloc(sizeof(unsigned char)*((length-1)/SHA256_DIGEST_LENGTH+1)*SHA256_DIGEST_LENGTH);
  unsigned char *_input = (unsigned char*)malloc(sizeof(unsigned char)*(input_size+4)); // make room for hash addition
  unsigned char *hash_add = _input+input_size;
  memcpy(_input, input, input_size);
  for(uint32_t counter=0; counter<((length-1)/SHA256_DIGEST_LENGTH+1); ++counter){
    for(int i=3; i>=0; --i)
      hash_add[3-i] = *((unsigned char*)&counter+i); // i2osp
    sha256(output+SHA256_DIGEST_LENGTH*counter, _input, input_size+4);
  }
  free(_input);
  return output;
}

void mgf1(unsigned char* rop, const unsigned char* input, size_t input_size, size_t length/*=strlen(input)*/){ // perform mgf and copy into rop
  unsigned char *output = __mgf1(input, input_size, length);
  memcpy(rop, output, length);
  free(output);
}
inline void mgf1_string(unsigned char* rop, const char* input){
  mgf1(rop, (const unsigned char*)input, input_size, strlen(input));
}

void mgf1_xor(unsigned char* rop, const unsigned char* input, size_t input_size, size_t length/*=strlen(input)*/){ // perform mfg1 and xor instead of memcpy into rop
  unsigned char *output = __mgf1(input, input_size, length);
  for(size_t i=0; i<length; ++i)
    rop[i]^=output[i];
  free(output);
}
inline void mgf1_xor_string(unsigned char* rop, const char* input){
  mgf1_xor(rop, (const unsigned char*)input, input_size, strlen(input));
}


#ifndef SHIZ_CAT
#define SHIZC_CAT(A, B) SHIZC_CAT2(A, B)
#endif

#ifndef SHIZC_CAT2
#define SHIZC_CAT2(A, B) A ## B
#endif

#define MGF1_SHIZC_COUNT_PARMS2(_1, _2, _3, _4, _, ...) _
#define MGF1_SHIZC_COUNT_PARMS(...) MGF1_SHIZC_COUNT_PARMS2(__VA_ARGS__, , _string, 2, 1)
#define mgf1(...) SHIZC_CAT(mgf1, MGF1_SHIZC_COUNT_PARMS(__VA_ARGS__))(__VA_ARGS__)

#define MGF1_XOR_SHIZC_COUNT_PARMS2(_1, _2, _3, _4, _, ...) _
#define MGF1_XOR_SHIZC_COUNT_PARMS(...) MGF1_XOR_SHIZC_COUNT_PARMS2(__VA_ARGS__, , _string, 2, 1)
#define mgf1_xor(...) SHIZC_CAT(mgf1_xor, MGF1_XOR_SHIZC_COUNT_PARMS(__VA_ARGS__))(__VA_ARGS__)

#endif
