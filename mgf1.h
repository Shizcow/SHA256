#include "sha256.h"
#include <string.h>

void mgf1(unsigned char* rop, const char* input, size_t length){
  size_t input_size = strlen(input)+4;
  unsigned char *output = (unsigned char*)malloc(sizeof(unsigned char)*((length-1)/SHA256_DIGEST_LENGTH+1)*SHA256_DIGEST_LENGTH);
  unsigned char *_input = (unsigned char*)malloc(sizeof(unsigned char)*(input_size)); // make room for hash addition
  unsigned char *hash_add = _input+input_size-4;
  memcpy(_input, input, input_size-4);
  for(uint32_t counter=0; counter<((length-1)/SHA256_DIGEST_LENGTH+1); ++counter){
    for(int i=3; i>=0; --i)
      hash_add[3-i] = *((unsigned char*)&counter+i); // i2osp
    sha256(output+SHA256_DIGEST_LENGTH*counter, (char*)_input, input_size);
  }
  memcpy(rop, output, length);
  free(output);
  free(_input);
}
