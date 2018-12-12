#include "sha256.h"
#include "mgf1.h"
#include <time.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <assert.h>

void test(){
  size_t rands = rand()%10;
  char *msg_proto = (char*)malloc(sizeof(char)*rands+1);
  for(size_t i=0; i<rands; ++i)
    msg_proto[i] = /*rand()%255+1*/'a'; // No null chars
  msg_proto[rands] = 0;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  sha256(hash, msg_proto);

  unsigned char hash_ossl[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, msg_proto, rands);
  SHA256_Final(hash_ossl, &sha256);

  int success = 1;
  for(int i=0; success&&i<32; ++i)
    success = (hash[i]==hash_ossl[i]);
  
  if(!success){
    printf("Failed on message: %s\n", msg_proto);
    printf("OpenSSL reference: ");
    for(int i=0; i<32; ++i){
      if(hash_ossl[0]<0xf)
	putchar('0');
      printf("%x ", hash[i]);
    }
    putchar('\n');
    printf("local SHA256 impl: ");
    for(int i=0; i<32; ++i){
      if(hash[0]<0xf)
	putchar('0');
      printf("%x ", hash[i]);
    }
    putchar('\n');
    exit(1);
  }
  free(msg_proto);
}


int main(){
  srand(time(NULL));

  printf("Testing SHA256\n");
  for(int i=0; i<10000; ++i)
    test();

  unsigned char mgf1_vector[50] = {56, 37, 118, 167, 132, 16, 33, 204, 40, 252, 76, 9, 72, 117, 63, 184, 49, 32, 144, 206, 169, 66, 234, 76, 78, 115, 93, 16, 220, 114, 75, 21, 95, 159, 96, 105, 242, 137, 214, 29, 172, 160, 203, 129, 69, 2, 239, 4, 234, 225}; 
  
  printf("Testing mgf1\n");
  unsigned char mask[50];
  mgf1(mask, "bar", 50);
  for(int i=0; i<50; ++i)
    if(mgf1_vector[i]!=mask[i]){
      printf("Test failed on message \"bar\". Output is as follows:\n");
      for(int i=0; i<50; ++i){
	if(mask[i]<0xf)
	  putchar('0');
	printf("%x", (int)mask[i]);
      }
      putchar('\n');
      exit(1);
    }
  
  printf("Tests successful\n");
  return 0;
}
