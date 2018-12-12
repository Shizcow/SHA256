#include "SHA256.h"
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
    printf("local RSA256 impl: ");
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

  for(int i=0; i<10000; ++i)
    test();
  printf("Tests completed successfully\n");
  return 0;
}
