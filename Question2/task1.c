#include <stdio.h>
#include <string.h>
#include <time.h>

#define HASH_SIZE 65

typedef struct Block {
    int index;                 
    char timestamp[32];         
    char data[256];             
    char prev_hash[HASH_SIZE];  
    char hash[HASH_SIZE];    
} Block;

void display_block(Block block) {
    printf("----- Block %d -----\n", block.index);
    printf("Timestamp : %s\n", block.timestamp);
    printf("Data      : %s\n", block.data);
    printf("Prev Hash : %s\n", block.prev_hash);
    printf("Hash      : %s\n", block.hash);
    printf("--------------------\n");
}


int main() {
    Block block;
    block.index = 0;
    time_t now = time(NULL);
    strftime(block.timestamp, sizeof(block.timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    strcpy(block.data, "Genesis Block - First block in the chain");
    strcpy(block.prev_hash, "0");
    strcpy(block.hash, "abc123def456...fakehash");

    display_block(block);

    return 0;
}
