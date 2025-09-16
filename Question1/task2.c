#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

#define HASH_SIZE 65
#define MAX_BLOCKS 10

typedef struct Block {
    int index;
    char timestamp[32];
    char data[256];
    char prev_hash[HASH_SIZE];
    char hash[HASH_SIZE];
} Block;

void calculate_hash(Block *block, char *output_hash) {
    char input[1024];
    snprintf(input, sizeof(input), "%d%s%s%s",
             block->index, block->timestamp, block->data, block->prev_hash);

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input, strlen(input), digest);

    // Convert to hex string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&output_hash[i*2], "%02x", digest[i]);
    }
    output_hash[64] = '\0';
}

Block create_block(int index, const char *data, const char *prev_hash) {
    Block block;
    block.index = index;

    time_t now = time(NULL);
    strftime(block.timestamp, sizeof(block.timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    strncpy(block.data, data, sizeof(block.data) - 1);
    block.data[sizeof(block.data) - 1] = '\0';

    strncpy(block.prev_hash, prev_hash, HASH_SIZE);
    block.prev_hash[HASH_SIZE - 1] = '\0';

    // calculate hash
    calculate_hash(&block, block.hash);

    return block;
}

int validate_chain(Block *chain, int length) {
    for (int i = 1; i < length; i++) {
        char check_hash[HASH_SIZE];
        calculate_hash(&chain[i], check_hash);
        if (strcmp(chain[i].hash, check_hash) != 0) {
            printf("Block %d: INVALID hash!\n", i);
            return 0;
        }

        if (strcmp(chain[i].prev_hash, chain[i-1].hash) != 0) {
            printf("Block %d: INVALID previous hash!\n", i);
            return 0;
        }
    }
    return 1;
}

// Function to add a new block and validate immediately
int add_block(Block *blockchain, int *chain_length, const char *data) {
    if (*chain_length >= MAX_BLOCKS) {
        printf("Blockchain full!\n");
        return 0;
    }

    Block new_block = create_block(*chain_length, data, blockchain[*chain_length - 1].hash);
    blockchain[*chain_length] = new_block;
    (*chain_length)++;

    printf("\nAdded Block %d\n", new_block.index);
    printf("Timestamp: %s\n", new_block.timestamp);
    printf("Data: %s\n", new_block.data);
    printf("Prev Hash: %s\n", new_block.prev_hash);
    printf("Hash: %s\n", new_block.hash);

    if (!validate_chain(blockchain, *chain_length)) {
        printf("\nBlockchain is INVALID after adding block %d!\n", new_block.index);
        return 0;
    } else {
        printf("\nBlockchain is VALID after adding block %d\n", new_block.index);
    }

    return 1;
}

int main() {
    Block blockchain[MAX_BLOCKS];
    int chain_length = 0;

    // Create Genesis Block
    blockchain[0] = create_block(0, "Genesis Block", "0");
    chain_length = 1;

    printf("\nGenesis Block Created\n");
    printf("Hash: %s\n", blockchain[0].hash);

    // Add more blocks with validation each time
    add_block(blockchain, &chain_length, "Alice pays Bob 10 BTC");
    add_block(blockchain, &chain_length, "Bob pays Charlie 5 BTC");
    add_block(blockchain, &chain_length, "Charlie pays Dave 2 BTC");

    return 0;
}
