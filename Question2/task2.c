#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

#define HASH_SIZE 65

typedef struct Block {
    int index;
    char timestamp[32];
    char data[256];
    char prev_hash[HASH_SIZE];
    char hash[HASH_SIZE];
    struct Block *next;
} Block;

Block *head = NULL;

// -------------------- SHA-256 --------------------
void calculate_sha256(const char *string, char outputBuffer[HASH_SIZE]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)string, strlen(string), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);

    outputBuffer[HASH_SIZE - 1] = '\0';
}

// -------------------- BLOCK HASH --------------------
void calculate_block_hash(Block *block, char output_hash[HASH_SIZE]) {
    char input[1024];
    snprintf(input, sizeof(input), "%d%s%s%s",
             block->index, block->timestamp, block->data, block->prev_hash);

    calculate_sha256(input, output_hash);
}

// -------------------- VALIDATE BLOCKCHAIN --------------------
int validate_chain() {
    if (head == NULL) return 1; // empty chain is valid

    Block *current = head;
    while (current != NULL && current->next != NULL) {
        Block *next = current->next;

        // Recalculate hash for current block
        char recalculated_hash[HASH_SIZE];
        calculate_block_hash(current, recalculated_hash);

        if (strcmp(current->hash, recalculated_hash) != 0) {
            printf("Tampered block detected at index %d!\n", current->index);
            return 0;
        }

        if (strcmp(current->hash, next->prev_hash) != 0) {
            printf("Hash mismatch between block %d and %d!\n", current->index, next->index);
            return 0;
        }

        current = current->next;
    }
    return 1;
}

// -------------------- CREATE BLOCK --------------------
Block *create_block(int index, const char *data, const char *prev_hash) {
    Block *new_block = (Block *)malloc(sizeof(Block));
    new_block->index = index;

    time_t now = time(NULL);
    strftime(new_block->timestamp, sizeof(new_block->timestamp),
             "%Y-%m-%d %H:%M:%S", localtime(&now));

    strncpy(new_block->data, data, sizeof(new_block->data) - 1);
    new_block->data[sizeof(new_block->data) - 1] = '\0';

    strncpy(new_block->prev_hash, prev_hash, HASH_SIZE - 1);
    new_block->prev_hash[HASH_SIZE - 1] = '\0';

    // Calculate hash
    calculate_block_hash(new_block, new_block->hash);
    new_block->next = NULL;

    return new_block;
}

// -------------------- ADD BLOCK --------------------
void add_block(const char *data) {
    if (!validate_chain()) {
        printf("Blockchain invalid. Cannot add new block.\n");
        return;
    }

    if (head == NULL) {
        head = create_block(0, data, "0"); // Genesis block
    } else {
        Block *current = head;
        while (current->next != NULL)
            current = current->next;

        Block *new_block = create_block(current->index + 1, data, current->hash);
        current->next = new_block;
    }
    printf("Block added successfully!\n");
}

// -------------------- DISPLAY BLOCKCHAIN --------------------
void display_chain() {
    Block *current = head;
    while (current != NULL) {
        printf("----- Block %d -----\n", current->index);
        printf("Timestamp : %s\n", current->timestamp);
        printf("Data      : %s\n", current->data);
        printf("Prev Hash : %s\n", current->prev_hash);
        printf("Hash      : %s\n", current->hash);
        printf("--------------------\n");
        current = current->next;
    }
}

// -------------------- MAIN --------------------
int main() {
    add_block("Genesis Block");
    add_block("Second Block - Blockchain Demo");
    add_block("Third Block - Testing Integrity");

    printf("\n=== Blockchain ===\n");
    display_chain();

    return 0;
}
