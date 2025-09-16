#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

#define HASH_SIZE 65
#define MAX_TRANSACTIONS 10
#define MAX_TX_LENGTH 128

// -------------------- BLOCK STRUCT --------------------
typedef struct Block {
    int index;
    char timestamp[32];
    char transactions[MAX_TRANSACTIONS][MAX_TX_LENGTH];
    int transaction_count;
    char prev_hash[HASH_SIZE];
    char hash[HASH_SIZE];
    struct Block *next;
} Block;

Block *head = NULL;

// -------------------- SHA-256 FUNCTION --------------------
void calculate_sha256(const char *string, char outputBuffer[HASH_SIZE]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)string, strlen(string), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);

    outputBuffer[HASH_SIZE - 1] = '\0';
}

// -------------------- HASH A BLOCK --------------------
void calculate_block_hash(Block *block) {
    char input[2048] = "";
    char tx_concat[1024] = "";

    for (int i = 0; i < block->transaction_count; i++) {
        strcat(tx_concat, block->transactions[i]);
    }

    snprintf(input, sizeof(input), "%d%s%s%s",
             block->index, block->timestamp, tx_concat, block->prev_hash);

    calculate_sha256(input, block->hash);
}

// -------------------- CREATE A NEW BLOCK --------------------
Block *create_block(int index, const char *prev_hash) {
    Block *new_block = (Block *)malloc(sizeof(Block));
    if (!new_block) {
        perror("Failed to allocate memory for block");
        exit(1);
    }

    new_block->index = index;

    time_t now = time(NULL);
    strftime(new_block->timestamp, sizeof(new_block->timestamp),
             "%Y-%m-%d %H:%M:%S", localtime(&now));

    new_block->transaction_count = 0;

    strncpy(new_block->prev_hash, prev_hash, HASH_SIZE - 1);
    new_block->prev_hash[HASH_SIZE - 1] = '\0';

    calculate_block_hash(new_block);

    new_block->next = NULL;
    return new_block;
}

// -------------------- ADD TRANSACTION --------------------
void add_transaction(Block *block, const char *transaction) {
    if (block->transaction_count < MAX_TRANSACTIONS) {
        strncpy(block->transactions[block->transaction_count],
                transaction, MAX_TX_LENGTH - 1);
        block->transactions[block->transaction_count][MAX_TX_LENGTH - 1] = '\0';
        block->transaction_count++;

        calculate_block_hash(block);
    } else {
        printf("⚠️ Transaction limit reached for block %d!\n", block->index);
    }
}

// -------------------- VALIDATE CHAIN --------------------
int validate_chain() {
    Block *current = head;
    while (current != NULL && current->next != NULL) {
        char recalculated_hash[HASH_SIZE];
        calculate_block_hash(current);
        strncpy(recalculated_hash, current->hash, HASH_SIZE);

        if (strcmp(current->hash, recalculated_hash) != 0) {
            printf("Tampered block detected at index %d!\n", current->index);
            return 0;
        }

        // Check hash link consistency
        if (strcmp(current->hash, current->next->prev_hash) != 0) {
            printf("Hash mismatch between block %d and %d!\n",
                   current->index, current->next->index);
            return 0;
        }

        current = current->next;
    }
    return 1;
}

// -------------------- ADD BLOCK --------------------
void add_block() {
    if (!validate_chain()) {
        printf("Blockchain invalid. Cannot add new block.\n");
        return;
    }

    if (head == NULL) {
        head = create_block(0, "0");
    } else {
        Block *current = head;
        while (current->next != NULL)
            current = current->next;

        Block *new_block = create_block(current->index + 1, current->hash);
        current->next = new_block;
    }
    printf("New block added successfully!\n");
}

// -------------------- DISPLAY BLOCKCHAIN --------------------
void display_chain() {
    Block *current = head;
    while (current != NULL) {
        printf("----- Block %d -----\n", current->index);
        printf("Timestamp : %s\n", current->timestamp);
        printf("Prev Hash : %s\n", current->prev_hash);
        printf("Hash      : %s\n", current->hash);

        printf("Transactions (%d):\n", current->transaction_count);
        for (int i = 0; i < current->transaction_count; i++) {
            printf("   - %s\n", current->transactions[i]);
        }

        printf("--------------------\n");
        current = current->next;
    }
}

// -------------------- MAIN --------------------
int main() {
    add_block(); // Genesis
    add_transaction(head, "Alice pays Bob 10 BTC");
    add_transaction(head, "Charlie pays Dave 5 BTC");

    add_block();
    add_transaction(head->next, "Eve pays Frank 7 BTC");

    add_block();
    add_transaction(head->next->next, "George pays Hannah 3 BTC");

    printf("\n=== Blockchain with Transactions ===\n");
    display_chain();

    return 0;
}
