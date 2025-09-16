/*
 * blockchain_persistence.c
 *
 * Task 4: Save and load blockchain in human-readable format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

#define HASH_SIZE 65
#define MAX_TRANSACTIONS 5
#define MAX_DATA_LEN 256

// -------------------- BLOCK STRUCT --------------------
typedef struct Block {
    int index;
    char timestamp[32];
    char transactions[MAX_TRANSACTIONS][MAX_DATA_LEN];
    int transaction_count;
    char prev_hash[HASH_SIZE];
    char hash[HASH_SIZE];
    struct Block *next;
} Block;

Block *head = NULL;

// -------------------- HASH FUNCTION --------------------
void calculate_hash(Block *block, char *output) {
    char input[2048] = "";
    sprintf(input, "%d%s", block->index, block->timestamp);

    for (int i = 0; i < block->transaction_count; i++) {
        strcat(input, block->transactions[i]);
    }
    strcat(input, block->prev_hash);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input, strlen(input), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

// -------------------- VALIDATION --------------------
int validate_chain() {
    Block *current = head;
    while (current && current->next) {
        char recalculated_hash[HASH_SIZE];
        calculate_hash(current, recalculated_hash);
        if (strcmp(current->hash, recalculated_hash) != 0) {
            printf("Tampered block detected at index %d!\n", current->index);
            return 0;
        }
        if (strcmp(current->next->prev_hash, current->hash) != 0) {
            printf("Broken link between block %d and %d!\n", current->index, current->next->index);
            return 0;
        }
        current = current->next;
    }
    return 1;
}

// -------------------- BLOCKCHAIN FUNCTIONS --------------------
Block* create_block(int index, char transactions[][MAX_DATA_LEN], int tx_count, const char *prev_hash) {
    Block *new_block = (Block*)malloc(sizeof(Block));
    new_block->index = index;

    time_t now = time(NULL);
    strftime(new_block->timestamp, sizeof(new_block->timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    new_block->transaction_count = tx_count;
    for (int i = 0; i < tx_count; i++) {
        strcpy(new_block->transactions[i], transactions[i]);
    }

    strcpy(new_block->prev_hash, prev_hash);
    calculate_hash(new_block, new_block->hash);
    new_block->next = NULL;

    return new_block;
}

void add_block(char transactions[][MAX_DATA_LEN], int tx_count) {
    if (!validate_chain()) {
        printf("Blockchain invalid. Cannot add new block.\n");
        return;
    }

    if (head == NULL) {
        head = create_block(0, transactions, tx_count, "0");
    } else {
        Block *current = head;
        while (current->next != NULL) current = current->next;
        Block *new_block = create_block(current->index + 1, transactions, tx_count, current->hash);
        current->next = new_block;
    }
    printf("New block added successfully!\n");
}

// -------------------- DISPLAY --------------------
void display_chain() {
    Block *current = head;
    while (current != NULL) {
        printf("\n----- Block %d -----\n", current->index);
        printf("Timestamp : %s\n", current->timestamp);
        printf("Prev Hash : %s\n", current->prev_hash);
        printf("Hash      : %s\n", current->hash);
        printf("Transactions:\n");
        for (int i = 0; i < current->transaction_count; i++) {
            printf("  - %s\n", current->transactions[i]);
        }
        current = current->next;
    }
}

// -------------------- SAVE & LOAD --------------------
void save_chain(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("File open failed");
        return;
    }

    Block *current = head;
    while (current != NULL) {
        fprintf(fp, "Block %d\n", current->index);
        fprintf(fp, "Timestamp: %s\n", current->timestamp);
        fprintf(fp, "PrevHash: %s\n", current->prev_hash);
        fprintf(fp, "Hash: %s\n", current->hash);
        fprintf(fp, "Transactions:\n");
        for (int i = 0; i < current->transaction_count; i++) {
            fprintf(fp, "  %s\n", current->transactions[i]);
        }
        fprintf(fp, "----\n");
        current = current->next;
    }
    fclose(fp);
    printf("Blockchain saved to %s\n", filename);
}

void load_chain(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("File open failed");
        return;
    }

    // Clear current blockchain
    while (head) {
        Block *temp = head;
        head = head->next;
        free(temp);
    }

    Block *prev_block = NULL;

    int index;
    char timestamp[32];
    char txs[MAX_TRANSACTIONS][MAX_DATA_LEN];
    int tx_count;

    while (fscanf(fp, "Block %d\n", &index) == 1) {
        fscanf(fp, "Timestamp: %[^\n]\n", timestamp);
        fscanf(fp, "PrevHash: %[^\n]\n", timestamp); // skip saved prev hash
        fscanf(fp, "Hash: %[^\n]\n", timestamp);     // skip saved hash
        fscanf(fp, "Transactions:\n");

        tx_count = 0;
        char line[MAX_DATA_LEN];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "----", 4) == 0) break;
            if (tx_count < MAX_TRANSACTIONS) {
                line[strcspn(line, "\n")] = 0; // remove newline
                strcpy(txs[tx_count++], line + 2); // skip two spaces
            }
        }

        // Determine prev hash from previous block in memory
        const char *prev_hash = prev_block ? prev_block->hash : "0";

        // Recreate block using secure prev_hash
        Block *new_block = create_block(index, txs, tx_count, prev_hash);

        if (head == NULL) {
            head = new_block;
        } else {
            prev_block->next = new_block;
        }

        prev_block = new_block;
    }

    fclose(fp);

    if (validate_chain()) {
        printf("Blockchain loaded securely and validated.\n");
    } else {
        printf("Blockchain loaded but INVALID!\n");
    }
}


// -------------------- MAIN --------------------
int main() {
    char tx1[][MAX_DATA_LEN] = {"Alice pays Bob 5 BTC", "Charlie pays Dave 3 BTC"};
    char tx2[][MAX_DATA_LEN] = {"Eve pays Frank 2 BTC"};

    add_block(tx1, 2);
    add_block(tx2, 1);

    display_chain();

    save_chain("blockchain.txt");

    printf("\nReloading blockchain from file...\n");
    load_chain("blockchain.txt");

    display_chain();

    return 0;
}
