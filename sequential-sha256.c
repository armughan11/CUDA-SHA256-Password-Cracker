#include <stdio.h>
#include <sys/time.h>
#include <math.h>
#include <string.h>
#include "sha256.h"  // Include SHA256 library

#define HASH_LENGTH 32 // Hash length
#define MAX_PASSWORD_LENGTH 10 // Maximum password length

// Define alphabet for generating possible passwords
char alphabet[63] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// Function to generate a password given an index
void password_generator(char *password, unsigned long long index, int password_length) {
    int i;
    for (i = 0; i < password_length; i++) {
        password[i] = alphabet[index % 63]; // Select alphabet character based on index
        index /= 63;  // Update index for next iteration
    }
    password[password_length] = '\0'; // Null terminate the generated password
}

// Function to compare two strings in memory
int host_memcmp(const unsigned char* a, const unsigned char* b, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (a[i] != b[i]) { // If mismatch found, return 1
            return 1;
        }
    }
    return 0; // If no mismatch found, return 0
}

// Function to get current time in seconds
long long get_time_in_seconds() {
    struct timeval time;
    gettimeofday(&time, NULL);
    return time.tv_sec * 1000LL + time.tv_usec / 1000;
}

int main(int argc, char** argv) {
    char host_password[MAX_PASSWORD_LENGTH + 1] = "armu";

    if(argc > 1) {
        strncpy(host_password, argv[1], MAX_PASSWORD_LENGTH); // If a password argument is provided, use it. strncpy prevents buffer overflow.
        host_password[MAX_PASSWORD_LENGTH] = '\0'; // Ensures null termination.
    }
    // Calculate total possible passwords
    unsigned long long total_passwords = powl(strlen(alphabet), MAX_PASSWORD_LENGTH);

    // Compute the hash of the password
    unsigned char host_password_hash[HASH_LENGTH];
    SHA256_CTX sha256;
    sha256_init(&sha256);
    sha256_update(&sha256, (BYTE*)host_password, strlen(host_password));
    sha256_final(&sha256, host_password_hash);

    // Get the start time
    long long start_time = get_time_in_seconds();

    // Initialize counter for processed passwords
    unsigned long long processedPasswords = 0;

    int password_length;
    // Iterate over all possible password lengths
    for (password_length = 1; password_length <= MAX_PASSWORD_LENGTH; password_length++) {
        // Calculate the total number of passwords of current length
        unsigned long long password_count = powl(strlen(alphabet), password_length);

        unsigned long long index;
        // Iterate over all possible starting indices
        for (index = 0; index < password_count; index++) {
            char password[MAX_PASSWORD_LENGTH + 1];
            // Generate password at current index
            password_generator(password, index, password_length);

            // Compute the hash of the generated password
            unsigned char hash[HASH_LENGTH];
            SHA256_CTX sha256;
            sha256_init(&sha256);
            sha256_update(&sha256, (BYTE*)password, password_length);
            sha256_final(&sha256, hash);

            // If the generated password hash matches the original password hash, password is found
            if (host_memcmp(hash, host_password_hash, HASH_LENGTH) == 0) {
                printf("Password found: %s\n", password);
                long long elapsed = get_time_in_seconds() - start_time;
                printf("Hashes (%'lu) Seconds (%'f) Hashes/sec (%'lu)\r\n", processedPasswords, ((float) elapsed) / 1000.0, (unsigned long) ((double) processedPasswords / (double) elapsed) * 1000);
                return 0;
            }
            processedPasswords++;
        }
        long long elapsed = get_time_in_seconds() - start_time;
        printf("Hashes (%'lu) Seconds (%'f) Hashes/sec (%'lu)\r\n", processedPasswords, ((float) elapsed) / 1000.0, (unsigned long) ((double) processedPasswords / (double) elapsed) * 1000);
    }

    printf("\n");
    return 0;
}

