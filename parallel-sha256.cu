#include <cuda.h>
#include <stdio.h>
#include <sys/time.h>
#include <math.h>
#include "sha256.cuh"

#define HASH_LENGTH 32 // Define the hash length
#define MAX_PASSWORD_LENGTH 10 // Define the maximum password length
#define THREADS_PER_BLOCK 256 // Number of threads per block
#define NUMBER_OF_BLOCKS 512 // Number of blocks

__constant__ char alphabet[63]; // The array of possible characters in a password

// Password generator function
__device__ void password_generator(char *password, unsigned long long index, int password_length) {
    // Generate a password from the given index
    for (int i = 0; i < password_length; i++) {
        password[i] = alphabet[index % 63];
        index /= 63;
    }
    password[password_length] = '\0';
}

// Memory comparison function
__device__ int device_memcmp(const unsigned char* a, const unsigned char* b, int size) {
    // Compare two given arrays of the specified size
    for (int i = 0; i < size; i++) {
        if (a[i] != b[i]) {
            return 1;
        }
    }
    return 0;
}

__device__ int found_flag = 0; // Flag to check if password has been found

__global__ void password_cracker(char *device_password, int original_password_length, int generated_password_length, unsigned long long start_index, unsigned long long password_count, uint32_t *processedPasswords) {
    // Early return if password has been found
    if (found_flag) {
        return;
    }
    unsigned long long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    // Only continue if the current thread index is within the total number of passwords
    if (thread_index < password_count) {
        char password[MAX_PASSWORD_LENGTH + 1];
        // Generate a password using the current thread index
        password_generator(password, start_index + thread_index, generated_password_length);

        unsigned char hash[HASH_LENGTH];
        unsigned char device_hash[HASH_LENGTH];
        SHA256_CTX sha256;

        // Calculate hash of the generated password
        sha256_init(&sha256);
        sha256_update(&sha256, (BYTE*)password, generated_password_length); // Use generated_password_length instead of MAX_PASSWORD_LENGTH
        sha256_final(&sha256, hash);

        // Calculate hash of the original password
        sha256_init(&sha256);
        sha256_update(&sha256, (BYTE*)device_password, original_password_length);
        sha256_final(&sha256, device_hash);

        // Compare the two hashes
        if (device_memcmp(hash, device_hash, HASH_LENGTH) == 0) {
            // If hashes match, password has been found
            printf("Password found: %s\n", password);
            found_flag = 1;
            return;
        }
    }
    // Increment the processed passwords counter
    atomicAdd(processedPasswords, 1);
}

// Function to get the current time in milliseconds
long long get_time_in_seconds() {
    struct timeval time;
    gettimeofday(&time, NULL);
    return time.tv_sec * 1000LL + time.tv_usec / 1000;
}

// Main function
int main(int argc, char** argv) {
    // Set the array of possible characters
    char host_alphabet[63] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    // Copy the array to constant memory
    cudaMemcpyToSymbol(alphabet, host_alphabet, sizeof(host_alphabet));

    char host_password[MAX_PASSWORD_LENGTH+1] = "armug"; // The password to crack

     if(argc > 1) {
        strncpy(host_password, argv[1], MAX_PASSWORD_LENGTH); // If a password argument is provided, use it. strncpy prevents buffer overflow.
        host_password[MAX_PASSWORD_LENGTH] = '\0'; // Ensures null termination.
    }
    // Device memory allocation and copying for the original password
    char* device_password;
    int password_length = strlen(host_password) + 1; // +1 for the null terminator
    cudaMalloc((void**)&device_password, password_length * sizeof(char)); // Allocate memory for the full password
    cudaMemcpy(device_password, host_password, password_length * sizeof(char), cudaMemcpyHostToDevice); // Copy the full password

    // Calculate the total number of possible passwords
    unsigned long long total_passwords = powl(strlen(host_alphabet), MAX_PASSWORD_LENGTH);

    // Get the start time
    long long start_time = get_time_in_seconds();

    // Device memory allocation and copying for the counter of processed passwords
    uint32_t *device_processedPasswords, host_processedPasswords = 0;
    cudaMalloc((void**)&device_processedPasswords, sizeof(uint32_t));
    cudaMemcpy(device_processedPasswords, &host_processedPasswords, sizeof(uint32_t), cudaMemcpyHostToDevice);

    // Loop over all possible password lengths
    for (int password_length = 1; password_length <= MAX_PASSWORD_LENGTH; password_length++) {
        // Calculate the total number of passwords of the current length
        unsigned long long password_count = powl(strlen(host_alphabet), password_length);

        // Loop over all possible starting indices for the password generation
        for (unsigned long long start_index = 0; start_index < password_count; start_index += THREADS_PER_BLOCK * NUMBER_OF_BLOCKS) {
            // Calculate the number of remaining passwords and the number of blocks
            unsigned long long remaining_passwords = min(password_count - start_index, (unsigned long long)(THREADS_PER_BLOCK * NUMBER_OF_BLOCKS));
            unsigned long long block_count = min((remaining_passwords + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK, (unsigned long long)NUMBER_OF_BLOCKS);
            
            // Call the password cracker kernel
            password_cracker<<<block_count, THREADS_PER_BLOCK>>>(device_password, strlen(host_password), password_length, start_index, remaining_passwords, device_processedPasswords);
            
            cudaDeviceSynchronize(); // Synchronize device
            
            // Check if password has been found
            int host_found_flag;
            cudaMemcpyFromSymbol(&host_found_flag, found_flag, sizeof(int), 0, cudaMemcpyDeviceToHost);
            if (host_found_flag) {
                //printf("Password found!\n");
                long long elapsed = get_time_in_seconds() - start_time;
                //printf("Hashes (%'lu) Seconds (%'f) Hashes/sec (%'lu)\r", host_processedPasswords, ((float) elapsed) / 1000.0, (unsigned long) ((double) host_processedPasswords / (double) elapsed) * 1000);
                break;
            }
            // Copy the number of processed passwords from device to host
            cudaMemcpy(&host_processedPasswords, device_processedPasswords, sizeof(uint32_t), cudaMemcpyDeviceToHost);
            // Print progress information
            long long elapsed = get_time_in_seconds() - start_time;
            printf("Hashes (%'lu) Seconds (%'f) Hashes/sec (%'lu)\r\n", host_processedPasswords, ((float) elapsed) / 1000.0, (unsigned long) ((double) host_processedPasswords / (double) elapsed) * 1000);
            fflush(stdout); // Flush the output buffer to ensure immediate printing
        }
        if (found_flag) {
            break;
        }
    }

    printf("\n");
    long long elapsed = get_time_in_seconds() - start_time;

    printf("Hashes processed (%'lu) Time Taken in seconds (%'f) Avg Hashes/sec (%'lu)\n", host_processedPasswords, ((float) elapsed) / 1000.0, (unsigned long) ((double) host_processedPasswords / (double) elapsed) * 1000);
    // Free the device memory
    cudaFree(device_password);
    cudaFree(device_processedPasswords);

    return 0;
}
