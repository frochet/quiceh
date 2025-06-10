#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>

/*
The maximum output number possible for u64 random functions
*/
#define RAND_U64_MAX (uint64_t)(-1)

#ifdef __cplusplus
extern "C"{
#endif


/*
Return the number of nanoseconds since the last second.
*/
uint64_t random_standard_seed(void);

/*
Set the random seed for all unsecure random functions.
Set this with random_standard_seed if you want some entropy or with a fixed value if you want to always have the same results in a simulation for example.
*/
void random_set_unsecure_seed(uint64_t seed);


/*
Generate an uint64_t integer between the range 0 and random_RAND_U64_MAX using xorshift128+
*/
uint64_t random_unsecure_uint64(void);


/*
Generate a fast random integer in the range given using xorshift128+.
This function is NOT safe for cryptographic applications.
*/
int64_t random_unsecure_int64(int64_t start, int64_t end);

/*
Generate a fast random float in the range given using xorshift128+.
This function is NOT safe for cryptographic applications.
*/
double random_unsecure_float(double start, double end);

/*
Generate a fast random byte array using xorshift128+.
This function is NOT safe for cryptographic applications.
*/
void random_unsecure_bytes(void* bytes, size_t number_of_bytes);

#ifdef __cplusplus
}
#endif
#endif