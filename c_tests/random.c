#include <assert.h>
#include <time.h>
#include "random.h"

static struct xorshift128p_state {
    uint64_t x[2];
} _unsecure_seed = {.x = {0, 1}};


/*
Used to change a seed to a better one, that can't be 0.
*/
static uint64_t transform_seed(uint64_t n)
{
    n += 0x9E3779B97f4A7C15;
    n = (n ^ (n >> 30)) * 0xBF58476D1CE4E5B9;
    n = (n ^ (n >> 27)) * 0x94D049BB133111EB;
    n = n ^ (n >> 31);
    if(n == 0)
    {
        return 0x18A270F24D80907B;
    }
    return n;
}

/*
Return the number of nanoseconds since the last second.
*/
uint64_t random_standard_seed(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);

    return t.tv_nsec;
}

/*
Set the random seed for all unsecure random functions.
Set this with random_standard_seed if you want some entropy or with a fixed value if you want to always have the same results in a simulation for example.
*/
void random_set_unsecure_seed(uint64_t seed)
{
    _unsecure_seed.x[1] = transform_seed(seed + _unsecure_seed.x[0]);
    _unsecure_seed.x[0] = transform_seed(seed);
}


/*
Generate an uint64_t integer between the range 0 and random_RAND_U64_MAX using xorshift128+
*/
uint64_t random_unsecure_uint64(void)
{
    uint64_t t = _unsecure_seed.x[0];
    const uint64_t s = _unsecure_seed.x[1];
    _unsecure_seed.x[0] = s;
    t ^= t << 23;
    t ^= t >> 18;
    t ^= s ^ (s >> 5);
    _unsecure_seed.x[1] = t;
    return t + s;
}


/*
Generate a fast random integer in the range given using xorshift128+.
This function is NOT safe for cryptographic applications.
*/
int64_t random_unsecure_int64(int64_t start, int64_t end)
{
    assert(start <= end);

    return start + (int64_t)(random_unsecure_uint64() % (uint64_t)(end - start + 1));
}

/*
Generate a fast random float in the range given using xorshift128+.
This function is NOT safe for cryptographic applications.
*/
double random_unsecure_float(double start, double end)
{
    assert(start <= end);
    double total = (double)(RAND_U64_MAX) / (end - start);
    return start + (double)random_unsecure_uint64() / total;
}

/*
Generate a fast random byte array using xorshift128+.
This function is NOT safe for cryptographic applications.
*/
void random_unsecure_bytes(void* bytes, size_t number_of_bytes)
{
    unsigned char* ptr = (unsigned char*) bytes;
    for(size_t i = 0; i < number_of_bytes; i++)
    {
        *ptr = (unsigned char)(random_unsecure_uint64() % 256);
        ptr++;
    }
}