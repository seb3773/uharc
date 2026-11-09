#include <math.h>
#include <stdint.h>
#include "alz_tables.h"

uint16_t  AlzSseMap[16385];
uint32_t  AlzDistanceBase[44];
uint16_t  AlzEntryStep[0x420];
uint16_t  AlzEscStep[0x420];
int32_t   AlzS7BankC[256];
int32_t   AlzS7BankD[256];
int32_t   AlzCandBucket9[512];
uint8_t   AlzSelTab2[256];
uint32_t  AlzMMCost[256];

static int isqrt(int x)
{
    int r = 0;
    while ((r + 1) * (r + 1) <= x)
        r++;
    return r;
}

static int bucket(const int *thr, int hi, int i)
{
    int v, res = 0;
    for (v = 0; v <= hi; v++)
        if (thr[v] <= i)
            res = v;
    return res;
}

void uha_alz_gen_tables(void)
{
    static int done;
    int i, k, v;
    int fib[9];
    int T2[16];
    int rthr[13];
    int fthr[11];

    if (done)
        return;
    done = 1;

    AlzSseMap[0] = 0;
    for (i = 1; i <= 16384; i++)
        AlzSseMap[i] = (uint16_t)(65520 - (int)ceil(4680.0 * log((double)i) / log(2.0)));

    for (i = 0; i < 44; i++) {
        if (i < 6)
            AlzDistanceBase[i] = 1u << i;
        else {
            k = 6 + (i - 6) / 2;
            if (((i - 6) & 1) == 0)
                AlzDistanceBase[i] = 1u << k;
            else
                AlzDistanceBase[i] = 3u << (k - 1);
        }
    }

    for (i = 0; i < 0x420; i++)
        AlzEntryStep[i] = 0;
    for (i = 0; i <= 1008; i++)
        AlzEntryStep[i] = 32;
    for (i = 1009; i <= 1016; i++)
        AlzEntryStep[i] = 10;
    AlzEntryStep[1017] = 65281;
    AlzEntryStep[1020] = 256;
    AlzEntryStep[1021] = 65280;
    AlzEntryStep[1022] = 2;

    for (i = 0; i < 0x420; i++)
        AlzEscStep[i] = 8;
    for (i = 512; i <= 992; i++)
        AlzEscStep[i] = 16;
    AlzEscStep[768] = 6;
    for (i = 1017; i < 0x420; i++)
        AlzEscStep[i] = 32;

    for (i = 0; i < 256; i++) {
        k = i;
        if (256 - i < k)
            k = 256 - i;
        AlzS7BankC[i] = k >> 3;
        AlzS7BankD[i] = k >> 6;
    }
    for (i = 0; i < 512; i++) {
        k = i;
        if (512 - i < k)
            k = 512 - i;
        AlzCandBucket9[i] = (k == 0) ? 0 : isqrt(k - 1) + 1;
    }

    fib[0] = 1;
    fib[1] = 1;
    for (i = 2; i <= 8; i++)
        fib[i] = fib[i - 1] + fib[i - 2];

    T2[0] = 0;
    for (v = 1; v <= 8; v++)
        T2[v] = T2[v - 1] + fib[v];
    T2[9] = 170;
    for (v = 10; v <= 15; v++)
        T2[v] = T2[v - 1] + fib[8 - (v - 10)];
    for (i = 0; i < 256; i++)
        AlzSelTab2[i] = (uint8_t)bucket(T2, 15, i);

    for (v = 0; v <= 5; v++)
        rthr[v] = v;
    rthr[6] = 7;
    for (v = 7; v <= 12; v++)
        rthr[v] = rthr[v - 1] + fib[v - 4];
    fthr[0] = 166;
    fthr[1] = fthr[0] + fib[8];
    fthr[2] = fthr[1] + fib[7];
    fthr[3] = fthr[2] + fib[6];
    fthr[4] = fthr[3] + fib[5];
    fthr[5] = fthr[4] + fib[4];
    fthr[6] = fthr[5] + fib[3];
    fthr[7] = fthr[6] + fib[2];
    fthr[8] = fthr[7] + fib[1];
    fthr[9] = fthr[8] + fib[0];
    fthr[10] = fthr[9] + 1;
    for (i = 0; i < 256; i++) {
        if (i < 91)
            AlzMMCost[i] = (uint32_t)bucket(rthr, 12, i);
        else if (i <= 165)
            AlzMMCost[i] = 12;
        else
            AlzMMCost[i] = (uint32_t)(11 - bucket(fthr, 10, i));
    }
}
