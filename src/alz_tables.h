#ifndef UHA_ALZ_TABLES_H
#define UHA_ALZ_TABLES_H

#include <stdint.h>

extern uint16_t AlzSseMap[16385];
extern uint32_t AlzDistanceBase[44];
extern uint16_t AlzEntryStep[0x420];
extern uint16_t AlzEscStep[0x420];
extern int32_t  AlzS7BankC[256];
extern int32_t  AlzS7BankD[256];
extern int32_t  AlzCandBucket9[512];
extern uint8_t  AlzSelTab2[256];
extern uint32_t AlzMMCost[256];

void uha_alz_gen_tables(void);

#endif
