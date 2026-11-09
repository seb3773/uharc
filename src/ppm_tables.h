#ifndef UHA_PPM_TABLES_H
#define UHA_PPM_TABLES_H
#include <stdint.h>

extern const uint8_t PPMS_LZPTRANS[21];
extern const uint32_t PPMS_43A570[8];
extern const uint8_t PPMS_MAXLEN10[48];
extern const uint8_t PPMS_MAXLEN20[32];
extern const uint8_t PPMS_MAXLEN30[32];
extern const uint8_t PPMS_LENTREE[512];
extern const uint8_t PPMS_NOVEL[256];
extern const uint32_t PPMS_WTAB[16];
extern const uint32_t PPMS_43E070[16];
extern const uint32_t PPMS_43E0B0[16];
extern const uint32_t PPMS_43E0F0[16];
extern const uint32_t PPMS_43E130[16];
extern const uint32_t PPMS_43E170[16];
extern const uint32_t PPMS_43E1B0[8];
extern const uint32_t PPMS_43E1D0[16];
extern const uint32_t PPMS_43E1F4[32];
extern const uint8_t DetrClass[256];
extern const uint16_t DetrStrOff[99];
extern const uint8_t DetrStrLen[99];
extern const uint8_t DetrStrData[350];
extern const uint8_t DetrEsc[768];
extern const uint32_t PPMS_43B2CC[256];
extern const uint8_t CLS_T7DC[256];
extern const uint8_t CLS_T6CC[16];
extern const uint8_t CLS_T6DC[256];
extern const uint32_t CLS_CTXBASE[10];
extern const uint32_t CLS_STRIDE[10];
extern const uint8_t CLS_SHIFT[10];
extern const uint32_t BC1_LVLOFF[8];
extern const uint32_t BC1_WT070[16];
extern const uint32_t BC1_WT0B0[16];
extern const uint32_t BC1_WT0F0[16];
extern const int32_t AlzCandByteA[256];
extern const int32_t AlzCandByteB[256];
extern const int32_t AlzCandMask[6];

extern uint16_t PPMS_F154[16384];
extern uint32_t PPMS_RANKBASE_S[5];
extern uint32_t PPMS_RANKBASE_L[17];
extern int32_t  PPMS_S7BankC[256];
extern int32_t  PPMS_S7BankD[256];
extern int32_t  PPMS_CandBucket9[512];
extern uint8_t  PPMS_SelTab2[256];
extern uint32_t PPMS_MMCost[256];
extern uint32_t PPMS_43A590[256];
extern uint32_t PPMS_PAGETAB[288];
extern uint8_t  PPMS_REC1THR[256];
extern uint8_t  PPMS_REC2THR[256];
extern uint8_t  PPMS_LZPCLASS_INIT[656];
extern uint16_t PPMS_ROWSEED[256];

void uha_ppm_gen_tables(void);

#endif
