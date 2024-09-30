#ifndef __PINTOS_FIXED_POINT__
#define __PINTOS_FIXED_POINT__

#define FIXED_POINT_BITS 14
#define FIXED_POINT_DET_BITS (FIXED_POINT_BITS - 1)

#define TO_INTEGER_TZ(fixed) ((fixed) >> FIXED_POINT_BITS)
#define TO_INTEGER_N(fixed)  (TO_INTEGER_TZ(fixed) + ((fixed >> FIXED_POINT_DET_BITS) & 0x1 ? 1 : 0))
#define TO_INTEGER(fixed) TO_INTEGER_N(fixed)

#define TO_FIXED_POINT(integer) ((integer) << FIXED_POINT_BITS)
#define FIXED_MULT(f1, f2) ((((int64_t)(f1)) * f2) >> FIXED_POINT_BITS)
#define FIXED_DIV(f1, f2) ((((int64_t)(f1)) << FIXED_POINT_BITS) / f2)

#endif

