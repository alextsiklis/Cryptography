#include <stdio.h>

void generate_keys(unsigned k0, unsigned *k1, unsigned *k2);

unsigned ecb(unsigned key[], unsigned inf_block, int enc, int debug_mode);

unsigned cbc(unsigned key[], unsigned inf_block, unsigned init_vector, int enc, int debug_mode);

unsigned ofb(unsigned key[], unsigned init_vector, int debug_mode);

