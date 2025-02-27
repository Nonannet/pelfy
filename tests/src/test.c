
//Assebly x86-64 gcc 14.1 -O3

//dummy for heap variables
float read_float_ret = 1337;

//Dummy helper functions
int __attribute__ ((noinline)) result_float(float ret1){
    asm ("");
    return (int)ret1;
}

int __attribute__ ((noinline)) result_float_float(float ret1, float ret2){
    asm ("");
    return (int)ret1 + (int)ret2;
}

//Operations
void add_float_float(float arg1, float arg2){
    result_float(arg1 + arg2);
    //addss   %xmm1, %xmm0
    //jmp     result_float
}

void mul_float_float(float arg1, float arg2){
    result_float(arg1 * arg2);
    //mulss   %xmm1, %xmm0
    //jmp     result_float
}

//Read global variables from heap
void read_float(float arg1){
    result_float_float(arg1, read_float_ret);
    //movss   read_float_ret(%rip), %xmm1
    //jmp     result_float_float
}