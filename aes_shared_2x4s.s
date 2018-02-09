.fpu neon

.local randomness
.comm randomness, 11520, 16

//param a0 and b0 are d registers to swapmove
//param a1 and b1 are d registers to swapmove
//param t0 and r1 are d register that get overwritten
//param n is constant with the shift distance
//param m is d register with bitmask
.macro swapmove2 a0 b0 a1 b1 t0 t1 n m
    vshr.U16 \t0, \b0, #\n
    vshr.U16 \t1, \b1, #\n
    veor \t0, \a0
    veor \t1, \a1
    vand \t0, \m
    vand \t1, \m
    veor \a0, \t0
    veor \a1, \t1
    vshl.I16 \t0, #\n
    vshl.I16 \t1, #\n
    veor \b0, \t0
    veor \b1, \t1
.endm

//param a0-a7 are d registers to bitslice
//param t0-t2 are d registers that get overwritten
.macro bitslice a0 a1 a2 a3 a4 a5 a6 a7 t0 t1 t2
    //vmov.I16 \t2, #0x00ff
    vtrn.8 \a1, \a0
    vtrn.8 \a3, \a2
    vtrn.8 \a5, \a4
    vtrn.8 \a7, \a6
    vmov.I16 \t2, #0x0f0f
    swapmove2 \a0 \a1 \a2 \a3 \t0 \t1 4 \t2
    swapmove2 \a4 \a5 \a6 \a7 \t0 \t1 4 \t2
    vmov.I16 \t2, #0x5555
    swapmove2 \a0 \a2 \a1 \a3 \t0 \t1 1 \t2
    swapmove2 \a4 \a6 \a5 \a7 \t0 \t1 1 \t2
    vmov.I16 \t2, #0x3333
    swapmove2 \a0 \a4 \a1 \a5 \t0 \t1 2 \t2
    swapmove2 \a2 \a6 \a3 \a7 \t0 \t1 2 \t2
.endm

//param a0-a7 are d registers to unbitslice
//param t0-t2 are d registers that get overwritten
.macro unbitslice a0 a1 a2 a3 a4 a5 a6 a7 t0 t1 t2
    vmov.I16 \t2, #0x3333
    swapmove2 \a0 \a4 \a1 \a5 \t0 \t1 2 \t2
    swapmove2 \a2 \a6 \a3 \a7 \t0 \t1 2 \t2
    vmov.I16 \t2, #0x5555
    swapmove2 \a0 \a2 \a1 \a3 \t0 \t1 1 \t2
    swapmove2 \a4 \a6 \a5 \a7 \t0 \t1 1 \t2
    vmov.I16 \t2, #0x0f0f
    swapmove2 \a0 \a1 \a2 \a3 \t0 \t1 4 \t2
    swapmove2 \a4 \a5 \a6 \a7 \t0 \t1 4 \t2
    //vmov.I16 \t2, #0x00ff
    vtrn.8 \a1, \a0
    vtrn.8 \a3, \a2
    vtrn.8 \a5, \a4
    vtrn.8 \a7, \a6
.endm

.macro loadrk rk
    vld1.64 {d0}, [r1:64]!
    vmov d8, d0
    vld1.64 {d1}, [r1:64]!
    vmov d9, d1
    vld1.64 {d2}, [r1:64]!
    vmov d10, d2
    vld1.64 {d3}, [r1:64]!
    vmov d11, d3
    vld1.64 {d4}, [r1:64]!
    vmov d12, d4
    vld1.64 {d5}, [r1:64]!
    vmov d13, d5
    vld1.64 {d6}, [r1:64]!
    vmov d14, d6
    vld1.64 {d7}, [r1:64]!
    vmov d15, d7
    sub r1, #64
.endm

// void aes_keyexp(bint16_t key[8], bint16_t rk[11][8]);
.align 4
.global aes_keyexp
.type aes_keyexp STT_FUNC
aes_keyexp:
    //TODO
    //this function is a stub and does not do the AES key schedule
    //instead, we assume a fixed expanded key already in r1
    //this is converted to bitsliced representation
    //r0 is completely ignored

    vmov.I64 d24, #0xffffffff

    //round 1
    //TODO vmovs can already do the vzip step, slightly quicker
    loadrk r1
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6
    vstm r1!, {q0-q7}
    //round 2
    loadrk r1
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6
    veor d4, d24
    veor d8, d24
    veor d10, d24
    veor d14, d24
    vstm r1!, {q0-q7}
    //round 3
    loadrk r1
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6
    veor d4, d24
    veor d8, d24
    veor d10, d24
    veor d14, d24
    vstm r1!, {q0-q7}
    //round 4
    loadrk r1
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6
    veor d4, d24
    veor d8, d24
    veor d10, d24
    veor d14, d24
    vstm r1!, {q0-q7}
    //round 5
    loadrk r1
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6
    veor d4, d24
    veor d8, d24
    veor d10, d24
    veor d14, d24
    vstm r1!, {q0-q7}
    //round 6
    loadrk r1
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6
    veor d4, d24
    veor d8, d24
    veor d10, d24
    veor d14, d24
    vstm r1!, {q0-q7}
    //round 7
    loadrk r1
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6
    veor d4, d24
    veor d8, d24
    veor d10, d24
    veor d14, d24
    vstm r1!, {q0-q7}
    //round 8
    loadrk r1
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6
    veor d4, d24
    veor d8, d24
    veor d10, d24
    veor d14, d24
    vstm r1!, {q0-q7}
    //round 9
    loadrk r1
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6
    veor d4, d24
    veor d8, d24
    veor d10, d24
    veor d14, d24
    vstm r1!, {q0-q7}
    //round 10
    loadrk r1
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6
    veor d4, d24
    veor d8, d24
    veor d10, d24
    veor d14, d24
    vstm r1!, {q0-q7}
    //round final
    loadrk r1
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6
    veor d4, d24
    veor d8, d24
    veor d10, d24
    veor d14, d24
    vstm r1!, {q0-q7}

    bx lr


//assumes data in q0-q7
//will also overwrite q8-q15
//param rand is r register with address of randomnes, != sp/pc
//result in q0-q7
.macro subbytes rand
    veor  q8,  q6,  q3                    //Exec y14 = U3 ^ U5 into q8
    veor  q9,  q0,  q5                    //Exec y13 = U0 ^ U6 into q9
    veor q10,  q9,  q8                    //Exec y12 = y13 ^ y14 into q10
    veor q11,  q1, q10                    //Exec t1 = U4 ^ y12 into q11
    veor q12, q11,  q3                    //Exec y15 = t1 ^ U5 into q12
    refresh \rand q10 q14
    masked_and \rand q13 q10 q12 q14 q15 d28 d29 //Exec t2 = y12 & y15 into q13
    veor q14, q12,  q7                    //Exec y6 = y15 ^ U7 into q14
    veor q15, q11,  q2                    //Exec y20 = t1 ^ U1 into q15
    veor  q1,  q0,  q6                    //Exec y9 = U0 ^ U3 into q1
    veor q11, q15,  q1                    //Exec y11 = y20 ^ y9 into q11
    vpush {q10}                           //Store q10/y12 on stack
    vpush {q15}                           //Store q15/y20 on stack
    vpush {q14}                           //Store q14/y6 on stack
    refresh \rand  q1 q15
    masked_and \rand q10  q1 q11 q15 q14 d30 d31  //Exec t12 = y9 & y11 into q10
    veor q14,  q7, q11                    //Exec y7 = U7 ^ y11 into q14
    veor q15,  q0,  q3                    //Exec y8 = U0 ^ U5 into q15
    veor  q2,  q2,  q4                    //Exec t0 = U1 ^ U2 into q2
    veor  q3, q12,  q2                    //Exec y10 = y15 ^ t0 into q3
    veor  q4,  q3, q11                    //Exec y17 = y10 ^ y11 into q4
    vpush { q1}                           //Store q1/y9 on stack
    vpush {q12}                           //Store q12/y15 on stack
    vpush { q5}                           //Store q5/U6 on stack
    refresh \rand  q8 q12
    masked_and \rand  q1  q8  q4 q12  q5 d24 d25 //Exec t13 = y14 & y17 into q1
    veor  q5,  q1, q10                    //Exec t14 = t13 ^ t12 into q5
    veor q12,  q3, q15                    //Exec y19 = y10 ^ y8 into q12
    vpush { q8}                           //Store q8/y14 on stack
    vpush { q4}                           //Store q4/y17 on stack
    refresh \rand q15  q8
    masked_and \rand  q1 q15  q3  q8  q4 d16 d17 //Exec t15 = y8 & y10 into q1
    veor  q4,  q1, q10                    //Exec t16 = t15 ^ t12 into q4
    veor  q8,  q2, q11                    //Exec y16 = t0 ^ y11 into q8
    veor  q1,  q9,  q8                    //Exec y21 = y13 ^ y16 into q1
    vpush {q11}                           //Store q11/y11 on stack
    vpush { q3}                           //Store q3/y10 on stack
    refresh \rand  q9 q11
    masked_and \rand q10  q9  q8 q11  q3 d22 d23  //Exec t7 = y13 & y16 into q10
    veor  q3,  q0,  q8                    //Exec y18 = U0 ^ y16 into q3
    veor q11,  q2,  q7                    //Exec y1 = t0 ^ U7 into q11
    veor  q2, q11,  q6                    //Exec y4 = y1 ^ U3 into q2
    vpush { q9}                           //Store q9/y13 on stack
    vpush { q8}                           //Store q8/y16 on stack
    refresh \rand  q2  q9
    masked_and \rand  q6  q2  q7  q9  q8 d18 d19  //Exec t5 = y4 & U7 into q6
    veor  q8,  q6, q13                    //Exec t6 = t5 ^ t2 into q8
    veor  q9,  q8,  q4                    //Exec t18 = t6 ^ t16 into q9
    veor  q6,  q9, q12                    //Exec t22 = t18 ^ y19 into q6
    veor  q0, q11,  q0                    //Exec y2 = y1 ^ U0 into q0
    refresh \rand  q0  q9
    masked_and \rand  q8  q0 q14  q9 q12 d18 d19 //Exec t10 = y2 & y7 into q8
    veor  q9,  q8, q10                    //Exec t11 = t10 ^ t7 into q9
    veor q12,  q9,  q4                    //Exec t20 = t11 ^ t16 into q12
    veor  q3, q12,  q3                    //Exec t24 = t20 ^ y18 into q3
    vldr d8, [sp, #96]
    vldr d9, [sp, #104]                   //Load U6 into q4
    veor  q4, q11,  q4                    //Exec y5 = y1 ^ U6 into q4
    refresh \rand  q4  q9
    masked_and \rand  q8  q4 q11  q9 q12 d18 d19  //Exec t8 = y5 & y1 into q8
    veor  q9,  q8, q10                    //Exec t9 = t8 ^ t7 into q9
    veor q12,  q9,  q5                    //Exec t19 = t9 ^ t14 into q12
    veor  q1, q12,  q1                    //Exec t23 = t19 ^ y21 into q1
    veor  q8,  q4, q15                    //Exec y3 = y5 ^ y8 into q8
    vldr d18, [sp, #144]
    vldr d19, [sp, #152]                  //Load y6 into q9
    vpush { q7}                           //Store q7/U7 on stack
    refresh \rand  q8 q12
    masked_and \rand q10  q8  q9 q12  q7 d24 d25 //Exec t3 = y3 & y6 into q10
    veor  q7, q10, q13                    //Exec t4 = t3 ^ t2 into q7
    vldr d24, [sp, #176]
    vldr d25, [sp, #184]                  //Load y20 into q12
    veor  q7,  q7, q12                    //Exec t17 = t4 ^ y20 into q7
    veor  q5,  q7,  q5                    //Exec t21 = t17 ^ t14 into q5
    refresh \rand  q5 q10
    masked_and \rand  q7  q5  q1 q10 q12 d20 d21  //Exec t26 = t21 & t23 into q7
    veor q10,  q3,  q7                    //Exec t27 = t24 ^ t26 into q10
    veor q12,  q6,  q7                    //Exec t31 = t22 ^ t26 into q12
    veor  q5,  q5,  q6                    //Exec t25 = t21 ^ t22 into q5
    vpush { q2}                           //Store q2/y4 on stack
    refresh \rand  q5 q13
    masked_and \rand  q7  q5 q10 q13  q2 d26 d27  //Exec t28 = t25 & t27 into q7
    veor  q2,  q7,  q6                    //Exec t29 = t28 ^ t22 into q2
    refresh \rand  q2  q6
    masked_and \rand q13  q2  q0  q6  q7 d12 d13 //Exec z14 = t29 & y2 into q13
    refresh \rand  q2  q7
    masked_and \rand  q6  q2 q14  q7  q0 d14 d15 //Exec z5 = t29 & y7 into q6
    veor  q0,  q1,  q3                    //Exec t30 = t23 ^ t24 into q0
    vpush {q13}                           //Store q13/z14 on stack
    refresh \rand q12 q14
    masked_and \rand  q7 q12  q0 q14 q13 d28 d29  //Exec t32 = t31 & t30 into q7
    veor q13,  q7,  q3                    //Exec t33 = t32 ^ t24 into q13
    veor q14, q10, q13                    //Exec t35 = t27 ^ t33 into q14
    refresh \rand  q3  q7
    masked_and \rand  q0  q3 q14  q7 q12 d14 d15 //Exec t36 = t24 & t35 into q0
    veor  q7, q10,  q0                    //Exec t38 = t27 ^ t36 into q7
    refresh \rand  q2  q3
    masked_and \rand q12  q2  q7  q3 q10 d6 d7  //Exec t39 = t29 & t38 into q12
    veor  q3,  q5, q12                    //Exec t40 = t25 ^ t39 into q3
    veor q10,  q2,  q3                    //Exec t43 = t29 ^ t40 into q10
    vldr d10, [sp, #48]
    vldr d11, [sp, #56]                   //Load y16 into q5
    refresh \rand q10 q12
    masked_and \rand  q7 q10  q5 q12 q14 d24 d25  //Exec z3 = t43 & y16 into q7
    veor q12,  q7,  q6                    //Exec tc12 = z3 ^ z5 into q12
    vldr d28, [sp, #64]
    vldr d29, [sp, #72]                   //Load y13 into q14
    vpush {q12}                           //Store q12/tc12 on stack
    refresh \rand q10  q6
    masked_and \rand  q5 q10 q14  q6 q12 d12 d13  //Exec z12 = t43 & y13 into q5
    refresh \rand  q3 q12
    masked_and \rand  q6  q3  q4 q12 q10 d24 d25  //Exec z13 = t40 & y5 into q6
    refresh \rand  q3 q12
    masked_and \rand q10  q3 q11 q12  q4 d24 d25 //Exec z4 = t40 & y1 into q10
    veor  q4,  q7, q10                    //Exec tc6 = z3 ^ z4 into q4
    veor q12,  q1, q13                    //Exec t34 = t23 ^ t33 into q12
    veor  q0,  q0, q12                    //Exec t37 = t36 ^ t34 into q0
    veor  q1,  q3,  q0                    //Exec t41 = t40 ^ t37 into q1
    vldr d6, [sp, #96]
    vldr d7, [sp, #104]                   //Load y10 into q3
    refresh \rand  q1 q10
    masked_and \rand  q7  q1  q3 q10 q11 d20 d21  //Exec z8 = t41 & y10 into q7
    refresh \rand  q1 q11
    masked_and \rand q10  q1 q15 q11  q3 d22 d23 //Exec z17 = t41 & y8 into q10
    veor  q3, q13,  q0                    //Exec t44 = t33 ^ t37 into q3
    vldr d22, [sp, #176]
    vldr d23, [sp, #184]                  //Load y15 into q11
    refresh \rand  q3 q14
    masked_and \rand q12  q3 q11 q14 q15 d28 d29  //Exec z0 = t44 & y15 into q12
    vldr d28, [sp, #240]
    vldr d29, [sp, #248]                  //Load y12 into q14
    vpush {q10}                           //Store q10/z17 on stack
    refresh \rand  q3 q11
    masked_and \rand q15  q3 q14 q11 q10 d22 d23 //Exec z9 = t44 & y12 into q15
    refresh \rand  q0 q11
    masked_and \rand q10  q0  q8 q11  q3 d22 d23 //Exec z10 = t37 & y3 into q10
    refresh \rand  q0 q11
    masked_and \rand  q3  q0  q9 q11  q8 d22 d23 //Exec z1 = t37 & y6 into q3
    veor  q8,  q3, q12                    //Exec tc5 = z1 ^ z0 into q8
    veor q11,  q4,  q8                    //Exec tc11 = tc6 ^ tc5 into q11
    vldr d0, [sp, #48]
    vldr d1, [sp, #56]                    //Load y4 into q0
    refresh \rand q13  q8
    masked_and \rand  q3 q13  q0  q8  q9 d16 d17 //Exec z11 = t33 & y4 into q3
    veor  q8,  q2, q13                    //Exec t42 = t29 ^ t33 into q8
    veor  q9,  q8,  q1                    //Exec t45 = t42 ^ t41 into q9
    vldr d0, [sp, #144]
    vldr d1, [sp, #152]                   //Load y17 into q0
    refresh \rand  q9  q2
    masked_and \rand  q1  q9  q0  q2 q14 d4 d5 //Exec z7 = t45 & y17 into q1
    veor  q2,  q1,  q4                    //Exec tc8 = z7 ^ tc6 into q2
    vldr d28, [sp, #160]
    vldr d29, [sp, #168]                  //Load y14 into q14
    refresh \rand  q9  q1
    masked_and \rand  q0  q9 q14  q1  q4 d2 d3 //Exec z16 = t45 & y14 into q0
    vldr d2, [sp, #128]
    vldr d3, [sp, #136]                   //Load y11 into q1
    refresh \rand  q8  q9
    masked_and \rand  q4  q8  q1  q9 q14 d18 d19 //Exec z6 = t42 & y11 into q4
    veor  q9,  q4,  q2                    //Exec tc16 = z6 ^ tc8 into q9
    vldr d28, [sp, #208]
    vldr d29, [sp, #216]                  //Load y9 into q14
    vpush { q2}                           //Store q2/tc8 on stack
    refresh \rand  q8  q4
    masked_and \rand  q1  q8 q14  q4  q2 d8 d9 //Exec z15 = t42 & y9 into q1
    veor  q2,  q1,  q9                    //Exec tc20 = z15 ^ tc16 into q2
    veor  q4,  q1,  q0                    //Exec tc1 = z15 ^ z16 into q4
    veor  q0, q10,  q4                    //Exec tc2 = z10 ^ tc1 into q0
    veor  q1,  q0,  q3                    //Exec tc21 = tc2 ^ z11 into q1
    veor  q0, q15,  q0                    //Exec tc3 = z9 ^ tc2 into q0
    veor  q3,  q0,  q9                    //Exec S0 = tc3 ^ tc16 into q3
    veor  q0,  q0, q11                    //Exec S3 = tc3 ^ tc11 into q0
    veor  q8,  q0,  q9                    //Exec S1 = S3 ^ tc16 ^ 1 into q8
    veor  q4,  q6,  q4                    //Exec tc13 = z13 ^ tc1 into q4
    vldr d12, [sp, #80]
    vldr d13, [sp, #88]                   //Load U7 into q6
    refresh \rand q13 q10
    masked_and \rand  q9 q13  q6 q10 q11 d20 d21 //Exec z2 = t33 & U7 into q9
    veor q10, q12,  q9                    //Exec tc4 = z0 ^ z2 into q10
    veor q11,  q5, q10                    //Exec tc7 = z12 ^ tc4 into q11
    veor  q6,  q7, q11                    //Exec tc9 = z8 ^ tc7 into q6
    vldr d14, [sp, #0]
    vldr d15, [sp, #8]                    //Load tc8 into q7
    veor  q6,  q7,  q6                    //Exec tc10 = tc8 ^ tc9 into q6
    vldr d14, [sp, #48]
    vldr d15, [sp, #56]                   //Load z14 into q7
    veor  q7,  q7,  q6                    //Exec tc17 = z14 ^ tc10 into q7
    veor  q1,  q1,  q7                    //Exec S5 = tc21 ^ tc17 into q1
    veor  q2,  q7,  q2                    //Exec tc26 = tc17 ^ tc20 into q2
    vldr d14, [sp, #16]
    vldr d15, [sp, #24]                   //Load z17 into q7
    veor  q2,  q2,  q7                    //Exec S2 = tc26 ^ z17 ^ 1 into q2
    vldr d14, [sp, #32]
    vldr d15, [sp, #40]                   //Load tc12 into q7
    veor  q7, q10,  q7                    //Exec tc14 = tc4 ^ tc12 into q7
    veor  q4,  q4,  q7                    //Exec tc18 = tc13 ^ tc14 into q4
    veor  q6,  q6,  q4                    //Exec S6 = tc10 ^ tc18 ^ 1 into q6
    veor  q4,  q5,  q4                    //Exec S7 = z12 ^ tc18 ^ 1 into q4
    veor  q5,  q7,  q0                    //Exec S4 = tc14 ^ S3 into q5
    add sp, #288
    //[('q0', 'S3'), ('q1', 'S5'), ('q2', 'S2'), ('q3', 'S0'), ('q4', 'S7'), ('q5', 'S4'), ('q6', 'S6'), ('q7', 'tc14'), ('q8', 'S1'), ('q9', 'z2'), ('q10', 'tc4'), ('q11', 'tc7'), ('q12', 'z0'), ('q13', 't33'), ('q14', 'y9'), ('q15', 'z9')]
    vmov q7, q4 //S7
    vmov q4, q2 //S2
    vmov q2, q6 //S6
    vmov q6, q0 //S3
    vmov q0, q3 //S0
    vmov q3, q1 //S5
    vmov q1, q5 //S4
    vmov q5, q8 //S1
/*  state[0] = S0;
    state[1] = S4;
    state[2] = S6;
    state[3] = S5;
    state[4] = S2;
    state[5] = S1;
    state[6] = S3;
    state[7] = S7;*/
.endm

#assumes data in q0-q7
.macro mixcolumns
    //uint16_t r0 = state[7], r2 = state[2], r9 = state[3], r3 = state[1], r12 = state[6], r4 = state[4], r14 = state[5], r1 = state[0], r5, r6, r7, r8, r10, r11;
    vmov q9, q3
    vmov q3, q1
    vmov q1, q0
    vmov q0, q7
    vmov q12, q6
    vmov q14, q5

    //r10 = r2 ^ rol(r2, 4);
    vshl.I16 q10, q2, #4
    vsra.U16 q10, q2, #12
    //r7 = r9 ^ rol(r9, 4);
    vshl.I16 q7, q9, #4
    vsra.U16 q7, q9, #12
    //r11 = r0 ^ rol(r0, 4);
    vshl.I16 q11, q0, #4
    vsra.U16 q11, q0, #12
veor q10, q2
    //r8 = r3 ^ rol(r3, 4);
    vshl.I16 q8, q3, #4
    vsra.U16 q8, q3, #12
veor q7, q9
    //r5 = r14 ^ rol(r14, 4);
    vshl.I16 q5, q14, #4
    vsra.U16 q5, q14, #12
    //r9 = r9 ^ rol(r7, 4);
    vshl.I16 q13, q7, #4
    vsra.U16 q13, q7, #12
veor q11, q0
    //r9 = r9 ^ rol(r10, 12);
    vshl.I16 q6, q10, #12
    vsra.U16 q6, q10, #4
veor q5, q14
veor q9, q13
veor q8, q3
    //r7 = r12 ^ rol(r12, 4);
    vshl.I16 q7, q12, #4
    vsra.U16 q7, q12, #12
veor q9, q6
    //r6 = r4 ^ rol(r4, 4);
    vshl.I16 q6, q4, #4
    vsra.U16 q6, q4, #12
    //r3 = r3 ^ rol(r7, 12);
    vrev16.8 q13, q13
veor q7, q12
    veor q3, q13
    //r4 = r4 ^ rol(r7, 12);
    vshl.I16 q13, q7, #12
    vsra.U16 q13, q7, #4
veor q6, q4
    //r14 = r14 ^ rol(r6, 12);
    vshl.I16 q15, q6, #12
    vsra.U16 q15, q6, #4
    veor q14, q15
veor q4, q13
    //r6 = r4 ^ rol(r6, 4);
    vrev16.8 q15, q15
    veor q6, q4, q15
    //r4 = r1 ^ rol(r1, 4);
    vshl.I16 q4, q1, #4
    vsra.U16 q4, q1, #12
    //r2 = r2 ^ rol(r11, 12);
    vshl.I16 q15, q11, #12
    vsra.U16 q15, q11, #4
veor q4, q1
    //r0 = r0 ^ rol(r4, 12);
    vshl.I16 q13, q4, #12
    vsra.U16 q13, q4, #4
veor q2, q15
veor q0, q13
    //r2 = r2 ^ rol(r4, 12);
    veor q2, q13
    //r11 = r0 ^ rol(r11, 4);
    vrev16.8 q15, q15
    veor q11, q0, q15
    //r12 = r12 ^ rol(r8, 12);
    vshl.I16 q15, q8, #12
    vsra.U16 q15, q8, #4
    //r3 = r3 ^ rol(r4, 12);
    veor q3, q13
    //r12 = r12 ^ rol(r4, 12);
    veor q12, q13
    //r7 = r12 ^ rol(r7, 4);
    vshl.I16 q13, q7, #4
    vsra.U16 q13, q7, #12
veor q12, q15
    //r8 = r3 ^ rol(r8, 4);
    vrev16.8 q15, q15
    veor q8, q3, q15
    //r10 = r2 ^ rol(r10, 4);
    vshl.I16 q15, q10, #4
    vsra.U16 q15, q10, #12
veor q7, q12, q13
    //r1 = r1 ^ rol(r5, 12);
    vshl.I16 q12, q5, #12
    vsra.U16 q12, q5, #4
    //r4 = r1 ^ rol(r4, 4);
    vshl.I16 q13, q4, #4
    vsra.U16 q13, q4, #12
veor q1, q12
veor q10, q2, q15
    //r5 = r14 ^ rol(r5, 4);
    vrev16.8 q12, q12
    veor q5, q14, q12
veor q4, q1, q13

    //state[1] = rol(r8, 4);
    vshl.I16 q1, q8, #4
    vsra.U16 q1, q8, #12
    //state[2] = rol(r5, 4);
    vshl.I16 q2, q5, #4
    vsra.U16 q2, q5, #12
    //state[0] = rol(r4, 4);
    vshl.I16 q0, q4, #4
    vsra.U16 q0, q4, #12
    //state[4] = rol(r6, 4);
    vshl.I16 q4, q6, #4
    vsra.U16 q4, q6, #12
    //state[6] = rol(r7, 4);
    vshl.I16 q6, q7, #4
    vsra.U16 q6, q7, #12
    //state[3] = rol(r9, 4);
    vshl.I16 q3, q9, #4
    vsra.U16 q3, q9, #12
    //state[5] = rol(r10, 4);
    vshl.I16 q5, q10, #4
    vsra.U16 q5, q10, #12
    //state[7] = rol(r11, 4);
    vshl.I16 q7, q11, #4
    vsra.U16 q7, q11, #12
.endm

.macro shiftrow3 a b c t0 t1 t2 t3 t4 t5 t6 t7
    //state[i] = ((state[i] & 0xf000) | ((state[i] & 0x0800) >> 3) | ((state[i] & 0x0700) << 1) | ((state[i] & 0x0030) << 2) | ((state[i] & 0x00c0) >> 2) | ((state[i] & 0x000e) >> 1) | ((state[i] & 0x0001) << 3));

    vmov.I16 \t6, #0xf000
    vmov.I16 \t7, #0x0800
    vand.I16 \t0, \t6, \a
    vand.I16 \t1, \t6, \b
    vand.I16 \t2, \t6, \c

    vand.I16 \t3, \t7, \a
    vand.I16 \t4, \t7, \b
    vand.I16 \t5, \t7, \c
    vmov.I16 \t6, #0x0700
	vsra.U16 \t0, \t3, #3
	vsra.U16 \t1, \t4, #3
	vsra.U16 \t2, \t5, #3

    vand.I16 \t3, \t6, \a
    vand.I16 \t4, \t6, \b
    vand.I16 \t5, \t6, \c
    vmov.I16 \t7, #0x00c0
    vshl.I16 \t3, #1
    vshl.I16 \t4, #1
    vshl.I16 \t5, #1
    vorr \t0, \t3
    vorr \t1, \t4
    vorr \t2, \t5

    vand.I16 \t3, \t7, \a
    vand.I16 \t4, \t7, \b
    vand.I16 \t5, \t7, \c
    vmov.I16 \t6, #0x0030
	vsra.U16 \t0, \t3, #2
	vsra.U16 \t1, \t4, #2
	vsra.U16 \t2, \t5, #2

    vand.I16 \t3, \t6, \a
    vand.I16 \t4, \t6, \b
    vand.I16 \t5, \t6, \c
    vmov.I16 \t7, #0x000e
    vshl.I16 \t3, #2
    vshl.I16 \t4, #2
    vshl.I16 \t5, #2
    vorr \t0, \t3
    vorr \t1, \t4
    vorr \t2, \t5

    vand.I16 \t3, \t7, \a
    vand.I16 \t4, \t7, \b
    vand.I16 \t5, \t7, \c
    vmov.I16 \t6, #0x0001
	vsra.U16 \t0, \t3, #1
	vsra.U16 \t1, \t4, #1
	vsra.U16 \t2, \t5, #1

    vand.I16 \t3, \t6, \a
    vand.I16 \t4, \t6, \b
    vand.I16 \t5, \t6, \c
    vshl.I16 \t3, #3
    vshl.I16 \t4, #3
    vshl.I16 \t5, #3
    vorr \a, \t0, \t3
    vorr \b, \t1, \t4
    vorr \c, \t2, \t5
.endm

.macro shiftrow2 a b t0 t1 t2 t3 t4 t5
    //state[i] = ((state[i] & 0xf000) | ((state[i] & 0x0800) >> 3) | ((state[i] & 0x0700) << 1) | ((state[i] & 0x0030) << 2) | ((state[i] & 0x00c0) >> 2) | ((state[i] & 0x000e) >> 1) | ((state[i] & 0x0001) << 3));
    vmov.I16 \t2, #0xf000
    vmov.I16 \t3, #0x0800
    vand.I16 \t0, \t2, \a
    vand.I16 \t1, \t2, \b

    vand.I16 \t4, \t3, \a
    vand.I16 \t5, \t3, \b
    vmov.I16 \t2, #0x0700
	vsra.U16 \t0, \t4, #3
	vsra.U16 \t1, \t5, #3

	vand.I16 \t4, \t2, \a
    vand.I16 \t5, \t2, \b
    vmov.I16 \t3, #0x00c0
    vshl.I16 \t4, #1
    vshl.I16 \t5, #1
    vorr \t0, \t4
    vorr \t1, \t5

    vand.I16 \t4, \t3, \a
    vand.I16 \t5, \t3, \b
    vmov.I16 \t2, #0x0030
	vsra.U16 \t0, \t4, #2
	vsra.U16 \t1, \t5, #2

    vand.I16 \t4, \t2, \a
    vand.I16 \t5, \t2, \b
    vmov.I16 \t3, #0x000e
    vshl.I16 \t4, #2
    vshl.I16 \t5, #2
    vorr \t0, \t4
    vorr \t1, \t5

    vand.I16 \t4, \t3, \a
    vand.I16 \t5, \t3, \b
    vmov.I16 \t2, #0x0001
	vsra.U16 \t0, \t4, #1
	vsra.U16 \t1, \t5, #1

    vand.I16 \t4, \t2, \a
    vand.I16 \t5, \t2, \b
    //1 cycle stall
    vshl.I16 \t4, #3
    vshl.I16 \t5, #3
    vorr \a, \t0, \t4
    vorr \b, \t1, \t5
.endm

.macro shiftrows a0 a1 a2 a3 a4 a5 a6 a7 t0 t1 t2 t3 t4 t5 t6 t7
    shiftrow3 \a0 \a1 \a2 \t0 \t1 \t2 \t3 \t4 \t5 \t6 \t7
    shiftrow3 \a3 \a4 \a5 \t0 \t1 \t2 \t3 \t4 \t5 \t6 \t7
    shiftrow2 \a6 \a7 \t0 \t1 \t2 \t3 \t4 \t5
.endm

//param rk is r register with address of current round key
.macro addroundkey rk a0 a1 a2 a3 a4 a5 a6 a7 tmp
    vld1.64 {\tmp}, [\rk:128]!
    veor \a0, \tmp
    vld1.64 {\tmp}, [\rk:128]!
    veor \a1, \tmp
    vld1.64 {\tmp}, [\rk:128]!
    veor \a2, \tmp
    vld1.64 {\tmp}, [\rk:128]!
    veor \a3, \tmp
    vld1.64 {\tmp}, [\rk:128]!
    veor \a4, \tmp
    vld1.64 {\tmp}, [\rk:128]!
    veor \a5, \tmp
    vld1.64 {\tmp}, [\rk:128]!
    veor \a6, \tmp
    vld1.64 {\tmp}, [\rk:128]!
    veor \a7, \tmp
.endm

//param rand is r register with address of randomness
//param a is q register to refresh
//param tmp is q register that gets overwritten
.macro refresh rand a tmp
    vld1.64 {\tmp}, [\rand]! //get 16 bytes of randomness
    veor \a, \tmp
    vext.32 \tmp, \tmp, #1
    veor \a, \tmp
.endm

//param rand is r register with address of randomness
//param c is q register where result gets stored
//param a and b are q registers to and, remain unchanged
//param tmp and tmpr are q registers that get overwritten
//param tmpd0 and tmpd1 are the d registers that make up tmp
.macro masked_and rand c a b tmp tmpr tmpd0 tmpd1
    vand \c, \a, \b //K = A.B
    vld1.64 {\tmpr}, [\rand]! //get 16 bytes of randomness
    vext.32 \tmp, \b, \b, #1
    veor \c, \tmpr  // + R
    vand \tmp, \a
    veor \c, \tmp   // + A.(rot B 1)
    vext.32 \tmp, \a, \a, #1
    vand \tmp, \b
    veor \c, \tmp   // + (rot A 1).B
    vext.32 \tmpr, \tmpr, #1
    veor \c, \tmpr  // + (rot R 1)
    vext.32 \tmp, \b, \b, #2
    vand \tmp, \a
    veor \c, \tmp   // + A.(rot B 2)
    vld1.32 {\tmpd0[]}, [\rand]! //get 4 bytes of randomness
    vmov \tmpd1, \tmpd0
    veor \c, \tmp   // + (r5,r5,r5,r5)
.endm

.macro round rk rand
    addroundkey \rk q0 q1 q2 q3 q4 q5 q6 q7 q15
    subbytes \rand
    shiftrows q0 q1 q2 q3 q4 q5 q6 q7 q8 q9 q10 q11 q12 q13 q14 q15
    mixcolumns
.endm

//void aes_enc(FILE * random, bint16_t rk[11][8], bint16_t state[8]);
.align 4
.global aes_enc
.type aes_enc STT_FUNC
aes_enc:

    push {r1-r2,lr}

    mov r3, r0 //FILE
    movw r0, #:lower16:randomness
    movt r0, #:upper16:randomness
    mov r1, #32 //size
    mov r2, #360 //number
    bl fread

    pop {r1-r2}

    //load state in vector registers
    vldm.64 r2, {q0-q7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    bitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31
    vzip.16 q0, q4
    vzip.16 q1, q5
    vzip.16 q2, q6
    vzip.16 q3, q7
    vswp q1, q4
    vswp q2, q4
    vswp q3, q5
    vswp q5, q6

    //set address for randomness
    movw r0, #:lower16:randomness
    movt r0, #:upper16:randomness

    //go!
    round r1 r0 //round 1
    round r1 r0 //round 2
    round r1 r0 //round 3
    round r1 r0 //round 4
    round r1 r0 //round 5
    round r1 r0 //round 6
    round r1 r0 //round 7
    round r1 r0 //round 8
    round r1 r0 //round 9
    //round 10
    addroundkey r1 q0 q1 q2 q3 q4 q5 q6 q7 q15
    subbytes r0
    vswp q2, q5
    shiftrows q0 q1 q2 q3 q4 q5 q6 q7 q8 q9 q10 q11 q12 q13 q14 q15
    addroundkey r1 q0 q1 q2 q3 q4 q5 q6 q7 q15

    vswp q5, q6
    vswp q3, q5
    vswp q2, q4
    vswp q1, q4
    vuzp.16 q0, q4
    vuzp.16 q1, q5
    vuzp.16 q2, q6
    vuzp.16 q3, q7
    unbitslice d0 d1 d2 d3 d4 d5 d6 d7 d29 d30 d31
    unbitslice d8 d9 d10 d11 d12 d13 d14 d15 d29 d30 d31

    //store output to memory
    vstm r2, {q0-q7}

    pop {lr}
    bx lr
