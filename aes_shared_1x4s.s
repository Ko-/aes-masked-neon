.fpu neon

.local randomness
.comm randomness, 5760, 8

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

// void aes_keyexp(bint16_t key[8], bint16_t rk[11][8*NUM_BLOCKS]);
.align 4
.global aes_keyexp
.type aes_keyexp STT_FUNC
aes_keyexp:
    //TODO
    //this function is a stub and does not do the AES key schedule
    //instead, we assume a fixed expanded key already in r1
    //this is converted to bitsliced representation
    //r0 is completely ignored

    vmov.I64 d24, #0xffff
    
    //round 1
    vldm.64 r1, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15
    vstm r1!, {d0-d7}
    //round 2
    vldm.64 r1, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15
    veor d2, d24
    veor d4, d24
    veor d5, d24
    veor d7, d24
    vstm r1!, {d0-d7}
    //round 3
    vldm.64 r1, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15
    veor d2, d24
    veor d4, d24
    veor d5, d24
    veor d7, d24
    vstm r1!, {d0-d7}
    //round 4
    vldm.64 r1, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15
    veor d2, d24
    veor d4, d24
    veor d5, d24
    veor d7, d24
    vstm r1!, {d0-d7}
    //round 5
    vldm.64 r1, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15
    veor d2, d24
    veor d4, d24
    veor d5, d24
    veor d7, d24
    vstm r1!, {d0-d7}
    //round 6
    vldm.64 r1, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15
    veor d2, d24
    veor d4, d24
    veor d5, d24
    veor d7, d24
    vstm r1!, {d0-d7}
    //round 7
    vldm.64 r1, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15
    veor d2, d24
    veor d4, d24
    veor d5, d24
    veor d7, d24
    vstm r1!, {d0-d7}
    //round 8
    vldm.64 r1, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15
    veor d2, d24
    veor d4, d24
    veor d5, d24
    veor d7, d24
    vstm r1!, {d0-d7}
    //round 9
    vldm.64 r1, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15
    veor d2, d24
    veor d4, d24
    veor d5, d24
    veor d7, d24
    vstm r1!, {d0-d7}
    //round 10
    vldm.64 r1, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15
    veor d2, d24
    veor d4, d24
    veor d5, d24
    veor d7, d24
    vstm r1!, {d0-d7}
    //round final
    vldm.64 r1, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15
    veor d2, d24
    veor d4, d24
    veor d5, d24
    veor d7, d24
    vstm r1!, {d0-d7}

    bx lr


//assumes data in d0-d7
//will also overwrite d8-d15
//param rand is r register with address of randomnes, != sp/pc
//result in d0-d7 
.macro subbytes rand
    veor  d8,  d6,  d3                    //Exec y14 = U3 ^ U5 into d8
    veor  d9,  d0,  d5                    //Exec y13 = U0 ^ U6 into d9
    veor d10,  d9,  d8                    //Exec y12 = y13 ^ y14 into d10
    veor d11,  d1, d10                    //Exec t1 = U4 ^ y12 into d11
    veor d12, d11,  d3                    //Exec y15 = t1 ^ U5 into d12
    refresh \rand d10 d14
    masked_and \rand d13 d10 d12 d14 d15  //Exec t2 = y12 & y15 into d13
    veor d14, d12,  d7                    //Exec y6 = y15 ^ U7 into d14
    veor d15, d11,  d2                    //Exec y20 = t1 ^ U1 into d15
    veor d16,  d0,  d6                    //Exec y9 = U0 ^ U3 into d16
    veor d17, d15, d16                    //Exec y11 = y20 ^ y9 into d17
    refresh \rand d16 d19
    masked_and \rand d18 d16 d17 d19 d20  //Exec t12 = y9 & y11 into d18
    veor d19,  d7, d17                    //Exec y7 = U7 ^ y11 into d19
    veor d20,  d0,  d3                    //Exec y8 = U0 ^ U5 into d20
    veor d21,  d2,  d4                    //Exec t0 = U1 ^ U2 into d21
    veor d22, d12, d21                    //Exec y10 = y15 ^ t0 into d22
    veor d23, d22, d17                    //Exec y17 = y10 ^ y11 into d23
    refresh \rand  d8 d25
    masked_and \rand d24  d8 d23 d25 d26  //Exec t13 = y14 & y17 into d24
    veor d25, d24, d18                    //Exec t14 = t13 ^ t12 into d25
    veor d26, d22, d20                    //Exec y19 = y10 ^ y8 into d26
    refresh \rand d20 d28
    masked_and \rand d27 d20 d22 d28 d29  //Exec t15 = y8 & y10 into d27
    veor d28, d27, d18                    //Exec t16 = t15 ^ t12 into d28
    veor d29, d21, d17                    //Exec y16 = t0 ^ y11 into d29
    veor d30,  d9, d29                    //Exec y21 = y13 ^ y16 into d30
    refresh \rand  d9  d1
    masked_and \rand d31  d9 d29  d1  d2  //Exec t7 = y13 & y16 into d31
    veor  d1,  d0, d29                    //Exec y18 = U0 ^ y16 into d1
    veor  d2, d21,  d7                    //Exec y1 = t0 ^ U7 into d2
    veor  d3,  d2,  d6                    //Exec y4 = y1 ^ U3 into d3
    refresh \rand  d3  d6
    masked_and \rand  d4  d3  d7  d6 d11  //Exec t5 = y4 & U7 into d4
    veor  d6,  d4, d13                    //Exec t6 = t5 ^ t2 into d6
    veor d11,  d6, d28                    //Exec t18 = t6 ^ t16 into d11
    veor  d4, d11, d26                    //Exec t22 = t18 ^ y19 into d4
    veor  d0,  d2,  d0                    //Exec y2 = y1 ^ U0 into d0
    refresh \rand  d0 d11
    masked_and \rand  d6  d0 d19 d11 d18  //Exec t10 = y2 & y7 into d6
    veor d11,  d6, d31                    //Exec t11 = t10 ^ t7 into d11
    veor d18, d11, d28                    //Exec t20 = t11 ^ t16 into d18
    veor  d1, d18,  d1                    //Exec t24 = t20 ^ y18 into d1
    veor  d5,  d2,  d5                    //Exec y5 = y1 ^ U6 into d5
    refresh \rand  d5 d11
    masked_and \rand  d6  d5  d2 d11 d18  //Exec t8 = y5 & y1 into d6
    veor d11,  d6, d31                    //Exec t9 = t8 ^ t7 into d11
    veor d18, d11, d25                    //Exec t19 = t9 ^ t14 into d18
    veor  d6, d18, d30                    //Exec t23 = t19 ^ y21 into d6
    veor d11,  d5, d20                    //Exec y3 = y5 ^ y8 into d11
    refresh \rand d11 d21
    masked_and \rand d18 d11 d14 d21 d24  //Exec t3 = y3 & y6 into d18
    veor d21, d18, d13                    //Exec t4 = t3 ^ t2 into d21
    veor d24, d21, d15                    //Exec t17 = t4 ^ y20 into d24
    veor d13, d24, d25                    //Exec t21 = t17 ^ t14 into d13
    refresh \rand d13 d18
    masked_and \rand d15 d13  d6 d18 d21  //Exec t26 = t21 & t23 into d15
    veor d18,  d1, d15                    //Exec t27 = t24 ^ t26 into d18
    veor d21,  d4, d15                    //Exec t31 = t22 ^ t26 into d21
    veor d13, d13,  d4                    //Exec t25 = t21 ^ t22 into d13
    refresh \rand d13 d24
    masked_and \rand d15 d13 d18 d24 d25  //Exec t28 = t25 & t27 into d15
    veor d24, d15,  d4                    //Exec t29 = t28 ^ t22 into d24
    refresh \rand d24  d4
    masked_and \rand d25 d24  d0  d4 d15  //Exec z14 = t29 & y2 into d25
    refresh \rand d24 d15
    masked_and \rand  d4 d24 d19 d15  d0  //Exec z5 = t29 & y7 into d4
    veor  d0,  d6,  d1                    //Exec t30 = t23 ^ t24 into d0
    refresh \rand d21 d19
    masked_and \rand d15 d21  d0 d19 d26  //Exec t32 = t31 & t30 into d15
    veor d19, d15,  d1                    //Exec t33 = t32 ^ t24 into d19
    veor d26, d18, d19                    //Exec t35 = t27 ^ t33 into d26
    refresh \rand  d1 d15
    masked_and \rand  d0  d1 d26 d15 d21  //Exec t36 = t24 & t35 into d0
    veor d15, d18,  d0                    //Exec t38 = t27 ^ t36 into d15
    refresh \rand d24  d1
    masked_and \rand d21 d24 d15  d1 d18  //Exec t39 = t29 & t38 into d21
    veor  d1, d13, d21                    //Exec t40 = t25 ^ t39 into d1
    veor d18, d24,  d1                    //Exec t43 = t29 ^ t40 into d18
    refresh \rand d18 d15
    masked_and \rand d13 d18 d29 d15 d21  //Exec z3 = t43 & y16 into d13
    veor d15, d13,  d4                    //Exec tc12 = z3 ^ z5 into d15
    refresh \rand d18  d4
    masked_and \rand d21 d18  d9  d4 d26  //Exec z12 = t43 & y13 into d21
    refresh \rand  d1 d26
    masked_and \rand  d4  d1  d5 d26  d9  //Exec z13 = t40 & y5 into d4
    refresh \rand  d1 d26
    masked_and \rand  d9  d1  d2 d26  d5  //Exec z4 = t40 & y1 into d9
    veor  d5, d13,  d9                    //Exec tc6 = z3 ^ z4 into d5
    veor d26,  d6, d19                    //Exec t34 = t23 ^ t33 into d26
    veor  d0,  d0, d26                    //Exec t37 = t36 ^ t34 into d0
    veor  d1,  d1,  d0                    //Exec t41 = t40 ^ t37 into d1
    refresh \rand  d1  d6
    masked_and \rand  d2  d1 d22  d6  d9  //Exec z8 = t41 & y10 into d2
    refresh \rand  d1  d9
    masked_and \rand  d6  d1 d20  d9 d13  //Exec z17 = t41 & y8 into d6
    veor  d9, d19,  d0                    //Exec t44 = t33 ^ t37 into d9
    refresh \rand  d9 d18
    masked_and \rand d13  d9 d12 d18 d20  //Exec z0 = t44 & y15 into d13
    refresh \rand  d9 d20
    masked_and \rand d18  d9 d10 d20 d12  //Exec z9 = t44 & y12 into d18
    refresh \rand  d0 d20
    masked_and \rand d12  d0 d11 d20  d9  //Exec z10 = t37 & y3 into d12
    refresh \rand  d0 d20
    masked_and \rand  d9  d0 d14 d20 d10  //Exec z1 = t37 & y6 into d9
    veor d10,  d9, d13                    //Exec tc5 = z1 ^ z0 into d10
    veor d20,  d5, d10                    //Exec tc11 = tc6 ^ tc5 into d20
    refresh \rand d19  d9
    masked_and \rand  d0 d19  d3  d9 d10  //Exec z11 = t33 & y4 into d0
    veor  d9, d24, d19                    //Exec t42 = t29 ^ t33 into d9
    veor d10,  d9,  d1                    //Exec t45 = t42 ^ t41 into d10
    refresh \rand d10  d3
    masked_and \rand  d1 d10 d23  d3 d11  //Exec z7 = t45 & y17 into d1
    veor  d3,  d1,  d5                    //Exec tc8 = z7 ^ tc6 into d3
    refresh \rand d10  d1
    masked_and \rand d11 d10  d8  d1  d5  //Exec z16 = t45 & y14 into d11
    refresh \rand  d9  d5
    masked_and \rand  d1  d9 d17  d5  d8  //Exec z6 = t42 & y11 into d1
    veor  d5,  d1,  d3                    //Exec tc16 = z6 ^ tc8 into d5
    refresh \rand  d9  d1
    masked_and \rand  d8  d9 d16  d1 d10  //Exec z15 = t42 & y9 into d8
    veor  d1,  d8,  d5                    //Exec tc20 = z15 ^ tc16 into d1
    veor d10,  d8, d11                    //Exec tc1 = z15 ^ z16 into d10
    veor  d8, d12, d10                    //Exec tc2 = z10 ^ tc1 into d8
    veor  d0,  d8,  d0                    //Exec tc21 = tc2 ^ z11 into d0
    veor  d8, d18,  d8                    //Exec tc3 = z9 ^ tc2 into d8
    veor  d9,  d8,  d5                    //Exec S0 = tc3 ^ tc16 into d9
    veor  d8,  d8, d20                    //Exec S3 = tc3 ^ tc11 into d8
    veor  d5,  d8,  d5                    //Exec S1 = S3 ^ tc16 ^ 1 into d5
    veor  d4,  d4, d10                    //Exec tc13 = z13 ^ tc1 into d4
    refresh \rand d19 d11
    masked_and \rand d10 d19  d7 d11 d12  //Exec z2 = t33 & U7 into d10
    veor d11, d13, d10                    //Exec tc4 = z0 ^ z2 into d11
    veor d12, d21, d11                    //Exec tc7 = z12 ^ tc4 into d12
    veor  d2,  d2, d12                    //Exec tc9 = z8 ^ tc7 into d2
    veor  d2,  d3,  d2                    //Exec tc10 = tc8 ^ tc9 into d2
    veor  d3, d25,  d2                    //Exec tc17 = z14 ^ tc10 into d3
    veor  d0,  d0,  d3                    //Exec S5 = tc21 ^ tc17 into d0
    veor  d1,  d3,  d1                    //Exec tc26 = tc17 ^ tc20 into d1
    veor  d1,  d1,  d6                    //Exec S2 = tc26 ^ z17 ^ 1 into d1
    veor  d3, d11, d15                    //Exec tc14 = tc4 ^ tc12 into d3
    veor  d4,  d4,  d3                    //Exec tc18 = tc13 ^ tc14 into d4
    veor  d2,  d2,  d4                    //Exec S6 = tc10 ^ tc18 ^ 1 into d2
    veor  d4, d21,  d4                    //Exec S7 = z12 ^ tc18 ^ 1 into d4
    veor  d3,  d3,  d8                    //Exec S4 = tc14 ^ S3 into d3
    //[('d0', 'S5'), ('d1', 'S2'), ('d2', 'S6'), ('d3', 'S4'), ('d4', 'S7'), ('d5', 'S1'), ('d6', 'z17'), ('d7', 'U7'), ('d8', 'S3'), ('d9', 'S0'), ('d10', 'z2'), ('d11', 'tc4'), ('d12', 'tc7'), ('d13', 'z0'), ('d14', 'y6'), ('d15', 'tc12'), ('d16', 'y9'), ('d17', 'y11'), ('d18', 'z9'), ('d19', 't33'), ('d20', 'tc11'), ('d21', 'z12'), ('d22', 'y10'), ('d23', 'y17'), ('d24', 't29'), ('d25', 'z14'), ('d26', 't34'), ('d27', 't15'), ('d28', 't16'), ('d29', 'y16'), ('d30', 'y21'), ('d31', 't7')]
    vmov d7, d4 //S7
    vmov d4, d1 //S2
    vmov d1, d3 //S4
    vmov d3, d0 //S5
    vmov d0, d9 //S0
    //vmov d2, d2 //S6
    //vmov d5, d5 //S1
    vmov d6, d8 //S3

/*  state[0] = S0;
    state[1] = S4;
    state[2] = S6;
    state[3] = S5;
    state[4] = S2;
    state[5] = S1;
    state[6] = S3;
    state[7] = S7;*/
.endm

#assumes data in d0-d7
.macro mixcolumns
    //uint16_t r0 = state[7], r2 = state[2], r9 = state[3], r3 = state[1], r12 = state[6], r4 = state[4], r14 = state[5], r1 = state[0], r5, r6, r7, r8, r10, r11;
    vmov d9, d3
    vmov d3, d1
    vmov d1, d0
    vmov d0, d7
    vmov d12, d6
    vmov d14, d5

    //r10 = r2 ^ rol(r2, 4);
    vshl.I16 d10, d2, #4
    vsra.U16 d10, d2, #12
    //r7 = r9 ^ rol(r9, 4);
    vshl.I16 d7, d9, #4
    vsra.U16 d7, d9, #12
    //r11 = r0 ^ rol(r0, 4);
    vshl.I16 d11, d0, #4
    vsra.U16 d11, d0, #12
veor d10, d2
    //r8 = r3 ^ rol(r3, 4);
    vshl.I16 d8, d3, #4
    vsra.U16 d8, d3, #12
veor d7, d9
    //r5 = r14 ^ rol(r14, 4);
    vshl.I16 d5, d14, #4
    vsra.U16 d5, d14, #12
    //r9 = r9 ^ rol(r7, 4);
    vshl.I16 d13, d7, #4
    vsra.U16 d13, d7, #12
veor d11, d0
    //r9 = r9 ^ rol(r10, 12);
    vshl.I16 d6, d10, #12
    vsra.U16 d6, d10, #4
veor d5, d14
veor d9, d13
veor d8, d3
    //r7 = r12 ^ rol(r12, 4);
    vshl.I16 d7, d12, #4
    vsra.U16 d7, d12, #12
veor d9, d6
    //r6 = r4 ^ rol(r4, 4);
    vshl.I16 d6, d4, #4
    vsra.U16 d6, d4, #12
    //r3 = r3 ^ rol(r7, 12);
    vrev16.8 d13, d13
veor d7, d12
    veor d3, d13
    //r4 = r4 ^ rol(r7, 12);
    vshl.I16 d13, d7, #12
    vsra.U16 d13, d7, #4
veor d6, d4
    //r14 = r14 ^ rol(r6, 12);
    vshl.I16 d15, d6, #12
    vsra.U16 d15, d6, #4
    veor d14, d15
veor d4, d13
    //r6 = r4 ^ rol(r6, 4);
    vrev16.8 d15, d15
    veor d6, d4, d15
    //r4 = r1 ^ rol(r1, 4);
    vshl.I16 d4, d1, #4
    vsra.U16 d4, d1, #12
    //r2 = r2 ^ rol(r11, 12);
    vshl.I16 d15, d11, #12
    vsra.U16 d15, d11, #4
veor d4, d1
    //r0 = r0 ^ rol(r4, 12);
    vshl.I16 d13, d4, #12
    vsra.U16 d13, d4, #4
veor d2, d15
veor d0, d13
    //r2 = r2 ^ rol(r4, 12);
    veor d2, d13
    //r11 = r0 ^ rol(r11, 4);
    vrev16.8 d15, d15
    veor d11, d0, d15
    //r12 = r12 ^ rol(r8, 12);
    vshl.I16 d15, d8, #12
    vsra.U16 d15, d8, #4
    //r3 = r3 ^ rol(r4, 12);
    veor d3, d13
    //r12 = r12 ^ rol(r4, 12);
    veor d12, d13
    //r7 = r12 ^ rol(r7, 4);
    vshl.I16 d13, d7, #4
    vsra.U16 d13, d7, #12
veor d12, d15
    //r8 = r3 ^ rol(r8, 4);
    vrev16.8 d15, d15
    veor d8, d3, d15
    //r10 = r2 ^ rol(r10, 4);
    vshl.I16 d15, d10, #4
    vsra.U16 d15, d10, #12
veor d7, d12, d13
    //r1 = r1 ^ rol(r5, 12);
    vshl.I16 d12, d5, #12
    vsra.U16 d12, d5, #4
    //r4 = r1 ^ rol(r4, 4);
    vshl.I16 d13, d4, #4
    vsra.U16 d13, d4, #12
veor d1, d12
veor d10, d2, d15
    //r5 = r14 ^ rol(r5, 4);
    vrev16.8 d12, d12
    veor d5, d14, d12
veor d4, d1, d13

    //state[1] = rol(r8, 4);
    vshl.I16 d1, d8, #4
    vsra.U16 d1, d8, #12
    //state[2] = rol(r5, 4);
    vshl.I16 d2, d5, #4
    vsra.U16 d2, d5, #12
    //state[0] = rol(r4, 4);
    vshl.I16 d0, d4, #4
    vsra.U16 d0, d4, #12
    //state[4] = rol(r6, 4);
    vshl.I16 d4, d6, #4
    vsra.U16 d4, d6, #12
    //state[6] = rol(r7, 4);
    vshl.I16 d6, d7, #4
    vsra.U16 d6, d7, #12
    //state[3] = rol(r9, 4);
    vshl.I16 d3, d9, #4
    vsra.U16 d3, d9, #12
    //state[5] = rol(r10, 4);
    vshl.I16 d5, d10, #4
    vsra.U16 d5, d10, #12
    //state[7] = rol(r11, 4);
    vshl.I16 d7, d11, #4
    vsra.U16 d7, d11, #12
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
//param tmp is q register that gets overwritten
.macro addroundkey rk a0 a1 a2 a3 a4 a5 a6 a7 tmp
    vld1.64 {\tmp}, [\rk:64]!
    veor \a0, \tmp
    vld1.64 {\tmp}, [\rk:64]!
    veor \a1, \tmp
    vld1.64 {\tmp}, [\rk:64]!
    veor \a2, \tmp
    vld1.64 {\tmp}, [\rk:64]!
    veor \a3, \tmp
    vld1.64 {\tmp}, [\rk:64]!
    veor \a4, \tmp
    vld1.64 {\tmp}, [\rk:64]!
    veor \a5, \tmp
    vld1.64 {\tmp}, [\rk:64]!
    veor \a6, \tmp
    vld1.64 {\tmp}, [\rk:64]!
    veor \a7, \tmp
.endm

//param rand is r register with address of randomness
//param a is d register to refresh
//param tmp is d register that gets overwritten
.macro refresh rand a tmp
    vld1.64 {\tmp}, [\rand]! //get 8 bytes of randomness
    veor \a, \tmp
    vext.16 \tmp, \tmp, #1
    veor \a, \tmp
.endm

//param rand is r register with address of randomness
//param c is d register where result gets stored
//param a and b are d registers to and, remain unchanged
//param tmp and tmpr are d registers that get overwritten
.macro masked_and rand c a b tmp tmpr
    vand \c, \a, \b //K = A.B
    vld1.64 {\tmpr}, [\rand]! //get 8 bytes of randomness
    vext.16 \tmp, \b, \b, #1
    veor \c, \tmpr  // + R
    vand \tmp, \a
    veor \c, \tmp   // + A.(rot B 1)
    vext.16 \tmp, \a, \a, #1
    vand \tmp, \b
    veor \c, \tmp   // + (rot A 1).B
    vext.16 \tmpr, \tmpr, #1
    veor \c, \tmpr  // + (rot R 1)
    vext.16 \tmp, \b, \b, #2
    vand \tmp, \a
    veor \c, \tmp   // + A.(rot B 2)
    vld1.16 {\tmp[]}, [\rand]! //get 2 bytes of randomness
    veor \c, \tmp   // + (r5,r5,r5,r5)
.endm

.macro round rk rand
    addroundkey \rk d0 d1 d2 d3 d4 d5 d6 d7 d15
    subbytes \rand 
    shiftrows d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 d10 d11 d12 d13 d14 d15
    mixcolumns
.endm

.ifdef ANALYSIS
//struct timespec 3ms
.local timeval
timeval:
    .word 0       //tv_sec
    .word 3000000 //tv_nsec
.endif

//void aes_enc(FILE * random, bint16_t rk[11][8*NUM_BLOCKS], bint16_t state[8*NUM_BLOCKS]);
.align 4
.global aes_enc
.type aes_enc STT_FUNC
aes_enc:
 
    push {r1-r3,lr}
    
    mov r3, r0 //FILE
    movw r0, #:lower16:randomness
    movt r0, #:upper16:randomness
    mov r1, #32 //size
    mov r2, #180 //number
    bl fread

    pop {r1-r3}

    //load state in vector registers
    vldm.64 r2, {d0-d7}
    bitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15

.ifdef ANALYSIS
    //set trigger
    push {r1-r3}
    mov r0, r3
    bl triggerup
    pop {r1-r3}
.endif

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
    addroundkey r1 d0 d1 d2 d3 d4 d5 d6 d7 d15
    subbytes r0
    vswp d2, d5
    shiftrows d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 d10 d11 d12 d13 d14 d15
    addroundkey r1 d0 d1 d2 d3 d4 d5 d6 d7 d15

.ifdef ANALYSIS
    //unset trigger
    push {r1-r3}
    mov r0, r3
    bl triggerdown
    pop {r1-r3}
.endif

    unbitslice d0 d1 d2 d3 d4 d5 d6 d7 d13 d14 d15

    //store output to memory
    vstm r2, {d0-d7}

    pop {lr}
    bx lr

