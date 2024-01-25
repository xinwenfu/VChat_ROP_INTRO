xor eax, eax           ; Clear out the EAX register, we do not know what may be stored there 
add eax, 0xabcdabb9    ; Add set eax = 0 + 0xabcdabb9 (One off from the goal so we can make the chain more interesting)
inc eax                ; Get final value of eax