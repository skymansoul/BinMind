/* BinMind 评测生成的最小驱动入口 (generated, not part of Juliet).
 * Juliet v1.3 official main.cpp is directory-wide (calls hundreds of test
 * functions), unusable for single-sample builds; this driver only calls this
 * sample's bad/good per the official OMITBAD/OMITGOOD macro semantics.
 * Test function bodies remain NIST originals, unmodified.
 */
#include "std_testcase.h"

#ifndef OMITBAD
void CWE416_Use_After_Free__malloc_free_char_01_bad(void);
#endif
#ifndef OMITGOOD
void CWE416_Use_After_Free__malloc_free_char_01_good(void);
#endif

int main(void)
{
#ifndef OMITBAD
    CWE416_Use_After_Free__malloc_free_char_01_bad();
#endif
#ifndef OMITGOOD
    CWE416_Use_After_Free__malloc_free_char_01_good();
#endif
    return 0;
}
