#ifndef __DRYGASCON_ARM_SELECTOR_H__
#define __DRYGASCON_ARM_SELECTOR_H__
//Optional file to select the best implementation for each chip

#ifdef STM32H743xx
    #define __DRYGASCON_ARM_SELECTOR_V7M_FPU__
    #define __DRYGASCON_ARM_SELECTOR_FOUND__
#endif

#ifdef STM32F746xx
    #define __DRYGASCON_ARM_SELECTOR_V7M_FPU__
    #define __DRYGASCON_ARM_SELECTOR_FOUND__
#endif

#ifdef STM32F411xx
    #define __DRYGASCON_ARM_SELECTOR_V7M_FPU__
    #define __DRYGASCON_ARM_SELECTOR_FOUND__
#endif

#ifdef STM32L552xx //technically it is V8M but we don't have a specific code for that one
    #define __DRYGASCON_ARM_SELECTOR_V7M__
    #define __DRYGASCON_ARM_SELECTOR_FOUND__
#endif

#ifdef STM32F103xx
    #define __DRYGASCON_ARM_SELECTOR_V7M__
    #define __DRYGASCON_ARM_SELECTOR_FOUND__
#endif

#ifdef STM32L011xx
    #define __DRYGASCON_ARM_SELECTOR_V6M__
    #define __DRYGASCON_ARM_SELECTOR_FOUND__
#endif

#ifdef __SAM3X8E__
    #define __DRYGASCON_ARM_SELECTOR_V7M__
    #define __DRYGASCON_ARM_SELECTOR_FOUND__
#endif

//TODO: add more chips here

#ifndef __DRYGASCON_ARM_SELECTOR_FOUND__
    //more generic defines catching whole families
    #if defined(STM32F4xx) || defined(STM32F7xx) || defined(STM32H7xx)
        #define __DRYGASCON_ARM_SELECTOR_V7M_FPU__
        #define __DRYGASCON_ARM_SELECTOR_FOUND__
    #endif

    #if defined(STM32F1xx)
        #define __DRYGASCON_ARM_SELECTOR_V7M__
        #define __DRYGASCON_ARM_SELECTOR_FOUND__
    #endif
#endif

#ifdef __DRYGASCON_ARM_SELECTOR_V7M_FPU__
    #define DRYGASCON_G_OPT   drygascon128_g_v7m_fpu
    #define DRYGASCON_F_OPT   drygascon128_f_v7m_fpu
    #define DRYGASCON_G0_OPT  drygascon128_g0_v7m_fpu
#endif

#ifdef __DRYGASCON_ARM_SELECTOR_V7M_FPU_X__
    #define DRYGASCON_G_OPT   drygascon128_g_v7m_fpu_x
    #define DRYGASCON_F_OPT   drygascon128_f_v7m_fpu_x
    #define DRYGASCON_G0_OPT  drygascon128_g0_v7m_fpu_x
#endif

#ifdef __DRYGASCON_ARM_SELECTOR_V7M__
    #define DRYGASCON_G_OPT   drygascon128_g_v7m
    #define DRYGASCON_F_OPT   drygascon128_f_v7m
    #define DRYGASCON_G0_OPT  drygascon128_g0_v7m
#endif

#ifdef __DRYGASCON_ARM_SELECTOR_V6M__
        #define DRYGASCON_G_OPT   drygascon128_g_v6m
        #define DRYGASCON_F_OPT   drygascon128_f_v6m
        //#define DRYGASCON_G0_OPT drygascon128_g0_v6m
        #define DRYGASCON_ALIGN_INPUT_32
#endif

#endif
