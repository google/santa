#include <mach/mach_types.h>

#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

extern "C" {

  extern kern_return_t _start(kmod_info_t *ki, void *data);
  extern kern_return_t _stop(kmod_info_t *ki, void *data);

  __attribute__((visibility("default"))) \
    KMOD_EXPLICIT_DECL(com.google.santa-driver, STR(SANTA_VERSION), _start, _stop)

  __private_extern__ kmod_start_func_t *_realmain = 0;
  __private_extern__ kmod_stop_func_t *_antimain = 0;

  __private_extern__ int _kext_apple_cc = __APPLE_CC__ ;
}
