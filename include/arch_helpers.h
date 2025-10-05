#pragma once

#ifdef _WIN64
  #define XDBG_IS_X64 1
  #define XDBG_IP_REG Script::Register::RIP
  #define XDBG_IP_NAME "rip"
#else
  #define XDBG_IS_X64 0
  #define XDBG_IP_REG Script::Register::EIP
  #define XDBG_IP_NAME "eip"
#endif
