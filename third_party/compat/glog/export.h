// Compatibility shim for glog's export.h.
// The glog Bazel build (BCR) does not generate export.h — it provides
// GLOG_EXPORT / GLOG_NO_EXPORT via cc_library defines instead. The
// fizz-rs FFI sources #define GLOG_USE_GLOG_EXPORT (for CMake builds)
// which triggers `#include "glog/export.h"`, so we supply this stub.

#pragma once

#ifndef GLOG_EXPORT
#  if defined(_WIN32)
#    define GLOG_EXPORT __declspec(dllexport)
#  elif defined(__GNUC__) || defined(__clang__)
#    define GLOG_EXPORT __attribute__((visibility("default")))
#  else
#    define GLOG_EXPORT
#  endif
#endif

#ifndef GLOG_NO_EXPORT
#  define GLOG_NO_EXPORT GLOG_EXPORT
#endif

#ifndef GLOG_DEPRECATED
#  define GLOG_DEPRECATED __attribute__((deprecated))
#endif

#ifndef GLOG_DEPRECATED_EXPORT
#  define GLOG_DEPRECATED_EXPORT GLOG_EXPORT
#endif

#ifndef GLOG_DEPRECATED_NO_EXPORT
#  define GLOG_DEPRECATED_NO_EXPORT GLOG_NO_EXPORT
#endif
