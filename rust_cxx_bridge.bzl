"""CXX bridge macro for generating C++ from Rust bridge definitions.

Adapted from bazelbuild/rules_rust examples/crate_universe/using_cxx.
"""

load("@bazel_skylib//rules:run_binary.bzl", "run_binary")
load("@rules_cc//cc:defs.bzl", "cc_library")

def rust_cxx_bridge(name, src, deps = [], strip_include_prefix = "", include_prefix = ""):
    """Generate C++ bridge code from a CXX bridge Rust source file.

    Creates three targets:
      {name}/include  - cc_library with the generated header
      {name}          - cc_library with the generated source (links against /include)

    Args:
        name: target name
        src: Rust source file containing #[cxx::bridge]
        deps: extra cc_library deps for the generated source target
        strip_include_prefix: strip this prefix from the generated header path
        include_prefix: add this prefix to the generated header path
    """
    run_binary(
        name = "%s/generated" % name,
        srcs = [src],
        outs = [
            src + ".h",
            src + ".cc",
        ],
        args = [
            "$(location %s)" % src,
            "-o",
            "$(location %s.h)" % src,
            "-o",
            "$(location %s.cc)" % src,
        ],
        tool = "@crates//:cxxbridge-cmd__cxxbridge-cmd",
    )

    include_kwargs = {}
    if strip_include_prefix:
        include_kwargs["strip_include_prefix"] = strip_include_prefix
    if include_prefix:
        include_kwargs["include_prefix"] = include_prefix

    cc_library(
        name = "%s/include" % name,
        hdrs = [src + ".h"],
        **include_kwargs
    )

    cc_library(
        name = name,
        srcs = [src + ".cc"],
        linkstatic = True,
        deps = deps + [":%s/include" % name],
    )
