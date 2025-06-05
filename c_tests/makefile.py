import os
import powermake

def cargo_build(config: powermake.Config):
    files = powermake.get_files("../quiceh/**/*.rs", "../quiceh/**/*.toml")
    powermake.run_command_if_needed(config, "../target/debug/libquiceh.so", dependencies=files, command=["cargo", "build", "--color", "always", "--features", "ffi"])

def on_build(config: powermake.Config):
    config.add_flags("-Wall", "-Wextra")

    config.add_shared_libs("quiceh")
    config.add_includedirs("../quiceh/include/")

    config.add_ld_flags("-L../target/debug/")

    cargo_build(config)

    files = powermake.get_files("*.c")
    objects = powermake.compile_files(config, files)
    powermake.link_files(config, objects)

def on_test(config: powermake.Config, args):
    os.environ["LD_LIBRARY_PATH"] = "../target/debug/"
    os.environ["RUST_BACKTRACE"] = "1"
    os.environ["RUST_LOGS"] = "trace"
    powermake.default_on_test(config, args)

powermake.run("test1", build_callback=on_build, test_callback=on_test)