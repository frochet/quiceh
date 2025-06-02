import powermake

def cargo_build(config: powermake.Config):
    files = powermake.get_files("../quiceh/**/*.rs", "../quiceh/**/*.toml")
    powermake.run_command_if_needed(config, "../target/debug/libquiceh.so", dependencies=files, command=["cargo", "build", "--color", "always", "--features", "ffi"])

def on_build(config: powermake.Config):
    config.add_flags("-Wall", "-Wextra", "-fanalyzer")

    config.add_shared_libs("quiceh")
    config.add_includedirs("../quiceh/include/")

    config.add_ld_flags("-L../target/debug/", "-static")

    cargo_build(config)

    files = powermake.get_files("*.c")
    objects = powermake.compile_files(config, files)
    powermake.link_files(config, objects)

powermake.run("test1", build_callback=on_build)