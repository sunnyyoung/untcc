# untcc

In-memory TCC bypass for macOS.

## Features

- Install hooks in system and user `tccd` processes
- Automatically reapply hooks when `tccd` restarts

## Requirements

- Apple silicon Mac running macOS 26 or later
- Root access and disabled SIP for injection

## Installation & Usage

```bash
# Install
brew install sunnyyoung/tap/untcc

# Update
brew upgrade untcc

# Start the service
sudo brew services start untcc

# Check permissions
untcc probe

# Stop the service
sudo brew services stop untcc
```

Run `sudo untcc` for foreground mode. Service logs are written to `$(brew --prefix)/var/log/untcc.log`.

`probe` reports the current process's Accessibility and Screen Recording access as JSON. It requires no root privileges and exits with `0` when both are allowed, otherwise `1`.

**Stopping untcc leaves hooks active until `tccd` exits.** Stop untcc and restart macOS to remove them.

## Build

Requires Xcode 27 or later.

```bash
make          # Debug
make release  # Release, with SHA-256
make clean
```

Binaries are written to `dist/Debug/untcc` and `dist/Release/untcc`.

## Tests

Requires `vmpal` on the host. The macOS VM needs disabled SIP, a signed-in administrator with passwordless sudo, and `untcc` installed through Homebrew.

```bash
./tests.sh "<vm>"
# Or
make test VM="<vm>"
```

[tests.sh](tests.sh) builds and tests Debug and Release in the selected VM. Permission checks run through an independent LaunchAgent. A successful run leaves the Release service running.

## References

- [tcc-bypass](https://github.com/unixzii/tcc-bypass)
- [yabai loader](https://github.com/koekeishiya/yabai/blob/master/src/osax/loader.m)
- [Clang Blocks ABI](https://clang.llvm.org/docs/Block-ABI-Apple.html)

## License

The [MIT](LICENSE) License.
