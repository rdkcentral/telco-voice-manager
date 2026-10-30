#!/usr/bin/env bash
# Creates empty stand-ins for libraries that are not built natively so the final link succeeds.
# Unresolved symbols are tolerated via -Wl,--unresolved-symbols=ignore-all in configure_options.conf.
set -e

LIB_DIR="$HOME/usr/local/lib"
mkdir -p "$LIB_DIR"

[[ -e "$LIB_DIR/libmsgpackc.so" ]] || ln -s "$HOME/usr/lib/libmsgpack-c.so" "$LIB_DIR/libmsgpackc.so"

STUB_SRC="$(mktemp --suffix=.c)"
trap 'rm -f "$STUB_SRC"' EXIT
echo "int cov_stub_placeholder;" > "$STUB_SRC"

for lib in webconfig_framework utctx utapi sysevent syscfg rdkloggers libparodus json_hal_client hal_platform avro; do
    if ! ls "$LIB_DIR/lib${lib}.so" "$HOME/usr/lib/lib${lib}.so" >/dev/null 2>&1; then
        gcc -shared -fPIC -o "$LIB_DIR/lib${lib}.so" "$STUB_SRC"
    fi
done
