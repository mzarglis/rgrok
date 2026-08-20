#!/bin/sh
set -eu

config_path=/etc/rgrok/server.toml
previous_arg=
for arg in "$@"; do
    case "$arg" in
        --config=*) config_path=${arg#--config=} ;;
    esac
    if [ "$previous_arg" = "--config" ] || [ "$previous_arg" = "-c" ]; then
        config_path=$arg
    fi
    previous_arg=$arg
done

if [ ! -f "$config_path" ]; then
    echo "rgrok-server: no configuration file found at $config_path" >&2
    echo "Mount an operator-managed config, for example: -v /etc/rgrok:/etc/rgrok:ro" >&2
    echo "Generate auth.secret with: openssl rand -hex 32" >&2
    exit 78
fi
if [ ! -r "$config_path" ]; then
    echo "rgrok-server: configuration file is not readable at $config_path" >&2
    echo "Ensure the mounted file is readable by the container's rgrok user." >&2
    exit 77
fi

exec /usr/local/bin/rgrok-server "$@"
