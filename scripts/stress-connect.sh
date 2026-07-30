#!/bin/sh

set -eu
umask 077

mode=
config=
iterations=50
connect_timeout=20
hold_seconds=2
binary=./target/release/usque-nativetun
interface=tun99
prefer_ipv6=0

usage() {
    cat <<'EOF'
Usage:
  stress-connect.sh --mode client|mesh --config PATH [options]

Options:
  --iterations N          Number of connect/disconnect cycles (default: 50)
  --connect-timeout SEC   Seconds allowed for CONNECT-IP setup (default: 20)
  --hold-seconds SEC      Seconds to retain an established session (default: 2)
  --binary PATH           usque-nativetun binary (default: target/release)
  --interface NAME        Dedicated, unused FreeBSD TUN name (default: tun99)
  --prefer-ipv6           Prefer an IPv6 MASQUE endpoint
  -h, --help              Show this help
EOF
}

require_value() {
    if [ "$#" -lt 2 ] || [ -z "$2" ]; then
        echo "missing value for $1" >&2
        usage >&2
        exit 2
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --mode)
            require_value "$@"
            mode=$2
            shift 2
            ;;
        --config)
            require_value "$@"
            config=$2
            shift 2
            ;;
        --iterations)
            require_value "$@"
            iterations=$2
            shift 2
            ;;
        --connect-timeout)
            require_value "$@"
            connect_timeout=$2
            shift 2
            ;;
        --hold-seconds)
            require_value "$@"
            hold_seconds=$2
            shift 2
            ;;
        --binary)
            require_value "$@"
            binary=$2
            shift 2
            ;;
        --interface)
            require_value "$@"
            interface=$2
            shift 2
            ;;
        --prefer-ipv6)
            prefer_ipv6=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$mode" in
    client)
        subcommand=nativetun
        ;;
    mesh)
        subcommand=mesh-node
        ;;
    *)
        echo "--mode must be client or mesh" >&2
        exit 2
        ;;
esac

is_positive_integer() {
    case "$1" in
        ''|*[!0-9]*|0)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

is_nonnegative_integer() {
    case "$1" in
        ''|*[!0-9]*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

if ! is_positive_integer "$iterations"; then
    echo "--iterations must be a positive integer" >&2
    exit 2
fi
if ! is_positive_integer "$connect_timeout"; then
    echo "--connect-timeout must be a positive integer" >&2
    exit 2
fi
if ! is_nonnegative_integer "$hold_seconds"; then
    echo "--hold-seconds must be a non-negative integer" >&2
    exit 2
fi
case "${interface#tun}" in
    ''|*[!0-9]*)
        echo "--interface must use a FreeBSD tunN name" >&2
        exit 2
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "run this test as root so it can create and clean up the TUN interface" >&2
    exit 1
fi
if [ ! -f "$config" ]; then
    echo "config not found: $config" >&2
    exit 1
fi
if [ ! -x "$binary" ]; then
    echo "binary is not executable: $binary" >&2
    echo "build it first with: cargo build --release" >&2
    exit 1
fi
if ! command -v ifconfig >/dev/null 2>&1; then
    echo "ifconfig is required" >&2
    exit 1
fi

log_dir=$(mktemp -d "${TMPDIR:-/tmp}/usque-connect-stress.XXXXXX")
current_pid=
owns_interface=0
cleanup_failed=0

cleanup_current() {
    if [ -n "$current_pid" ] && kill -0 "$current_pid" 2>/dev/null; then
        kill -TERM "$current_pid" 2>/dev/null || true
        remaining=5
        while kill -0 "$current_pid" 2>/dev/null && [ "$remaining" -gt 0 ]; do
            sleep 1
            remaining=$((remaining - 1))
        done
        if kill -0 "$current_pid" 2>/dev/null; then
            kill -KILL "$current_pid" 2>/dev/null || true
        fi
    fi
    if [ -n "$current_pid" ]; then
        wait "$current_pid" 2>/dev/null || true
        current_pid=
    fi

    if [ "$owns_interface" -eq 1 ] && ifconfig "$interface" >/dev/null 2>&1; then
        if ! ifconfig "$interface" destroy; then
            echo "failed to destroy test interface: $interface" >&2
            cleanup_failed=1
        fi
    fi
    if ifconfig "$interface" >/dev/null 2>&1; then
        echo "test interface still exists after cleanup: $interface" >&2
        cleanup_failed=1
    fi
    owns_interface=0
}

trap 'cleanup_current' EXIT
trap 'exit 130' HUP INT TERM

echo "Mode: $mode"
echo "Iterations: $iterations"
echo "Interface: $interface"
echo "Logs: $log_dir"

connected_count=0
failed_count=0
protocol_violation_count=0
iteration=1

while [ "$iteration" -le "$iterations" ]; do
    if ifconfig "$interface" >/dev/null 2>&1; then
        echo "refusing to use existing interface: $interface" >&2
        exit 1
    fi

    log_file="$log_dir/$(printf '%04d' "$iteration").log"
    echo "[$iteration/$iterations] establishing $mode session"

    if [ "$prefer_ipv6" -eq 1 ]; then
        RUST_LOG=info "$binary" --config "$config" "$subcommand" \
            --interface-name "$interface" --always-reconnect --no-iproute2 \
            --ipv6 >"$log_file" 2>&1 &
    else
        RUST_LOG=info "$binary" --config "$config" "$subcommand" \
            --interface-name "$interface" --always-reconnect --no-iproute2 \
            >"$log_file" 2>&1 &
    fi
    current_pid=$!
    owns_interface=1

    connected=0
    elapsed=0
    while [ "$elapsed" -lt "$connect_timeout" ]; do
        if grep -q "Connected to MASQUE server" "$log_file"; then
            connected=1
            break
        fi
        if ! kill -0 "$current_pid" 2>/dev/null; then
            break
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    iteration_ok=0
    if [ "$connected" -eq 1 ]; then
        if [ "$hold_seconds" -gt 0 ]; then
            sleep "$hold_seconds"
        fi
        if kill -0 "$current_pid" 2>/dev/null &&
            ! grep -Eq 'MASQUE session (failed|ended)' "$log_file"; then
            iteration_ok=1
        fi
    fi

    cleanup_current

    violations=$(grep -Eic 'PROTOCOL_VIOLATION|protocol violation' "$log_file" || true)
    protocol_violation_count=$((protocol_violation_count + violations))

    if [ "$iteration_ok" -eq 1 ]; then
        connected_count=$((connected_count + 1))
        echo "[$iteration/$iterations] connected and stable (setup <= ${elapsed}s)"
    else
        failed_count=$((failed_count + 1))
        echo "[$iteration/$iterations] failed; last log lines:" >&2
        tail -n 20 "$log_file" >&2
    fi

    iteration=$((iteration + 1))
done

echo
echo "Connection stress summary"
echo "  requested:           $iterations"
echo "  connected:           $connected_count"
echo "  failed:              $failed_count"
echo "  protocol violations: $protocol_violation_count"
echo "  cleanup failures:    $cleanup_failed"
echo "  logs:                $log_dir"

if [ "$failed_count" -ne 0 ] ||
    [ "$protocol_violation_count" -ne 0 ] ||
    [ "$cleanup_failed" -ne 0 ]; then
    exit 1
fi
