#!/usr/bin/env sh
set -eu
profile="${USQUE_BUILD_PROFILE:-release}"
cargo build --profile "$profile"
