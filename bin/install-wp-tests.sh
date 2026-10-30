#!/usr/bin/env bash

set -euo pipefail

# Pinned WP-CLI scaffold installer. Keeping the revision here makes CI setup
# reproducible while avoiding a large generated copy of the upstream script.
readonly INSTALLER_REVISION="7590c4bc7479348b5197e9235ab82f4a0aba4c65"
readonly INSTALLER_URL="https://raw.githubusercontent.com/wp-cli/scaffold-command/${INSTALLER_REVISION}/templates/install-wp-tests.sh"
readonly INSTALLER_FILE="$(mktemp)"

cleanup() {
    rm -f "${INSTALLER_FILE}"
}
trap cleanup EXIT

curl --fail --location --silent --show-error "${INSTALLER_URL}" --output "${INSTALLER_FILE}"

WP_INSTALL_TESTS_SKIP_UPDATE_CHECK=true bash "${INSTALLER_FILE}" "$@"
