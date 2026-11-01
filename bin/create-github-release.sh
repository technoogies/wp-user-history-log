#!/usr/bin/env bash
#
# Create a GitHub Release for the plugin header Version when one is missing.
# The tag name matches Version exactly (for example 1.9.0, not v1.9.0).
# Existing tags named 1.9.0 or v1.9.0 count as already published.

set -euo pipefail

PLUGIN_FILE="${PLUGIN_FILE:-wp-user-history-logging.php}"
README_FILE="${README_FILE:-readme.txt}"

extract_plugin_version() {
    local source_text="$1"
    printf '%s\n' "${source_text}" | sed -n 's/^ \* Version:[[:space:]]*//p' | head -n 1 | tr -d '[:space:]'
}

if [[ ! -f "${PLUGIN_FILE}" ]]; then
    echo "Missing plugin file: ${PLUGIN_FILE}" >&2
    exit 1
fi

current_version="$(extract_plugin_version "$(cat "${PLUGIN_FILE}")")"

if [[ -z "${current_version}" ]]; then
    echo "Could not read Version: from ${PLUGIN_FILE}" >&2
    exit 1
fi

if [[ ! "${current_version}" =~ ^[0-9]+([.][0-9A-Za-z-]+)*$ ]]; then
    echo "Version ${current_version} is not a release tag" >&2
    exit 1
fi

previous_version=""
if git rev-parse --verify HEAD^ >/dev/null 2>&1; then
    previous_version="$(extract_plugin_version "$(git show "HEAD^:${PLUGIN_FILE}")")"
fi

if [[ -n "${previous_version}" && "${previous_version}" != "${current_version}" ]]; then
    echo "Version bumped ${previous_version} -> ${current_version}."
elif [[ -n "${previous_version}" ]]; then
    echo "Version is unchanged (${current_version}); creating a Release only if one is missing."
else
    echo "No previous commit to compare; treating ${current_version} as a first Release."
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "gh is required to publish a Release." >&2
    exit 1
fi

if gh release view "${current_version}" >/dev/null 2>&1; then
    echo "Release ${current_version} already exists; skipping."
    exit 0
fi

if gh release view "v${current_version}" >/dev/null 2>&1; then
    echo "Release v${current_version} already exists; skipping."
    exit 0
fi

notes="WP User History Log ${current_version}."
if [[ -f "${README_FILE}" ]]; then
    extracted="$(awk -v ver="${current_version}" '
        $0 == "= " ver " =" {found=1; next}
        found && $0 ~ /^= / {exit}
        found {print}
    ' "${README_FILE}" | sed '/^[[:space:]]*$/d')"
    if [[ -n "${extracted}" ]]; then
        notes="${extracted}"
    fi
fi

gh release create "${current_version}" \
    --title "${current_version}" \
    --target "${RELEASE_SHA:-${GITHUB_SHA:-HEAD}}" \
    --notes "${notes}"

echo "Published GitHub Release ${current_version}."
