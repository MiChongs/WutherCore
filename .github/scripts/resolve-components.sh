#!/usr/bin/env bash
# Resolve the component tag set for one build matrix target.
#
# An explicitly requested tag set always wins and is used verbatim on every
# target. Only when nothing was requested does the target fall back to its own
# default preset. The literal preset `standard` is expressed as an empty tag
# set so the build runs wuther-core's default features instead of passing
# --no-default-features.
#
# Inputs (environment):
#   DEFAULT_TAGS     this target's preset, e.g. `standard` or `portable,with_young`
#   REQUESTED_TAGS   normalized tags requested for the whole matrix, may be empty
#   REQUESTED_LABEL  human readable form of REQUESTED_TAGS
#   REQUESTED_KEY    cache key fragment for REQUESTED_TAGS
#   TARGET           target triple, used only for diagnostics
#   YOUNG_SUPPORTED  `false` when this target has no NSS build chain
#
# Outputs (GITHUB_OUTPUT): tags, label, key, young

set -euo pipefail

tags="${REQUESTED_TAGS:-}"
label="${REQUESTED_LABEL:-}"
key="${REQUESTED_KEY:-}"

hash_tags() {
  # macOS runners ship shasum rather than sha256sum.
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | cut -c1-16
  else
    printf '%s' "$1" | shasum -a 256 | cut -c1-16
  fi
}

if [ -z "$tags" ] && [ "${DEFAULT_TAGS:-standard}" != "standard" ]; then
  tags="$DEFAULT_TAGS"
  label="$DEFAULT_TAGS (platform default)"
  key="$(hash_tags "$tags")"
fi

# Young embeds Mozilla NSS through nss-rs, so every target that compiles it
# needs the NSS toolchain provisioned first. An empty tag set means default
# features, which is `standard`, which includes `with_young`.
young=false
case ",${tags:-standard}," in
*,with_young,* | *,standard,* | *,all_components,*) young=true ;;
esac

# Fail loudly rather than shipping an archive that silently dropped a component
# the caller asked for. Targets opt out through YOUNG_SUPPORTED because their
# NSS build chain does not exist upstream, not because of a policy choice.
if [ "$young" = true ] && [ "${YOUNG_SUPPORTED:-true}" != "true" ]; then
  echo "::error::with_young was requested for ${TARGET:-this target}, which has no NSS build chain."
  exit 1
fi

{
  echo "tags=$tags"
  echo "label=$label"
  echo "key=$key"
  echo "young=$young"
} >> "$GITHUB_OUTPUT"

echo "components: tags='${tags:-<default features>}' young=$young"
