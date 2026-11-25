# Safe access to the scanner state in the data-latest release (sourced by watch.yml).
# GitHub's API returns transient 5xx; a failed download must never be mistaken for "no state", and an upload must
# never delete the previous asset before the new one is stored.
#   rel_get NAME OUT  -> 0 downloaded to OUT, 2 asset absent, 1 error (API unreachable after retries)
#   rel_put FILE      -> uploads FILE as <basename>.new, then swaps it in (delete old + rename); 1 on failure
REL_TAG="${REL_TAG:-data-latest}"

retry() {
  local n=0
  until "$@"; do
    n=$((n + 1))
    [ "$n" -ge 6 ] && return 1
    echo "retry $n: $*" >&2
    sleep $((n * 15))
  done
}

_rel_assets() {  # id<TAB>name per line
  gh api "repos/$GH_REPO/releases/tags/$REL_TAG" --jq '.assets[] | select(.state == "uploaded") | "\(.id)\t\(.name)"'
}

rel_assets() {
  local out
  out=$(retry _rel_assets) || return 1
  printf '%s\n' "$out"
}

_asset_id() {  # list name
  printf '%s\n' "$1" | awk -F'\t' -v n="$2" '$2 == n {print $1; exit}'
}

rel_get() {
  local name="$1" out="$2" list pick tmpd
  list=$(rel_assets) || { echo "release listing failed" >&2; return 1; }
  if [ -n "$(_asset_id "$list" "$name")" ]; then pick="$name"
  elif [ -n "$(_asset_id "$list" "$name.new")" ]; then pick="$name.new"; echo "using interrupted upload $pick" >&2
  else return 2
  fi
  tmpd=$(mktemp -d)
  if ! retry gh release download "$REL_TAG" -p "$pick" -D "$tmpd" --clobber; then rm -rf "$tmpd"; return 1; fi
  mv "$tmpd/$pick" "$out" && rm -rf "$tmpd"
}

_rel_del() {  # a 5xx DELETE may still have gone through: success when the asset is gone
  gh api -X DELETE "repos/$GH_REPO/releases/assets/$1" >/dev/null 2>&1 && return 0
  local l; l=$(_rel_assets) || return 1
  ! printf '%s\n' "$l" | awk -F'\t' -v i="$1" '$1 == i {f=1} END {exit !f}'
}

rel_put() {
  local f="$1" name tmpd list old new
  name=$(basename "$f")
  tmpd=$(mktemp -d)
  cp "$f" "$tmpd/$name.new"
  retry gh release upload "$REL_TAG" "$tmpd/$name.new" --clobber || { rm -rf "$tmpd"; return 1; }
  rm -rf "$tmpd"
  list=$(rel_assets) || return 1
  new=$(_asset_id "$list" "$name.new")
  old=$(_asset_id "$list" "$name")
  [ -n "$new" ] || { echo "uploaded $name.new not listed" >&2; return 1; }
  if [ -n "$old" ]; then retry _rel_del "$old" || return 1; fi
  retry gh api -X PATCH "repos/$GH_REPO/releases/assets/$new" -f name="$name" >/dev/null || return 1
  echo "uploaded $name"
}
