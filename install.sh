#!/bin/sh
# Installs pbx, the Passbox command-line client, from the GitHub releases.
#
#   curl -fsSL https://raw.githubusercontent.com/passboxnet/cli/main/install.sh | sh
#
# Environment:
#   PBX_VERSION       version to install, e.g. 0.1.0 (default: the latest release)
#   PBX_INSTALL_DIR   where to put pbx (default: ~/.local/bin)
#
# The archive is checked against the release's SHA256SUMS before anything is
# installed. The script never asks for root; to install system-wide, run it
# as root yourself with PBX_INSTALL_DIR=/usr/local/bin.

set -eu

REPO="passboxnet/cli"

say() {
  printf '%s\n' "$*" >&2
}

fail() {
  say "error: $*"
  exit 1
}

has() {
  command -v "$1" > /dev/null 2>&1
}

# download URL FILE
download() {
  if has curl; then
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
  elif has wget; then
    wget --https-only -q -O "$2" "$1"
  else
    fail "curl or wget is required"
  fi
}

latest_version() {
  if has curl; then
    # The latest release redirects to .../releases/tag/v<version>.
    url=$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' \
      "https://github.com/$REPO/releases/latest") || return 1
  else
    url=$(wget --https-only -qO- "https://api.github.com/repos/$REPO/releases/latest" |
      sed -n 's/.*"html_url": *"\([^"]*\/releases\/tag\/[^"]*\)".*/\1/p' | head -n 1) || return 1
  fi
  case "$url" in
  */releases/tag/v*) printf '%s\n' "${url##*/tag/v}" ;;
  *) return 1 ;;
  esac
}

target() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$arch" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) fail "no pbx build for the $arch architecture; build it from source: cargo install --locked --git https://github.com/$REPO passbox-cli" ;;
  esac
  case "$os" in
  Darwin)
    # A shell running under Rosetta reports x86_64 on Apple silicon.
    if [ "$arch" = x86_64 ] && [ "$(sysctl -n hw.optional.arm64 2> /dev/null || true)" = 1 ]; then
      arch=aarch64
    fi
    printf '%s\n' "$arch-apple-darwin"
    ;;
  Linux) printf '%s\n' "$arch-unknown-linux-musl" ;;
  MINGW* | MSYS* | CYGWIN* | Windows_NT)
    fail "on Windows, use install.ps1: irm https://raw.githubusercontent.com/$REPO/main/install.ps1 | iex"
    ;;
  *) fail "no pbx build for $os; build it from source: cargo install --locked --git https://github.com/$REPO passbox-cli" ;;
  esac
}

sha256() {
  if has sha256sum; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif has shasum; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  elif has openssl; then
    openssl dgst -sha256 -r "$1" | cut -d ' ' -f 1
  else
    fail "sha256sum, shasum or openssl is required to verify the download"
  fi
}

main() {
  for tool in uname tar mktemp; do
    has "$tool" || fail "$tool is required"
  done

  target=$(target)
  version=${PBX_VERSION:-}
  version=${version#v}
  if [ -z "$version" ]; then
    version=$(latest_version) || fail "could not find the latest release of $REPO"
  fi
  install_dir=${PBX_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}

  name="pbx-$version-$target"
  base="https://github.com/$REPO/releases/download/v$version"

  tmp=$(mktemp -d 2> /dev/null || mktemp -d -t pbx)
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 1' HUP INT TERM

  say "Downloading pbx $version for $target"
  download "$base/$name.tar.gz" "$tmp/$name.tar.gz" ||
    fail "could not download $base/$name.tar.gz (does version $version exist?)"
  download "$base/SHA256SUMS" "$tmp/SHA256SUMS" ||
    fail "could not download $base/SHA256SUMS"

  expected=$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
  [ -n "$expected" ] || fail "$name.tar.gz is not listed in SHA256SUMS"
  actual=$(sha256 "$tmp/$name.tar.gz")
  if [ "$actual" != "$expected" ]; then
    fail "checksum mismatch for $name.tar.gz (expected $expected, got $actual); nothing was installed"
  fi
  say "Checksum verified"

  tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
  [ -f "$tmp/$name/pbx" ] || fail "the archive does not contain pbx"

  mkdir -p "$install_dir" 2> /dev/null ||
    fail "cannot create $install_dir; choose another directory with PBX_INSTALL_DIR"
  [ -w "$install_dir" ] ||
    fail "$install_dir is not writable; choose another directory with PBX_INSTALL_DIR, or run this script as a user who can write there"
  # Copy next to the target and rename, so a running pbx is never half-written.
  cp "$tmp/$name/pbx" "$install_dir/.pbx.$$"
  chmod 755 "$install_dir/.pbx.$$"
  mv -f "$install_dir/.pbx.$$" "$install_dir/pbx"

  say "Installed $("$install_dir/pbx" --version) to $install_dir/pbx"

  case ":${PATH:-}:" in
  *":$install_dir:"*) ;;
  *)
    say ""
    say "$install_dir is not on your PATH. Add it, for example:"
    case "${SHELL:-}" in
    */zsh) say "  echo 'export PATH=\"$install_dir:\$PATH\"' >> ~/.zshrc" ;;
    */fish) say "  fish_add_path $install_dir" ;;
    *) say "  echo 'export PATH=\"$install_dir:\$PATH\"' >> ~/.profile" ;;
    esac
    say "Then open a new terminal."
    ;;
  esac
}

main "$@"
