# Install Sandbar

Sandbar targets Linux amd64. Native acceptance uses Ubuntu 24.04.
Caddy must be installed separately. Sandbar uses no Go runtime after installation.

## Release installation

`markjeee/sandbar` remains private for review of `v0.1.0-beta.1`.
The commands below require the repository to become public.
Public download verification remains pending until that visibility change.

```sh
curl -fsSL https://github.com/markjeee/sandbar/releases/download/v0.1.0-beta.1/install.sh | sh
```

The versioned installer downloads the matching archive and checks its SHA-256 checksum before replacing `sandbar`.
The checksum comes from the same HTTPS release. It checks transfer integrity, not an independent signature.

The default destination is `~/.local/bin`. Select another directory with `--bin-dir`:

```sh
curl -fsSL https://github.com/markjeee/sandbar/releases/download/v0.1.0-beta.1/install.sh | sh -s -- --bin-dir "$HOME/bin"
```

Make sure the selected directory is in `PATH`, or use the full executable path.
The installer does not edit shell profiles, install Caddy, start services, or change certificate trust.

## Checkout installation

Use the Go version declared in `go.mod`. Run the installer from a checkout:

```sh
sh ./install.sh
sh ./install.sh --bin-dir "$HOME/bin"
"$HOME/bin/sandbar" --version
```

The checkout installer builds the current local source, including uncommitted changes.
It locates source beside the script, so invocation from another working directory also works.
The source executable reports `development` unless the source version was changed.
Both methods reject unsupported operating systems and architectures.

Downloads, checksums, and builds finish before the executable is replaced.
The final temporary file shares the destination directory, so replacement uses an atomic rename.
A failed download, checksum check, or build preserves the installed executable.
The installer removes its temporary files when it exits.

## Release preparation

From the checkout:

```sh
scripts/release
cd .sandbox/release/v0.1.0-beta.1
sha256sum -c SHA256SUMS
./sandbar_v0.1.0-beta.1_linux_amd64 --version
```

`scripts/release [output-directory]` prepares these assets without publishing:

- `sandbar_v0.1.0-beta.1_linux_amd64`, a static executable.
- `sandbar_v0.1.0-beta.1_linux_amd64.tar.gz`, containing `sandbar`, `LICENSE`, `install.sh`, and `RELEASE_NOTES.md`.
- `install.sh`, pinned to this release.
- `RELEASE_NOTES.md`.
- `SHA256SUMS`, covering the executable, archive, installer, and release notes.

Run `scripts/test-install` to test checkout builds and controlled release downloads.
Verify public URLs after publication and the repository visibility change.
