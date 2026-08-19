#!/bin/bash
set -e

export VENDOR="$(pwd)/vendor"
echo "[+] Vendor path: $VENDOR"

# pip stores each dependency's LICENSE/COPYING/NOTICE file inside its
# "<pkg>-<version>.dist-info" folder, not inside the importable package
# directory. Deleting "*dist-info" (below) therefore silently strips the
# license/attribution notice for every vendored dependency (this includes
# certifi, which is MPL-2.0 and requires such notices not be stripped).
# Copy those notices into the package directory itself before cleanup so
# they survive. A bare license file sitting in a normal package directory
# (not a "*.dist-info"-suffixed folder) is invisible to
# importlib.metadata/pkg_resources, so this adds no packaging-metadata
# collision risk for the shared-runner composite action.
preserve_dist_info_licenses() {
    echo "[+] Preserve license notices before stripping dist-info"
    for dist_info in "$VENDOR"/*.dist-info; do
        [ -d "$dist_info" ] || continue

        if [ -f "$dist_info/top_level.txt" ]; then
            # Authoritative mapping shipped by pip/wheel. A single
            # distribution can install more than one top-level package
            # (e.g. PyYAML installs both `yaml` and `_yaml`).
            packages=$(cat "$dist_info/top_level.txt")
        else
            # Fall back to deriving the package name from the dist-info
            # folder name, e.g. "charset_normalizer-3.4.2.dist-info" ->
            # "charset_normalizer".
            name=$(basename "$dist_info" .dist-info | sed -E 's/-[0-9].*$//')
            name_lc=$(echo "$name" | tr '[:upper:]' '[:lower:]')
            case "$name_lc" in
                pyyaml) packages="yaml _yaml" ;;
                *) packages="$name" ;;
            esac
        fi

        for pkg in $packages; do
            [ -d "$VENDOR/$pkg" ] || continue
            # Modern wheels (PEP 639) commonly nest license files under a
            # "licenses/" subfolder (e.g. "<dist-info>/licenses/LICENSE")
            # instead of directly inside the dist-info folder, so search
            # the whole dist-info tree rather than just its top level.
            find "$dist_info" -type f \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) -print0 |
                while IFS= read -r -d '' notice; do
                    dest_name=$(basename "$notice")
                    # Some upstream projects (e.g. idna) name their license
                    # file "LICENSE.md". It's plain legal text, not
                    # documentation, but the ".md" extension would make
                    # repo-wide markdown linters try to parse it as one and
                    # fail (e.g. MD041 first-line-heading). Strip it.
                    case "$dest_name" in
                        *.md) dest_name="${dest_name%.md}" ;;
                    esac
                    cp "$notice" "$VENDOR/$pkg/$dest_name"
                done
        done
    done
}

echo "[+] Delete all folders in vendor"
# NOTE: the glob must stay outside the quotes so the shell expands it to each
# top-level directory; quoting it (e.g. "$VENDOR/*/") makes rm look for a
# literal path named "*" and silently deletes nothing, leaving stale/removed
# packages behind on every run. Only directories are matched (trailing "/"),
# so vendor/README.md and vendor/update.sh itself are left alone.
rm -rf "$VENDOR"/*/

if [ -f $PWD/Pipfile ]; then
    echo "[+] Install all dependencies (pipenv)"
    
    # pipenv clean
    # pipenv install --deploy
    pipenv requirements > "$VENDOR/requirements.txt"
    pip install -r "$VENDOR/requirements.txt" --target=$VENDOR --upgrade

    preserve_dist_info_licenses

    echo "[+] Clean up vendor folder"
    rm -rf $VENDOR/*dist-info && \
        rm -rf $VENDOR/requirements.txt

elif [ -f $PWD/requirements.txt ]; then
    echo "[+] Install all dependencies (pip -> requirements)"
    pip install -r $PWD/requirements.txt --target=$VENDOR --upgrade

    preserve_dist_info_licenses

    echo "[+] Clean up vendor folder"
    rm -rf $VENDOR/*dist-info && \
        rm -rf $VENDOR/requirements.txt

else 
    echo "[!] Unsupported Python installer, please update the 'vendor/update.sh' script"
    exit 1
fi

# Remove changes to the semantic_version package
git restore ./vendor/semantic_version/__init__.py

echo "[+] Completed vendor update"
