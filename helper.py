#!/usr/bin/env python3

import argparse
import os
import re
import shutil
import subprocess
import sys
import tarfile
from hashlib import sha256
from os.path import basename
from typing import Optional
from urllib.request import urlopen

FMT_URL: str = "https://downloads.openwrt.org/snapshots/targets/%s/%s/%s"


def panic(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)
    sys.exit(1)


def get_ib_url(target: str, subtarget: str) -> str:
    return FMT_URL % (
        target,
        subtarget,
        f"openwrt-imagebuilder-{target}-{subtarget}.Linux-x86_64.tar.xz",
    )


def get_sha256sum_file_url(target: str, subtarget: str) -> str:
    return FMT_URL % (target, subtarget, "sha256sums")


def sha256sum(fname: str) -> str:
    with open(fname, "rb") as f:
        h = sha256()
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def get_ib_sha256(text: str) -> Optional[str]:
    try:
        return re.search(
            r"([0-9a-f]{64})\s+\*openwrt-imagebuilder-.*\.Linux-x86_64\.tar\.xz", text
        ).group(1)
    except AttributeError:
        return None


def download_and_chdir(target, sub_target):
    ib_url = get_ib_url(target, sub_target)
    sha256_url = get_sha256sum_file_url(target, sub_target)

    # download the sha256sum file
    new_sha256_data = b""
    with urlopen(sha256_url) as f, open(
        f"{target}_{sub_target}-sha256.new", "wb"
    ) as f2:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            f2.write(chunk)
            new_sha256_data += chunk
    new_sha256_data = new_sha256_data.decode("utf-8")

    # copy old sha256sum data if exists
    old_sha256_data = ""
    try:
        with open(f"{target}_{sub_target}-sha256", "r") as f:
            old_sha256_data = f.read()
    except FileNotFoundError:
        pass

    if (
        not os.path.exists(f"{target}_{sub_target}-sha256")
        or not os.path.exists(basename(ib_url)[: -len(".tar.xz")])
        or get_ib_sha256(new_sha256_data) != get_ib_sha256(old_sha256_data)
    ):
        print("old configs were removed, image builder is getting updated...")

        if os.path.exists(f"{target}_{sub_target}-sha256"):
            os.remove(f"{target}_{sub_target}-sha256")
        os.rename(f"{target}_{sub_target}-sha256.new", f"{target}_{sub_target}-sha256")

        if os.path.exists(basename(ib_url)[: -len(".tar.xz")]):
            shutil.rmtree(basename(ib_url)[: -len(".tar.xz")])

        # download the file
        with urlopen(ib_url) as f, open(basename(ib_url), "wb") as f2:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                f2.write(chunk)

        # check the sha256sum
        hash = sha256sum(basename(ib_url))
        sha256_valid = False
        with open(f"{target}_{sub_target}-sha256", "r") as f:
            for line in f.readlines():
                line = line.strip()
                if line.endswith(basename(ib_url)):
                    if line.split()[0].lower() == hash.lower():
                        sha256_valid = True
        if not sha256_valid:
            os.remove(basename(ib_url))
            panic("sha256sum is not valid")

        # extract the file
        with tarfile.open(basename(ib_url)) as f:
            f.extractall()

        # remove the downloaded file
        os.remove(basename(ib_url))

        # show success message
        print("image builder is updated")
    else:
        os.remove(f"{target}_{sub_target}-sha256.new")
        print("IB sha256sum is up to date")

    # chdir to the extracted dir
    os.chdir(basename(ib_url)[: -len(".tar.xz")])


def generate_packages_list(profile: str, packages: str) -> str:
    info_run = subprocess.run(["make", "info"], text=True, capture_output=True)
    # Some packages like libubus have a date suffix, so we remove it
    # to avoid errors in case it was updated in new SNAPSHOT builds.
    # This is what ASU and luci-app-attendedsysupgrade also do.
    packages = list(packages.split()) if packages else list()
    for i in range(len(packages)):
        packages[i] = re.sub(r"\d{4}\d{2}\d{2}$", "", packages[i])
    packages = set(packages)

    default_packages = set(
        re.search(r"Default Packages: (.*)\n", info_run.stdout).group(1).split()
    )
    profile_packages = set(
        re.search(
            rf"{profile}:\n    .+\n    Packages: (.*?)\n",
            info_run.stdout,
            re.MULTILINE,
        )
        .group(1)
        .split()
    )

    # Taken from ASU's build.py
    remove_packages = (default_packages | profile_packages) - packages
    packages = packages | set(map(lambda p: f"-{p}", remove_packages))
    return " ".join(sorted(packages))


def backup_original_config(fname: str) -> None:
    if not os.path.exists(fname + ".orig"):
        shutil.copy(fname, fname + ".orig")


def restore_original_config(fname: str) -> None:
    if os.path.exists(fname + ".orig"):
        shutil.copy(fname + ".orig", fname)


def open_editor(fname: str) -> None:
    editor = os.environ.get("EDITOR")
    editor = editor if editor else shutil.which("nano")
    if not editor:
        panic("no editor found")
    subprocess.run([editor, fname])


def asking_loop(question: str, default: str) -> str:
    if default == "y":
        question = question + " [Y/n] "
    elif default == "n":
        question = question + " [y/N] "
    else:
        raise ValueError("default must be y or n")

    while True:
        answer = input(question).lower()
        if answer == "":
            answer = default
        if answer == "y" or answer == "n":
            return answer
        print("please answer with y or n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target",
        required=True,
        help="specify the target in the form of target/subtarget",
    )
    parser.add_argument(
        "--profile",
        required=True,
        help="specify the profile, find list of profiles from `make info'",
    )
    parser.add_argument(
        "--packages", required=True, help="packages to include, separated by space"
    )
    parser.add_argument(
        "--files",
        required=False,
        type=str,
        default="",
        help="include extra files from <path>",
    )
    parser.add_argument(
        "--bin-dir",
        required=False,
        type=str,
        default="",
        help="alternative output directory for the images",
    )
    parser.add_argument(
        "--extra-image-name",
        required=False,
        type=str,
        default="",
        help="add this to the output image filename (sanitized)",
    )
    parser.add_argument(
        "--disabled-services",
        required=False,
        type=str,
        default="",
        help="which services in /etc/init.d/ should be disabled, separated by space",
    )
    parser.add_argument(
        "--add-local-key",
        required=False,
        type=bool,
        default=False,
        help="store locally generated signing key in built images",
    )
    parser.add_argument(
        "--no-ask",
        action="store_true",
        help="do not ask about modifying the config file (uses the default IB config)",
    )
    args = parser.parse_args()

    target, sub_target = args.target.split("/")

    download_and_chdir(target, sub_target)
    backup_original_config(".config")

    if (
        not args.no_ask
        and os.path.exists(".config.orig")
        and sha256sum(".config") != sha256sum(".config.orig")
        and asking_loop("would you like to restore the original config file?", "n")
        == "y"
    ):
        restore_original_config(".config")

    if (
        not args.no_ask
        and asking_loop("would you like to edit the config file?", "n") == "y"
    ):
        open_editor(".config")

    packages = generate_packages_list(args.profile, args.packages)
    build_cmd = ["make", "image", f"PACKAGES={packages}", f"PROFILE={args.profile}"]
    if args.files:
        build_cmd.append(f"FILES={args.files}")
    if args.bin_dir:
        build_cmd.append(f"BIN_DIR={args.bin_dir}")
    if args.extra_image_name:
        build_cmd.append(f"EXTRA_IMAGE_NAME={args.extra_image_name}")
    if args.disabled_services:
        build_cmd.append(f"DISABLED_SERVICES={args.disabled_services}")
    if args.add_local_key:
        build_cmd.append("ADD_LOCAL_KEY=1")
    subprocess.run(build_cmd)


if __name__ == "__main__":
    main()
