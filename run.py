###
# NOTICE: This computer software was prepared by National Technology &
# Engineering Solutions of Sandia, LLC, hereinafter the Contractor, under
# Contract DE-NA0003525 with the Department of Energy/National Nuclear Security
# Administration (DOE/NNSA). All rights in the computer software are reserved
# by DOE/NNSA on behalf of the United States Government and the Contractor as
# provided in the Contract. You are authorized to use this computer software
# for Governmental purposes but it is not to be released or distributed to the
# public.
#
# NEITHER THE GOVERNMENT NOR THE CONTRACTOR MAKES ANY WARRANTY, EXPRESS OR
# IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE. This notice
# including this sentence must appear on any copies of this computer software.

# Script to perform analysis across multiple versions of Ghidra.
import json
import logging
import os
import re
import subprocess
import packaging.version

from collections import namedtuple

import click
import requests
import tqdm

logging.basicConfig(level=logging.ERROR)

# TODO: when there are more than 100 releases, we'll need to walk the pages.
RELEASES_URL = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases?per_page=100"

PROJECT_NAME = "default"

# Named tuple for a Ghidra release containing all the information that we need
GhidraRelease = namedtuple("GhidraRelease", ["name", "version", "url", "sha256"])

# From ChangeHistory, Ghidra started to require JDK 17 at version 10.2
JDK17_CUTOFF = packaging.version.parse("10.2")

# From ChangeHistory, Ghidra started to require JDK 21 at version 11.2
JDK21_CUTOFF = packaging.version.parse("11.2")

version_option = click.option(
    "--version", default="",
    help="Comma-separated list of version expressions. "
         "Each expression should provide an operator and a version. "
         "If an operator is not provide, equality ('==') is assumed. "
         "Valid operators include '==', '!=', '<', '<=', '>', '>='. "
         "Multiple version expressions are AND'd together. "
         "For example, '>10.0,<11.0' would match versions between 10 and 11.")

dry_run_option = click.option(
    "--dry-run", default=False, is_flag=True,
    help="print commands instead of running them")

def parse_releases(data):
    """
    Generator to extract releases from data
    """
    for release in data:
        # Get the first asset's download URL
        for asset in release["assets"]:
            download_url = asset["browser_download_url"]
            if "ghidra" in asset["name"] and "PUBLIC" in asset["name"]:
                break
        else:
            logging.error("no release found in assets for release %s, skipping", release["name"])
            continue

        # Extract the sha256 from the description
        match = re.search(r"SHA-256: `([a-f0-9]{64})`", release["body"])
        if not match:
            logging.error("no sha256 for release: %s, skipping", release["name"])
            continue
        else:
            sha256 = match.group(1)

        yield GhidraRelease(
            release["name"],
            packaging.version.parse(release["name"].split(" ")[1]),
            download_url,
            sha256)


def get_releases_offline(fname):
    """
    Use an offline cached version of releases
    """
    logging.info("reading releases from offline: %s", fname)
    with open(fname, "r") as f:
        return parse_releases(json.load(f))


def get_releases_online():
    """
    Download a list of the released versions from the Github API
    """
    logging.info("reading releases from URL: %s", RELEASES_URL)
    response = requests.get(RELEASES_URL)
    return parse_releases(response.json())


# default is online
get_releases = get_releases_online


def build_release(release, dry_run):
    """
    Build a docker container for a specific Ghidra release
    """
    cmd = [
        "docker",
        "build",
        "-f",
        "Dockerfile",
        "--build-arg",
        f"GHIDRA_VERSION={release.version}",
        "--build-arg",
        f"GHIDRA_URL={release.url}",
        "--build-arg",
        f"GHIDRA_SHA={release.sha256}",
        "-t",
        f"ghidra:{release.version}",
    ]

    if release.version >= JDK21_CUTOFF:
        cmd.extend([
            "--build-arg",
            f"BASE_IMAGE=eclipse-temurin:21-jdk",
        ])
    elif release.version >= JDK17_CUTOFF:
        cmd.extend([
            "--build-arg",
            f"BASE_IMAGE=eclipse-temurin:17-jdk",
        ])

    cmd.append(".")

    logging.info("build_release: %s", cmd)

    if dry_run:
        return

    with open("build_release.log", "a") as f:
        subprocess.call(cmd, stderr=f)


def push_release(release, registry, dry_run):
    """
    Retag the container built for a specific release for a given registry and
    push it.
    """
    cmd = [
        "docker",
        "tag",
        f"ghidra:{release.version}",
        f"{registry}:{release.version}",
    ]

    logging.info("push_release: %s", cmd)

    if not dry_run:
        with open("push_release.log", "a") as f:
            subprocess.call(cmd, stderr=f)

    cmd = [
        "docker",
        "push",
        f"{registry}:{release.version}",
    ]

    logging.info("push_release: %s", cmd)

    if not dry_run:
        with open("push_release.log", "a") as f:
            subprocess.call(cmd, stderr=f)


def pull_release(release, registry, dry_run):
    """
    Pull from registry and retag it to use locally.
    """
    cmd = [
        "docker",
        "pull",
        f"{registry}:{release.version}",
    ]

    logging.info("pull_release: %s", cmd)

    if not dry_run:
        with open("pull_release.log", "a") as f:
            subprocess.call(cmd, stderr=f)

    cmd = [
        "docker",
        "tag",
        f"{registry}:{release.version}",
        f"ghidra:{release.version}",
    ]

    logging.info("pull_release: %s", cmd)

    if not dry_run:
        with open("pull_release.log", "a") as f:
            subprocess.call(cmd, stderr=f)


def save_release(release, path, dry_run):
    """
    Use docker save to export a release.
    """
    tag = f"ghidra:{release.version}"
    cmd = [
        "docker",
        "save",
        "-o",
        os.path.join(path, tag + ".tar"),
        tag,
    ]

    logging.info("save_release: %s", cmd)

    if dry_run:
        return

    with open("save_release.log", "a") as f:
        subprocess.call(cmd, stderr=f)


def load_release(release, path, dry_run):
    """
    Use docker load to import a release.
    """
    cmd = [
        "docker",
        "load",
        "-i",
        os.path.join(path, f"ghidra:{release.version}.tar"),
    ]

    logging.info("load_release: %s", cmd)

    if dry_run:
        return

    with open("load_release.log", "a") as f:
        subprocess.call(cmd, stderr=f)

def do_import_file(release, input_file, output_dir, timeout, dry_run):
    """
    Import a file into Ghidra and create a project file for the input file.
    """
    # add release version to the path so that we get results for each release
    output_dir = os.path.join(output_dir, str(release.version))

    # make paths absolute
    input_file = os.path.abspath(input_file)
    output_dir = os.path.abspath(output_dir)

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{os.path.dirname(input_file)}:/input:ro",
        "-v",
        f"{output_dir}:/output",
        f"ghidra:{release.version}",
        "/output/",
        PROJECT_NAME,
        "-analysisTimeoutPerFile",
        f"{timeout}",
        "-import",
        f"/input/{os.path.basename(input_file)}"
    ]

    logging.info("import_file: %s", cmd)

    if dry_run:
        return

    os.makedirs(output_dir)

    with open(f"{output_dir}/ghidra-import.out", "w") as out:
        with open(f"{output_dir}/ghidra-import.err", "w") as err:
            subprocess.call(cmd, stdout=out, stderr=err)


def do_run_script(release, script_dir, input_dir, script_args, dry_run):
    """
    Run a script on a particular release, mapping in script_dir to
    /app/ghidra_scripts, and input_dir to /input. Expects the input_dir was
    previously the output directory of import_file.
    """
    # add release version to the path so that we get results for each release
    input_dir = os.path.join(input_dir, str(release.version))

    project_path = os.path.join(input_dir, f"{PROJECT_NAME}.rep")
    if not os.path.exists(project_path):
        logging.error("run_script: project does not exist, cannot run script. path: %s", project_path)
        return

    # make paths absolute
    script_dir = os.path.abspath(script_dir)
    input_dir = os.path.abspath(input_dir)

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{script_dir}:/app/ghidra_scripts:ro",
        "-v",
        f"{input_dir}:/input",
        f"ghidra:{release.version}",
        "/input/",
        PROJECT_NAME,
        "-process",
        "-scriptPath",
        "/app/ghidra_scripts/",
        "-postScript"
    ]

    cmd.extend(script_args)

    logging.info("run_script: %s", cmd)

    if dry_run:
        return

    with open(f"{input_dir}/ghidra-{script_args[0]}.out", "w") as out:
        with open(f"{input_dir}/ghidra-{script_args[0]}.err", "w") as err:
            subprocess.call(cmd, stdout=out, stderr=err)


def compile_version_filter(expression):
    operator = ""
    operator_chars = set("<>!=")
    for c in expression:
        if c in operator_chars:
            operator += c
        else:
            break

    expression = expression[len(operator):]

    comparison_version = packaging.version.parse(expression)

    if operator == "==" or operator == "":
        return lambda v: v == comparison_version
    elif operator == "!=":
        return lambda v: v != comparison_version
    elif operator == "<":
        return lambda v: v < comparison_version
    elif operator == "<=":
        return lambda v: v <= comparison_version
    elif operator == ">":
        return lambda v: v > comparison_version
    elif operator == ">=":
        return lambda v: v >= comparison_version
    else:
        raise ValueError("Invalid comparison operator")


def apply_fn(fn, version_expr):
    """
    apply_fn calls fn on a particular version or runs it across all versions,
    depending on if version is None.
    """
    filters = []
    if version_expr:
        filters = [compile_version_filter(v.strip()) for v in version_expr.split(",")]

    releases = get_releases()
    if filters:
        filtered = []
        for release in releases:
            for f in filters:
                if not f(release.version):
                    break
            else:
                # did not break => passed all filters
                filtered.append(release)

        if len(filtered) == 0:
            logging.error("unable to find releases matching version expression: %s", version_expr)
            return

        releases = filtered

    for release in tqdm.tqdm(releases):
        fn(release)


@click.group()
@click.option(
    "-v", "--verbose", default=False, count=True,
    help="increase logging verbosity")

@click.option(
    "--offline", default=None,
    help="read releases from provided file instead of querying them")
def cli(verbose, offline):
    global get_releases

    if verbose == 1:
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
    elif verbose > 1:
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

    if offline:
        def fn():
            return get_releases_offline(offline)
        get_releases = fn


@cli.command()
def list_releases():
    for release in get_releases():
        print(release.version)


@cli.command()
@version_option
@dry_run_option
def build_releases(version, dry_run):
    def wrapped(release):
        return build_release(release, dry_run)

    apply_fn(wrapped, version)


@cli.command()
@click.argument("registry")
@version_option
@dry_run_option
def push_releases(registry, version, dry_run):
    def wrapped(release):
        return push_release(release, registry, dry_run)

    apply_fn(wrapped, version)


@cli.command()
@click.argument('registry')
@version_option
@dry_run_option
def pull_releases(registry, version, dry_run):
    def wrapped(release):
        return pull_release(release, registry, dry_run)

    apply_fn(wrapped, version)


@cli.command()
@click.argument('path')
@version_option
@dry_run_option
def save_releases(path, version, dry_run):
    def wrapped(release):
        return save_release(release, path, dry_run)

    apply_fn(wrapped, version)


@cli.command()
@click.argument('path')
@version_option
@dry_run_option
def load_releases(path, version, dry_run):
    def wrapped(release):
        return load_release(release, path, dry_run)

    apply_fn(wrapped, version)


@cli.command()
@version_option
@dry_run_option
@click.option('--timeout', default=20*60, help="timeout in seconds", type=int)
@click.argument('input-file')
@click.argument('output-dir')
def import_file(version, dry_run, timeout, input_file, output_dir):
    def wrapped(release):
        return do_import_file(release, input_file, output_dir, timeout, dry_run)

    apply_fn(wrapped, version)


@cli.command()
@version_option
@dry_run_option
@click.argument('script-dir')
@click.argument('input-dir')
@click.argument('script-args', nargs=-1)
def run_script(version, dry_run, script_dir, input_dir, script_args):
    if not script_args:
        raise click.UsageError("at least one script_arg is required for name of script")

    def wrapped(release):
        return do_run_script(release, script_dir, input_dir, script_args, dry_run)

    apply_fn(wrapped, version)


def main():
    cli()


if __name__ == "__main__":
    main()
