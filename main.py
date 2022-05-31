#!/usr/bin/python3
# -*- coding: utf-8 -*-

# build-in modules:
from os import getenv
from pathlib import Path
from hashlib import sha256, md5, blake2b
from pkginfo import UnpackedSDist
from json import loads
import re

# pip modules:
from twine.commands.upload import upload
from twine.commands.check import check
from twine.settings import Settings
from twine.cli import configure_output
from rich.traceback import install
from rich.console import Console
from rich import print
from github import Github
from github.GithubException import UnknownObjectException
from urllib3 import PoolManager


def fix_repository_url(repository_url: str) -> str:
    if repository_url is None or repository_url.startswith("https://upload.pypi.org/"):
        return "https://pypi.org/"
    elif repository_url.startswith("https://test.pypi.org/"):
        return "https://test.pypi.org/"
    else:
        return repository_url


class FailedToGetVersion(Exception):
    pass


def get_latest_version(package: str, repository_url: str) -> str:
    repository_url = fix_repository_url(repository_url)
    pool_manager = PoolManager()
    response = pool_manager.request(
        "GET",
        f"{repository_url}pypi/{package}/json"
    )

    if response.status == 200:
        js = loads(response.data.decode('utf-8'))
        version = js.get("info").get("version")
        return version
    else:
        raise FailedToGetVersion(response.status)


def pep440_is_prerelease(version: str) -> bool:
    # https://github.com/pypa/warehouse/blob/main/warehouse/migrations/versions/e7b09b5c089d_add_pep440_is_prerelease.py#L28-L35
    # https://peps.python.org/pep-0440/
    """
    CREATE FUNCTION pep440_is_prerelease(text) returns boolean as $$
            SELECT lower($1) ~* '(a|b|rc|dev|alpha|beta|c|pre|preview)'
        $$
        LANGUAGE SQL
        IMMUTABLE
        RETURNS NULL ON NULL INPUT;
    """
    return bool(re.search(r'(a|b|rc|dev|alpha|beta|c|pre|preview)', version, re.I))


def get_package_info(dist_dir: Path) -> tuple:
    """
    Returns: tuple: (name, version)
    """
    egg_info = None

    for file in dist_dir.parent.resolve().absolute().iterdir():
        if file.name.endswith(".egg-info"):
            egg_info = file

    if egg_info is None:
        print("[red]egg-info not found.")
        exit(1)

    pkg = UnpackedSDist(egg_info)
    return pkg.name, pkg.version


def get_release_url(package_name: str, package_version: str, repository_url: str = None) -> str:
    repository_url = fix_repository_url(repository_url)
    return f"{repository_url}project/{package_name}/{package_version}/"


def gen_hashes(files: Path) -> dict:
    """
    hashes = {
        "file_1.txt": {
            "sha256": "...",
            "md5": "...",
            "blake2_256": "..."
        }
    }
    """

    hashes = {}

    for file_object in files.iterdir():
        file_content = file_object.read_bytes()
        hashes[file_object.name] = {
            "SHA256": sha256(file_content).hexdigest(),
            "MD5": md5(file_content).hexdigest(),
            "BLAKE2-256": blake2b(file_content, digest_size=32).hexdigest()
        }

    return hashes


def print_hashes(hashes: dict) -> None:
    for file_name, file_hashes in hashes.items():
        print(f"[green]{file_name}:[magenta]")
        print(f"    [green]SHA256: \t[magenta]{file_hashes['SHA256']}")
        print(f"    [green]MD5: \t[magenta]{file_hashes['MD5']}")
        print(f"    [green]BLAKE2-256: [magenta]{file_hashes['BLAKE2-256']}")


def create_SUM_files(hashes: dict) -> list:
    hash_types = ["SHA256", "MD5", "BLAKE2-256"]

    for hash_type in hash_types:
        with open(f"{hash_type}-SUMS.txt", "w") as f:
            for file_name, file_hashes in hashes.items():
                f.write(f"{file_hashes[hash_type]} {file_name}\n")

    return [Path(f"{hash_type}-SUMS.txt").resolve().absolute().as_posix() for hash_type in hash_types]


class PyPIPublish(object):
    def __init__(self):
        # rich init:
        # force_terminal to Enable color.
        self.console = Console(force_terminal=True)
        install(console=self.console)  # Install rich traceback.
        configure_output()
        """
        Running configure_output to reconfigure the rich console.
        This also forces the console to use color.
        Optional this can be done by: rich.reconfigure(force_terminal=True)
        """

        # Get needed env variables:
        # Github:
        self.github_api_url = getenv("GITHUB_API_URL")
        self.github_repository = getenv("GITHUB_REPOSITORY")
        self.github_server_url = getenv("GITHUB_SERVER_URL")

        self.latest_commit_sha = getenv("GITHUB_SHA")

        self.github_token = getenv("INPUT_GITHUB_TOKEN")

        # PyPI:
        self.pypi_password = getenv("INPUT_PASSWORD")
        self.pypi_user = getenv("INPUT_USER")
        self.pypi_repository = getenv("INPUT_REPOSITORY") if len(
            getenv("INPUT_REPOSITORY")) > 0 else None

        # Other:
        self.verify_metadata = \
            False if getenv("INPUT_VERIFY_METADATA") == "false" else True
        self.print_hash = \
            False if getenv("INPUT_PRINT_HASH") == "false" else True
        self.verbose = \
            False if getenv("INPUT_VERBOSE") == "false" else True
        self.add_hash = \
            False if getenv("INPUT_ADD_HASH") == "false" else True
        self.releases_message = getenv("INPUT_RELEASES_MESSAGE")

        # Version Prefix and Suffix:
        self.prefix = getenv("INPUT_PREFIX")
        self.suffix = getenv("INPUT_SUFFIX")

        # get dist:
        self.dist_dir = Path(getenv("INPUT_DIST_PATH")).resolve().absolute()
        self.dists = [str(package) for package in self.dist_dir.iterdir()]

        # get package info:
        self.package_name, self.package_version = get_package_info(
            self.dist_dir
        )

        # set tag/release name:
        self.version_tag = f"{self.prefix}{self.package_version}{self.suffix}"

        # None variables:
        self.hashes = None

    def get_hashes(self) -> dict:
        if self.hashes is None:
            print("[cyan]Generating hashes...")
            self.hashes = gen_hashes(self.dist_dir)
        return self.hashes

    def tag_and_release(self):
        print()
        print("[cyan]Connecting to GitHub...")
        gh = Github(
            base_url=self.github_api_url,
            login_or_token=self.github_token
        )
        repository = gh.get_repo(self.github_repository)

        # setup release message:
        try:
            release = repository.get_latest_release()
            changelog_url = f"{self.github_server_url}/{self.github_repository}/compare/{release.tag_name}...{self.version_tag}"
        except UnknownObjectException:
            changelog_url = f"{self.github_server_url}/{self.github_repository}/commits/{self.version_tag}"
        message = self.releases_message.format(
            release_url=get_release_url(
                self.package_name, self.package_version, self.pypi_repository
            ),
            changelog_url=changelog_url,
            package_name=self.package_name,
            package_version=self.package_version,
            prefix=self.prefix,
            suffix=self.suffix,
            tag_name=self.version_tag,
        )

        print(
            f"[cyan]Creating git tag ([green]{self.version_tag}[cyan])..."
        )
        repository.create_git_tag(
            self.version_tag,
            "",
            object=self.latest_commit_sha,
            type="commit"
        )

        # repository.create_git_ref("refs/tags/"+tag.tag, tag.sha) # make the tag visible on the repository.
        print(
            f"[cyan]Creating git release ([green]{self.version_tag}[cyan])..."
        )
        release = repository.create_git_release(
            self.version_tag,
            self.version_tag,
            message,
            prerelease=pep440_is_prerelease(self.package_version)
        )

        print("[cyan]Uploading dists to release:")
        for dist in self.dists:
            release.upload_asset(dist)
            print(f"    [green]Uploaded: [magenta]{dist}")

        if self.add_hash:
            print()
            hashes = self.get_hashes()
            print("[cyan]Creating SUM files...")
            SUMS_files = create_SUM_files(hashes)

            print("[cyan]Uploading SUM files:")
            for file in SUMS_files:
                release.upload_asset(file)
                print(f"    [green]Uploaded: [magenta]{file}")

    def main(self):
        try:
            latest_version = get_latest_version(
                self.package_name,
                self.pypi_repository
            )
        except FailedToGetVersion:
            print("[red]Failed to get latest version from PyPI.")
            exit(1)

        if latest_version == self.package_version:
            print(
                f"[yellow]Version {self.package_version} is already published.")
            exit()

        settings = Settings(
            repository_url=self.pypi_repository,
            username=self.pypi_user,
            password=self.pypi_password,
            verbose=self.verbose
        )

        if self.verify_metadata:
            print("[cyan]Verifying dists metadata...")
            check(self.dists)
            print()

        if self.print_hash:
            hashes = self.get_hashes()
            print("[cyan]Displaying hashes:")
            print_hashes(hashes)
            print()

        print("[cyan]Uploading dists to PyPI...")
        upload(settings, self.dists)

        # Github Tag and Release:
        self.tag_and_release()


def main():
    PyPIPublish().main()


if __name__ == "__main__":
    main()
