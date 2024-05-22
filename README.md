# pypi-publish

Automatically publish packages to PyPI and crete Tags and Releases

## Example workflow

**WARNING:** Do not enter any secrets in plain text! Add them as a env var in `settings/secrets/actions`.

You don't need to set `secrets.GITHUB_TOKEN` (its automatically set).

```yml
name: Publish

on:
  push:
    branches:
      - main

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout 🛎️
        uses: actions/checkout@v5

      - name: Set up Python 🧰
        uses: actions/setup-python@v5
        with:
          python-version: 3.x

      - name: Install dependencies 🧰
        env:
          PIP_ROOT_USER_ACTION: ignore
        run: |
          python -m pip install --upgrade pip
          pip install build

      - name: Build package 🔨
        run: python -m build

      - name: Publish package 🚀
        uses: Commandcracker/pypi-publish@v1
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input              | Description                                       | Required | Default                                                                            |
|--------------------|---------------------------------------------------|----------|------------------------------------------------------------------------------------|
| `user`             | `PyPI user`                                       | `false`  | `__token__`                                                                        |
| `password`         | `Password for the PyPI user or an access token`   | `true`   |                                                                                    |
| `repository`       | `The repository URL for PyPI`                     | `false`  | `https://pypi.python.org/pypi`                                                     |
| `verify_metadata`  | `Check distribution metadata before uploading`    | `false`  | `true`                                                                             |
| `verbose`          | `Show verbose output.`                            | `false`  | `false`                                                                            |
| `print_hash`       | `Show hash values of distribution to be uploaded` | `false`  | `true`                                                                             |
| `add_hash`         | `Add hash values to release assets`               | `false`  | `true`                                                                             |
| `github_token`     | `${{ secrets.GITHUB_TOKEN }}`                     | `true`   |                                                                                    |
| `prefix`           | `Prefix to add to the version tag`                | `false`  |                                                                                    |
| `suffix`           | `Suffix to add to the version tag`                | `false`  |                                                                                    |
| `releases_message` | `Message for the release`                         | `false`  | `**View releases at**: [PyPI]({release_url})\n**Full Changelog**: {changelog_url}` |

## Releases Message Variables

Set them like this: `{var_name}`

| Variable          | Description                                                 |
|-------------------|-------------------------------------------------------------|
| `release_url`     | `{repository_url}project/{package_name}/{package_version}/` |
| `changelog_url`   | `https://github.com/{github_repository}/compare/?...?`      |
| `package_name`    | `Your package name`                                         |
| `package_version` | `Your package version`                                      |
| `prefix`          | `same as the prefix input`                                  |
| `suffix`          | `same as the suffix input`                                  |
| `tag_name`        | `{prefix}{package_version}{suffix}`                         |
