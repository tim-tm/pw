[![build](https://github.com/tim-tm/pw/actions/workflows/build.yml/badge.svg)](https://github.com/tim-tm/pw/actions/workflows/build.yml)

# pw

pw is a really simple password manager.

## Setup

### Dependencies
- openssl
- glibc

### Building pw

Getting the source
```sh
git clone https://github.com/tim-tm/pw.git && cd pw
```

Setting up the build directory
```sh
make setup
```

Building pw
```sh
make
```

## Usage

```sh
./pw <options>
```

| Option | Description |
| ------ | ----------- |
| -g \<password length\> | Generate a password containing numbers, letters and special characters. |
| -c \<password\> | Check a password's stength. |
| -rs \<password\> \<old password\> | Set the root password. The old password doesn't need to be specified if no password is set. Consider choosing a strong password since the root password provides access to all other stored passwords. This action will destroy your cache file and therefore all your stored passwords. |

## Contribution

Feel free to open a pull request if you want to contribute to pw.

## License

pw is licensed under the [MIT License](https://github.com/tim-tm/pw/blob/main/LICENSE).
