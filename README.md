# Brewutils

Brewutils is a library around Brew and a CLI `brew-utils-cli` with focus (not only)
on obtaining information about downstream patches obtained about the artifact

## Contributing

See our [contributing guidelines](https://github.com/fabric8-analytics/common/blob/master/CONTRIBUTING.md) for more info.

### Usage

```
$ brew-utils-cli -v/--version <ver> [-d/--digest <digest>] NAMES...
```

Version is a mandatory argument, digest is optional.

### Configuration

Two environmental variables can be used to change Brew URL's:

```
export BREWHUB_URL='https://koji.fedoraproject.org/kojihub'
export BREWPATH_URL='https://kojipkgs.fedoraproject.org'
```
