# Brewutils

Brewutils is a library around Brew and a CLI `brew-utils-cli` with focus (not only)
on obtaining information about downstream patches obtained about the artifact

### Usage

```
$ brew-utils-cli -v/--version <ver> [-d/--digest <digest>] NAMES...
```

Version is a mandatory argument, digest is optional.

### Configuration

Two environmental variables can be used to change Brew URL's:

```
export BREWHUB_URL='http://brewhub.devel.redhat.com/brewhub'
export BREWPATH_URL='http://download.lab.bos.redhat.com/brewroot'
```
