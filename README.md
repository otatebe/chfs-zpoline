# chfs-zpoline

Syscall interception library for [CHFS](https://github.com/otatebe/chfs) using [zpoline](https://github.com/yasukata/zpoline) to enable POSIX access.

## Dependency

- CHFS
- binutils (zpoline uses libopcodes)

## How to build

   PKG_CONFIG_PATH must be set if CHFS is installed in a non-standard location.
   ```
   export PKG_CONFIG_PATH=$CHFS_PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH
   ```

   ```
   autoreconf --install
   ./configure [ --prefix=PREFIX ]
   make
   make install
   ```

   Default PREFIX is /usr/local.

## Setup

```
sudo sysctl vm.mmap_min_addr=0
export LIBZPHOOK=$PREFIX/lib/libcz.so
export LIBZPDIRS="$PWD /data"
```

LIBZPDIRS specifies hooked directories.  If LIBZPDIRS is not specified, /chfs is considered to be a virtual mount directory.

## How to use

```
LD_PRELOAD=$PREFIX/lib/libzpoline.so program ...
```
