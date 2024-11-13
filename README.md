# chfs-zpoline
[CHFS](https://github.com/otatebe/chfs)をPOSIXで使えるようにするライブラリ

## Dependency
- CHFS
- binutils(zpoline uses libopcodes)
## Build
   CHFSを手動で入れたなら、pkg-configにCHFSの場所を教えてやる必要がある
   ```
   export PKG_CONFIG_PATH=[CHFSをインストールしたディレクトリ]/lib/pkgconfig:$PKG_CONFIG_PATH
   ```

   ```
   autoreconf --install
   ./configure  --prefix=[PREFIX]
   make
   make install
   ```

## Setup
```
sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"
```

## Use
```
$ LIBZPHOOK={chfs-zpoline-path}/.libs/libcz.so LD_PRELOAD={chfs-zpoline-path}/zpoline/libzpoline.so [program such as ior]
```
