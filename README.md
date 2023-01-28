# Helper script for IB usage

Currently supports SNAPSHOT only.

# Example usage

```
./helper.py --target x86/64 --profile generic --packages "$(ssh gw  opkg list-installed | awk '{print $1}' | sed -E 's/[0-9]{8}$//g')"
scp openwrt-imagebuilder-x86-64.Linux-x86_64/build_dir/target-x86_64_musl/linux-x86_64/tmp/openwrt-x86-64-generic-ext4-combined-efi.img.gz gw:/tmp
ssh gw sysupgrade /tmp/openwrt-x86-64-generic-ext4-combined-efi.img.gz
```

**NOTE:** `sed -E 's/[0-9]{8}$//g'` is required to remove the ISO date from the end of packages like libubus as an upgrade might
cause a change in that package name.
