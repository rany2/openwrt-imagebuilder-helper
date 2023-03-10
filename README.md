# Helper script for IB usage

Currently supports SNAPSHOT only. Automatically does exclusion of packages not requested (so if `ppp` was not requested,
the script will exclude it so it isn't reincluded by profile defaults).

It also automatically updates IB when an update is found.

# Options

```
usage: helper.py [-h] --target TARGET --profile PROFILE --packages PACKAGES [--files FILES] [--bin-dir BIN_DIR]
                 [--extra-image-name EXTRA_IMAGE_NAME] [--disabled-services DISABLED_SERVICES] [--add-local-key ADD_LOCAL_KEY] [--no-ask]

options:
  -h, --help            show this help message and exit
  --target TARGET       specify the target in the form of target/subtarget
  --profile PROFILE     specify the profile, find list of profiles from `make info'
  --packages PACKAGES   packages to include, separated by space
  --files FILES         include extra files from <path>
  --bin-dir BIN_DIR     alternative output directory for the images
  --extra-image-name EXTRA_IMAGE_NAME
                        add this to the output image filename (sanitized)
  --disabled-services DISABLED_SERVICES
                        which services in /etc/init.d/ should be disabled, separated by space
  --add-local-key ADD_LOCAL_KEY
                        store locally generated signing key in built images
  --no-ask              do not ask about modifying the config file (uses the default IB config)
```

# Example usage

```
$ ./helper.py --target x86/64 --profile generic --packages "$(ssh gw opkg list-installed | awk '{print $1}')"
sha256sums file is up to date
would you like to restore the original config file? [y/N] 
would you like to edit the config file? [y/N] 
Building images for x86 - Generic x86/64
Packages: arp-scan arp-scan-database atop attendedsysupgrade-common base-files bash bind-check bind-ddns-confgen bind-dig bind-dnssec bind-host bind-libs bind-nslookup bind-rndc bind-tools bnx2-firmware btop busybox ca-bundle cgi-io coreutils coreutils-nohup coreutils-sleep curl ddns-scripts ddns-scripts-services dnsmasq-full dnsproxy drill dropbear e2fsprogs firewall4 freeradius3 freeradius3-common freeradius3-default freeradius3-democerts freeradius3-mod-always freeradius3-mod-attr-filter freeradius3-mod-chap freeradius3-mod-detail freeradius3-mod-digest freeradius3-mod-eap freeradius3-mod-eap-gtc freeradius3-mod-eap-leap freeradius3-mod-eap-md5 freeradius3-mod-eap-mschapv2 freeradius3-mod-eap-peap freeradius3-mod-eap-pwd freeradius3-mod-eap-tls freeradius3-mod-eap-ttls freeradius3-mod-exec freeradius3-mod-expiration freeradius3-mod-expr freeradius3-mod-files freeradius3-mod-logintime freeradius3-mod-mschap freeradius3-mod-pap freeradius3-mod-preprocess freeradius3-mod-radutmp freeradius3-mod-realm freeradius3-mod-sql freeradius3-mod-sql-sqlite freeradius3-mod-unix freeradius3-utils fstools fwtool getrandom grub2 grub2-bios-setup grub2-efi haveged htop intel-microcode ip-full iperf3 iptraf-ng iputils-arping iputils-clockdiff iputils-ping iputils-tracepath irqbalance jansson4 jshn jsonfilter kernel kmod-amazon-ena kmod-amd-xgbe kmod-bnx2 kmod-button-hotplug kmod-crypto-acompress kmod-crypto-crc32c kmod-crypto-hash kmod-crypto-kpp kmod-crypto-lib-chacha20 kmod-crypto-lib-chacha20poly1305 kmod-crypto-lib-curve25519 kmod-crypto-lib-poly1305 kmod-crypto-md5 kmod-e1000 kmod-e1000e kmod-forcedeth kmod-fs-vfat kmod-hwmon-core kmod-i2c-algo-bit kmod-i2c-core kmod-igb kmod-igc kmod-input-core kmod-ipt-core kmod-ipt-ipset kmod-ixgbe kmod-lib-crc-ccitt kmod-lib-crc32c kmod-lib-lzo kmod-libphy kmod-macvlan kmod-mdio kmod-mdio-devres kmod-mii kmod-netlink-diag kmod-nf-conntrack kmod-nf-conntrack-netlink kmod-nf-conntrack6 kmod-nf-flow kmod-nf-ipt kmod-nf-log kmod-nf-log6 kmod-nf-nat kmod-nf-reject kmod-nf-reject6 kmod-nfnetlink kmod-nft-core kmod-nft-fib kmod-nft-nat kmod-nft-offload kmod-nls-base kmod-nls-cp437 kmod-nls-iso8859-1 kmod-nls-utf8 kmod-phy-realtek kmod-ppp kmod-pppoe kmod-pppox kmod-pps kmod-ptp kmod-r8169 kmod-slhc kmod-tg3 kmod-udptunnel4 kmod-udptunnel6 kmod-wireguard libatomic1 libattr libblkid1 libblobmsg-json libbpf libc libcap libcomerr0 libcurl4 libedit libelf1 libext2fs2 libf2fs6 libgcc1 libgmp10 libhavege libiperf3 libiwinfo libiwinfo-data libjson-c5 libjson-script libldns liblua5.1.5 liblucihttp-lua liblucihttp-ucode liblucihttp0 libmbedtls12 libmnl0 libncurses6 libnetfilter-conntrack3 libnettle8 libnfnetlink0 libnftnl11 libnghttp2-14 libnl-tiny2022-11-01 libopenssl-conf libopenssl1.1 libpcap1 libpcre libpthread libreadline8 librt libsmartcols1 libsqlite3-0 libss2 libstdcpp6 libtalloc libubox libubus libubus-lua libuci libuclient libucode libustream-openssl libuuid1 libuv1 logd lua luci luci-app-attendedsysupgrade luci-app-ddns luci-app-firewall luci-app-opkg luci-base luci-lib-base luci-lib-ip luci-lib-jsonc luci-lib-nixio luci-lua-runtime luci-mod-admin-full luci-mod-network luci-mod-status luci-mod-system luci-proto-ipv6 luci-proto-ppp luci-proto-wireguard luci-ssl-openssl luci-theme-bootstrap mac-telnet-client mac-telnet-discover mac-telnet-ping mac-telnet-server mkf2fs mtd nano-full netifd nftables-json odhcp6c odhcpd-ipv6only openssl-util openwrt-keyring opkg partx-utils ppp ppp-mod-pppoe procd procd-seccomp procd-ujail pv r8169-firmware rpcd rpcd-mod-file rpcd-mod-iwinfo rpcd-mod-luci rpcd-mod-rpcsys rpcd-mod-rrdns rpcd-mod-ucode sqlite3-cli ss tcpdump telnet-bsd terminfo ubox ubus ubusd uci uclient-fetch ucode ucode-mod-fs ucode-mod-html ucode-mod-lua ucode-mod-math ucode-mod-ubus ucode-mod-uci uhttpd uhttpd-mod-ubus urandom-seed urngd usign uwsgi uwsgi-cgi-plugin uwsgi-luci-support uwsgi-syslog-plugin wget-ssl wireguard-tools zlib base-files busybox ca-bundle dropbear e2fsprogs firewall4 fstools grub2-bios-setup kernel kmod-amazon-ena kmod-amd-xgbe kmod-bnx2 kmod-button-hotplug kmod-e1000 kmod-e1000e kmod-forcedeth kmod-fs-vfat kmod-igb kmod-igc kmod-ixgbe kmod-nft-offload kmod-r8169 kmod-tg3 libc logd mkf2fs mtd netifd odhcp6c odhcpd-ipv6only opkg partx-utils ppp ppp-mod-pppoe procd procd-seccomp procd-ujail uci uclient-fetch urandom-seed urngd
<rest of build log here>
$ scp openwrt-imagebuilder-x86-64.Linux-x86_64/build_dir/target-x86_64_musl/linux-x86_64/tmp/openwrt-x86-64-generic-ext4-combined-efi.img.gz gw:/tmp
openwrt-x86-64-generic-ext4-combined-efi.img.gz                                                                     100%   32MB  11.3MB/s   00:02    
$ ssh gw sysupgrade /tmp/openwrt-x86-64-generic-ext4-combined-efi.img.gz
Sat Jan 28 20:19:26 EET 2023 upgrade: Image metadata not present
Sat Jan 28 20:19:26 EET 2023 upgrade: Reading partition table from bootdisk...
Sat Jan 28 20:19:26 EET 2023 upgrade: Extract boot sector from the image
Sat Jan 28 20:19:26 EET 2023 upgrade: Reading partition table from image...
Sat Jan 28 20:19:26 EET 2023 upgrade: Saving config files...
Sat Jan 28 20:19:27 EET 2023 upgrade: Commencing upgrade. Closing all shell sessions.
Command failed: ubus call system sysupgrade { "prefix": "\/tmp\/root", "path": "\/tmp\/openwrt-x86-64-generic-ext4-combined-efi.img.gz", "backup": "\/tmp\/sysupgrade.tgz", "command": "\/lib\/upgrade\/do_stage2", "options": { "save_partitions": 1 } } (Connection failed)
```
