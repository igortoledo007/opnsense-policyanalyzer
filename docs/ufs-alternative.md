# Policy Analyzer on UFS installations

Context: in [opnsense/plugins#5926](https://github.com/opnsense/plugins/issues/5926) an OPNsense maintainer replied that
OPNsense only accepts small plugins, ideally based on FreeBSD ports, and that the Policy Analyzer relies on a lot of
Python, custom ZFS datasets and jails. The advice was to keep it in its own repository, announce it on Reddit and on
the forum, keep its own gettext domain (approved) and warn that part of it does not work on UFS.

Decision: I follow that advice. The plugin stays at github.com/igortoledo007/opnsense-policyanalyzer, and it now
supports **both ZFS and UFS, both tested**: instead of only warning, I fixed what failed on UFS, protected the system
disk and offer an optional alternative. This document describes what changes without ZFS, the fixes, the ZFS pool in a
file, the alternative without local disk use, and how to test. The lab results (UFS and ZFS virtual machines) are in
[file-systems.md](file-systems.md).

## 1. What changes on UFS

Most of the plugin does not depend on the file system: analysis, incidents, anomalies, posture, devices, reports and
the remote AI providers work the same. The difference is only in the local AI runtime (a jail with Ollama) and the
models:

| Part | With ZFS (zroot) | On UFS |
|---|---|---|
| Storage (`prepare_storage`, `ai/storage.py`) | creates the dataset `zroot/ai` on `/var/db/ai` (recordsize 1M, no compression, `primarycache=metadata`) | creates only the directory `/var/db/ai/models` on the system disk |
| Jail root (`install_runtime`) | dataset `zroot/ai/jail` (lz4) | directory `/var/db/ai/jail` |
| Uninstall with the models | `zfs destroy -r zroot/ai`, confirmation `confirm=zroot/ai` | used to fail with "/var/db/ai is not a ZFS dataset, nothing to destroy"; now deletes the models directory, confirmation `confirm=/var/db/ai/models` |
| Space | the models share the pool with the rest of the system | the models share the `/var` partition (logs, config.xml backups, package database) |
| Health collector (`collect/health.py`) | `zpool list -Hp` | `df -kP /` (also when the pool in a file exists) |

### Fixes

1. **Removing the models on UFS.** When `/var/db/ai` is not a ZFS dataset, `uninstall_runtime +remove_dataset` now
   accepts the path `/var/db/ai/models` as confirmation. The step is `remove_tree` flagged `models: true`, the only
   case where the executor deletes the models directory, and only that directory (never a subdirectory, never
   anything next to it, never while it is a mount point or has something mounted below it). It is listed as
   `irreversible` and the plan risk is `high`. Nothing changed on ZFS: the confirmation is still the dataset name.
2. **Free-space guard.** Before installing the runtime, downloading (`pull_model`) or importing (`import_gguf`) a
   model, and before creating the pool in a file, the plan checks the free space of the target file system and blocks
   when what would remain after the operation is below max(20 % of the estimate, a floor). The floor is 2 GiB on the
   file system that holds `/var` (same device on UFS, same pool on ZFS) and 1 GiB elsewhere. Estimates:
   - runtime: `BASE_TXZ_BYTES_ESTIMATE` + `BASE_EXTRACTED_BYTES_ESTIMATE` + `PKG_DOWNLOAD_ESTIMATE` +
     `PKG_INSTALLED_ESTIMATE` from `setup/common.py` (measured on 2026-11-07, about 1.8 GB);
   - registry model: exact sum of the missing blobs, read from the manifest;
   - GGUF: file size, ×2 when downloaded from Hugging Face (the file and the copy Ollama makes);
   - pool image: the exact size chosen (no 20 %, only the 2 GiB floor).
   On UFS the plan and `status runtime` also warn that the models share the system disk.
3. **Default limits on small hosts** (found in the lab): the default cpu set `2-3` does not exist on a 2-cpu host, and
   `install_runtime` without arguments failed with "threads (2) can not exceed the number of cpus in the set (1)".
   When the default does not fit, the upper half of the cpus is used now (cpu 1 on a 2-cpu host) and the default
   threads are capped to that set. Not specific to UFS, but it shows up on small firewalls.
4. **Executable bit of the scripts** (found in the lab): `setup/quicktest.py`, `analyze.py` and the `cli.py` of
   minrule, posture and shadowai lacked the executable bit in git; configd calls the quick test directly and the test
   question failed with exit 126. The mode is fixed in git.
5. **Jail at boot when `/var/log` is a tmpfs** (lab round 2): the nano image and installations with a RAM disk for
   `/var/log` lose `/var/log/policyanalyzer` at every boot, and `jail(8)` refused to create the jail because
   `exec.consolelog` pointed there. The jail console log is now `/var/db/ai/jail-ollama.console.log`, which exists at
   boot (UFS, `zroot/ai` or `aipool/ai`).
6. **Uninstall right after stopping the jail** (round 2, also on native ZFS): after `jail -r` the jail stays "dying"
   for up to a minute and `zfs destroy` of the jail dataset failed with "dataset is busy". The step now retries for up
   to 90 s while the error is "busy", and stopping the jail has an inverse again: if the uninstall fails, the rollback
   starts Ollama again.
7. **Exporting the pool in a file at shutdown** (round 2): for the same reason the `zpool export` of the rc script
   failed at shutdown; it now retries for up to 75 s (below the default `rcshutdown_timeout` of 90 s). And
   `remove_file_pool` resets `vfs.zfs.arc.max=0` right away, without waiting for the next boot.
8. **Runtime leftovers no longer block the pool** (round 3): the console log left in `/var/db/ai` after uninstalling
   the runtime made `create_file_pool` refuse with "already holds files". The check now ignores that known leftover,
   and `uninstall_runtime +remove_dataset` deletes the log together with the models.
9. **Fake pid at shutdown** (round 3): OPNsense's `rc.freebsd` takes the pid of each service from the last field of
   `status` and sends `kill -9` after 30 s; the pool status ended with the free space ("17.8G" became pid 178). The
   status now ends with "is imported" / "is not imported", without digits.
10. **Runtime install without the storage step** (screenshot session): `install_runtime` failed with "No such file
   or directory: '/var/db/ai/models'" when the directory did not exist (storage step skipped, or after
   `remove_file_pool`). It now creates it before giving it to the jail user.
11. **`prepare_storage` on UFS** warns that the models live on the system disk and, when a dataset is already mounted
   on `/var/db/ai` (the pool in a file), uses that dataset instead of saying "root is not ZFS".

## 2. Risks of keeping the models on the system disk (UFS)

- A 5–20 GB model on a single partition can fill `/var`: syslog stops writing, the config.xml backup fails, updates
  and `pkg` stop working. The free-space guard keeps the plugin from causing this, but it reserves nothing: after the
  download, the logs can still grow.
- UFS has no per-directory quota on OPNsense (UFS quotas are not enabled by default), so there is no hard limit for
  `/var/db/ai`.
- Removing the models on UFS is a real `rm -rf`: no snapshot, no way back. That is why it asks for the full path as
  confirmation.

## 3. Optional alternative: a ZFS pool in a file

Created only on request (`create_file_pool`). The idea: an image file `/var/db/ai.zpool.img`, fully preallocated to
the size I choose, attached as a vnode `md` disk and holding its own ZFS pool (`aipool`). The dataset `aipool/ai` is
mounted on `/var/db/ai`, so the rest of the plugin sees `/var/db/ai` as a ZFS dataset: the jail becomes
`aipool/ai/jail` and removing the models is `confirm=aipool/ai` again.

### What the plan does (in order)

1. `kldload -n zfs` (skipped when the module is already loaded).
2. Optional: `sysctl vfs.zfs.arc.max=<arc_mb>` (undo: `vfs.zfs.arc.max=0`, automatic size).
3. Writes `/etc/rc.conf.d/policyanalyzer_aipool` (enabled at boot, image, md unit, pool, ARC cap).
4. Writes `/usr/local/etc/rc.d/policyanalyzer_aipool` (0755).
5. `image_create`: creates the image with `posix_fallocate` in 1 GiB chunks (zeros where unsupported), with progress
   and cancel. Preallocation is what guarantees the fixed limit: the space leaves the disk now, and the pool never
   grows later.
6. `md_attach`: `mdconfig -a -t vnode -f /var/db/ai.zpool.img -u <N>`, N being the first free unit between 10 and 99
   (away from md0/md1, which OPNsense uses for RAM disks).
7. `zpool_create`: `zpool create -o ashift=12 -o cachefile=none -o autoexpand=off -o failmode=continue -O
   mountpoint=none -O canmount=off -O atime=off -O compression=off aipool /dev/mdN`.
8. `zfs create -o mountpoint=/var/db/ai -o recordsize=1M -o compression=off -o atime=off -o primarycache=metadata
   aipool/ai` (same tuning as `zroot/ai`: large files written once, no data in the ARC).
9. Creates `/var/db/ai/models`.

The plan blocks when: `/var/db` is already on ZFS (then it makes no sense), a pool named `aipool` exists that is not
backed by this image, the image exists but is not attached, `/var/db/ai` already holds files (models or the jail,
which the pool would hide; the known console-log leftover is ignored), the runtime is running, or the space does not
fit.

### Persistence at boot

I evaluated two options:

- **`/etc/rc.conf.d/mdconfig` with `mdconfig_md10="-t vnode -f /var/db/ai.zpool.img"` + `zfs_enable="YES"`**:
  FreeBSD's `/etc/rc.d/mdconfig` attaches the disk, but `/etc/rc.d/zpool` imports from the cache file and has
  `REQUIRE: hostid disks`, not `mdconfig`; the order between them is not guaranteed, and a pool in the system cache
  file may be looked for before the md disk exists. It would also change the global ZFS configuration of a system
  that does not use ZFS.
- **Own rc.d script (chosen)**: `/usr/local/etc/rc.d/policyanalyzer_aipool`, with `PROVIDE: policyanalyzer_aipool`,
  `REQUIRE: FILESYSTEMS`, `BEFORE: jail` and `KEYWORD: shutdown nojail`. On `start` it checks the image, loads zfs,
  applies the ARC cap (if set), attaches the image to the same unit (refusing if the unit is attached to another
  file) and runs `zpool import -d /dev/mdN -o cachefile=none aipool`. On `stop` it runs `zpool export` (retried while
  a dying jail keeps the datasets busy) and `mdconfig -d`. Since the pool uses `cachefile=none`, no system cache file
  points to it; only this script imports it, and `zfs_enable` is not needed. `BEFORE: jail` is what guarantees that
  `/var/db/ai/models` is mounted when the Ollama jail starts (the jail mounts that directory with nullfs). Its
  `status` never ends with digits, because `rc.freebsd` reads a pid from the last field.

On OPNsense the rc.d scripts are run by `/usr/local/etc/rc.freebsd` at the end of the boot, in rcorder, for the
services enabled in `/etc/rc.conf.d/`, the same path the Ollama jail already uses (`/etc/rc.conf.d/jail`). The lab
confirmed it: the pool is imported before "Starting jails: ollama.", and it is exported at shutdown.

### Undo

- **Revert of `create_file_pool`** (from the action history): in reverse order: ARC back, `/var/db/ai/models` removed
  if empty, `zfs destroy aipool/ai` and `zpool destroy aipool` **only while they hold no files or snapshots**,
  `mdconfig -d`, the image deleted (refused while still attached) and the rc files last. If there are models, the
  revert stops before touching the rc files, so the pool is still imported at boot.
- **`remove_file_pool aipool`**: destroys the pool with everything in it (irreversible), requires the runtime to be
  uninstalled first (`uninstall_runtime`), detaches the md disk, deletes the image and the rc files, and resets the
  ARC cap. Its revert creates an empty pool of the same size again; the models do not come back.

### Pros and cons

Pros:
- A fixed, real size limit: the models never exceed the image size, and the system disk does not fill up.
- `/var/db/ai` becomes a ZFS dataset: checksums on the models, 1M recordsize, the jail in its own lz4 dataset, and a
  clean removal (`zfs destroy`, `zpool destroy`, deleting one file).
- Reversible and isolated: nothing outside the image, two rc files and the zfs module.

Cons:
- **Two stacked file systems**: every model read goes through ZFS, the vnode md and UFS. Models are read once when
  loaded (then they stay in Ollama's RAM), so the impact should only show in the load time; writes are rare
  (downloads).
- **Performance**: the vnode md is synchronous and single-queue; the UFS below can fragment the image if the disk is
  already full when it is preallocated. In the lab, preallocating 20 GiB took about 5–6 minutes (~56 MiB/s on a
  qcow2 disk).
- **ARC RAM on a small firewall**: loading ZFS turns on the ARC, which by default may use a large share of the RAM.
  With `primarycache=metadata` the model data does not go into the ARC, but the metadata and the jail
  (`primarycache=all`) do. I recommend `arc_mb=256` to `512` on firewalls with 4–8 GB. ZFS also reserves kernel memory
  that does not show as "free".
- **Recovery**: after a power loss UFS runs fsck (the image is one large file; fsck does not look inside it) and ZFS
  runs its own checks on import. If the image is corrupted, the pool may not import: then the way out is
  `remove_file_pool` (or deleting the image by hand with the md detached) and downloading the models again. Nothing
  irreplaceable lives there: the models come back from the registry.
- The md disk does not show up as a system pool in the installer; whoever administers the firewall needs to know it
  exists (hence the file name and the "Managed by os-policyanalyzer" header in the rc files).

## 4. Another alternative: a model server in the LAN (no use of the firewall disk)

This is the one I recommend for small or UFS firewalls. The plugin already supports it: provider **Ollama** with
"Where does Ollama run?" = **"On a server in my LAN"** (`ai/providers/ollama.py`, field `location: lan` and `url`, for
example `http://192.0.2.10:11434`). Nothing is installed or downloaded on the firewall; data only goes to that server
in my network (anonymized first, when anonymization is on). There are also the remote providers Anthropic API
(`ai/providers/claude.py`) and Claude Code through the LAN bridge (`ai/providers/claudecode.py`), which use no local
disk.

In that case the local runtime is not installed: configuring the provider in Firewall › Policy Analyzer › AI setup is
enough.

## 5. Commands

Through configd (the same path the GUI uses; `change_plan` only simulates):

```sh
# runtime status, with file_pool and models_fs (fstype, shares_var)
configctl policyanalyzer ai_runtime

# UFS: uninstall the runtime deleting the models (confirmation = path)
configctl policyanalyzer change_plan  uninstall_runtime +remove_dataset /var/db/ai/models
configctl policyanalyzer change_apply uninstall_runtime +remove_dataset /var/db/ai/models

# pool in a file: size in GiB and, optionally, the ARC cap in MiB
configctl policyanalyzer change_plan  create_file_pool 40 512
configctl policyanalyzer change_apply create_file_pool 40 512     # runs in the background
configctl policyanalyzer setup_job                                # progress (preallocation)
configctl policyanalyzer change_history                           # journal id for the revert

# after that, the normal flow
configctl policyanalyzer change_apply install_runtime
configctl policyanalyzer change_apply pull_model qwen3:4b

# remove everything
configctl policyanalyzer change_apply uninstall_runtime +remove_dataset aipool/ai
configctl policyanalyzer change_apply remove_file_pool aipool
```

Directly with `manage.py` (as root, same JSON output):

```sh
cd /usr/local/opnsense/scripts/policyanalyzer
./manage.py plan create_file_pool 40 512
./manage.py apply create_file_pool 40 512
./manage.py plan remove_file_pool aipool
./manage.py status runtime
```

From the shell, `size=40 arc_mb=512 image=/var/db/other.img` (key=value) also works; the GUI only takes the
positional form.

Manual checks after the apply and after a reboot:

```sh
mdconfig -lv                      # md10  vnode  40G  /var/db/ai.zpool.img
zpool list aipool                 # ONLINE
zfs list -r -o name,mountpoint,used,avail aipool
mount -p | grep /var/db/ai
service policyanalyzer_aipool status
sysctl vfs.zfs.arc.max
df -h /var                        # the image space is already accounted for
```

Unit tests (no FreeBSD needed, fake runner):

```sh
(cd tests/setup && python3 -m unittest -q test_ufs)
(cd tests/collect && python3 -m unittest -q test_health)
```

`tests/setup/test_ufs.py` covers UFS without the alternative (directory and warnings), removing the models on UFS
(plan, confirmation, apply and the `remove_tree` guard), the free-space guard (2 GiB floor and 20 % margin), the pool
in a file (plan, simulated apply, idempotency, empty revert, revert refused with models, rollback on failure,
`remove_file_pool` and its revert, guards of the new steps), ZFS unchanged, and one test per lab finding.

## 6. What only a FreeBSD/OPNsense machine validates

All of the items below were validated in the KVM labs (see [file-systems.md](file-systems.md)): `rc.freebsd` runs the
rc script at boot before the jail and stops it at shutdown; the real output of `mdconfig` and `zpool import -d`;
`posix_fallocate` on UFS; `kldload zfs` on a UFS install and `vfs.zfs.arc.max` (set and reset to 0); the jail on
`aipool/ai/jail` with the nullfs mount of `/var/db/ai/models`; the UFS uninstall with
`+remove_dataset /var/db/ai/models`. Not covered: importing the pool after a power loss without `export` (it should
import without `-f`, since the hostid is the same).
