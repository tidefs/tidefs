#!/usr/bin/env bash

set -ex

exit_handler() {
    exit "$XFSTESTS_EXIT_STATUS"
}
trap exit_handler TERM
trap "kill 0" INT EXIT

export RUST_BACKTRACE=1

TEST_DATA_DIR=$(mktemp --directory)
SCRATCH_DATA_DIR=$(mktemp --directory)
TEST_DIR=$(mktemp --directory)
SCRATCH_DIR=$(mktemp --directory)

set +e
# Clear mount log file, since the tests append to it
echo "" > /code/logs/xfstests_mount.log
DIR=/var/tmp/fuse-xfstests/check-fuser
mkdir -p $DIR
cd /code/fuse-xfstests

# requires OFD & POSIX locks. OFD locks are not supported by fuse
echo "generic/478" >> xfs_excludes.txt

# TFR-011: open-unlink xfstests still need the public FUSE UAPI boundary.
echo "generic/484" >> xfs_excludes.txt

# Writes directly to scratch block dev
echo "generic/062" >> xfs_excludes.txt

# TFR-011: character-device rows need the public FUSE UAPI boundary.
echo "generic/078" >> xfs_excludes.txt

# TFR-020: long-running harness rows need explicit signal classification.
echo "generic/069" >> xfs_excludes.txt

# TFR-011: fallocate rows need the FUSE UAPI boundary recorded.
echo "generic/263" >> xfs_excludes.txt

# TFR-020: long-running harness rows need explicit signal classification.
echo "generic/127" >> xfs_excludes.txt

# TFR-011: fallocate coverage needs the public FUSE UAPI boundary.
echo "generic/103" >> xfs_excludes.txt

# TFR-011: mknod character-file rows need the public FUSE UAPI boundary.
echo "generic/184" >> xfs_excludes.txt
echo "generic/401" >> xfs_excludes.txt

# TFR-011: fifo rows need the public FUSE UAPI boundary.
echo "generic/423" >> xfs_excludes.txt
echo "generic/434" >> xfs_excludes.txt

# TFR-011: file-size limit rows need the public FUSE UAPI boundary.
echo "generic/394" >> xfs_excludes.txt

# requires BSD lock support, and checks /proc/locks. fuse locks don't seem to show up in /proc/locks
echo "generic/504" >> xfs_excludes.txt

# TFR-011: POSIX ACL rows need one FUSE UAPI authority.
# Some information about it linked from here: https://stackoverflow.com/questions/29569408/documentation-of-posix-acl-access-and-friends
echo "generic/099" >> xfs_excludes.txt
echo "generic/105" >> xfs_excludes.txt
echo "generic/375" >> xfs_excludes.txt

# TFR-011: read-only mount rows need the public FUSE UAPI boundary.
echo "generic/294" >> xfs_excludes.txt
echo "generic/306" >> xfs_excludes.txt
echo "generic/452" >> xfs_excludes.txt

# TFR-005: atime rows need the POSIX timestamp authority.
echo "generic/003" >> xfs_excludes.txt
echo "generic/192" >> xfs_excludes.txt

# TFR-008: sparse-hole rows need the writeback and durability boundary.
# for this test to be fast
echo "generic/130" >> xfs_excludes.txt

# TFR-004: namespace and inode mapping rows need dataset-scoped authority.
# this test ends up trying to chmod "/" (the root inode)
echo "generic/317" >> xfs_excludes.txt

# TFR-011: ACL rows need one public FUSE UAPI boundary.
echo "generic/319" >> xfs_excludes.txt
echo "generic/444" >> xfs_excludes.txt

# TFR-020: host-OOM harness rows need explicit signal classification.
echo "generic/089" >> xfs_excludes.txt

# TFR-020: long-running harness rows need explicit signal classification.
echo "generic/074" >> xfs_excludes.txt

# TFR-020: long-running harness rows need explicit signal classification.
echo "generic/339" >> xfs_excludes.txt

# TFR-020: long-running harness rows need explicit signal classification.
echo "generic/006" >> xfs_excludes.txt
echo "generic/011" >> xfs_excludes.txt
echo "generic/070" >> xfs_excludes.txt

# TFR-020: long-running harness rows need explicit signal classification.
echo "generic/438" >> xfs_excludes.txt

# TFR-020: host-crash harness rows need explicit signal classification.
echo "generic/476" >> xfs_excludes.txt

# TFR-020: Docker-only harness limits need explicit signal classification.
echo "generic/086" >> xfs_excludes.txt
echo "generic/391" >> xfs_excludes.txt
echo "generic/426" >> xfs_excludes.txt
echo "generic/467" >> xfs_excludes.txt
echo "generic/477" >> xfs_excludes.txt

# TFR-011: FIBMAP rows need one public FUSE UAPI boundary.
echo "generic/519" >> xfs_excludes.txt

# TFR-020: high-file-count harness rows need explicit signal classification.
echo "generic/531" >> xfs_excludes.txt

# Test requires mounting a loopback device
echo "generic/564" >> xfs_excludes.txt


FUSER_EXTRA_MOUNT_OPTIONS="" TEST_DEV="$TEST_DATA_DIR" TEST_DIR="$TEST_DIR" SCRATCH_DEV="$SCRATCH_DATA_DIR" SCRATCH_MNT="$SCRATCH_DIR" \
./check-fuser -E xfs_excludes.txt "$@" \
| tee /code/logs/xfstests.log

export XFSTESTS_EXIT_STATUS=${PIPESTATUS[0]}

if [ $XFSTESTS_EXIT_STATUS ]
then
  cat /code/fuse-xfstests/results/generic/*.bad
  cp /code/fuse-xfstests/results/generic/*.bad /code/logs/
fi

rm -rf ${TEST_DATA_DIR}
rm -rf ${TEST_DIR}
rm -rf ${SCRATCH_DATA_DIR}
rm -rf ${SCRATCH_DIR}
