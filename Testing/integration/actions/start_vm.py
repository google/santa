#!/usr/bin/env python3
"""Download and run the given Santa E2E testing VM image."""
import argparse
import json
import logging
import os
import pathlib
import subprocess
import tempfile
import urllib.request

VMS_DIR = pathlib.Path.home() / "VMs"
TIMEOUT = 15 * 60  # in seconds

if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO)

  parser = argparse.ArgumentParser(description="Start E2E VM")
  # This is redundant, but kept to keep consistency with update_vm.py
  parser.add_argument("--vm", help="VM tar.gz. name", required=True)
  parser.add_argument(
      "--vmcli", help="Path to VMCLI binary", default="/opt/bin/VMCLI"
  )
  args = parser.parse_args()

  if not args.vm.endswith(".tar.gz"):
    logging.fatal("Image name should be .tar.gz file")

  tar_path = VMS_DIR / args.vm
  extracted_path = pathlib.Path(str(tar_path)[: -len(".tar.gz")])

  with tempfile.TemporaryDirectory() as snapshot_dir:
    logging.info(f"Snapshot: {snapshot_dir}")
    # COW copy the image to this tempdir
    subprocess.check_output(["cp", "-rc", extracted_path, snapshot_dir])

    # Get a JIT runner key
    github_token = os.environ["RUNNER_REG_TOKEN"]
    body = json.dumps(
        {
            "name": os.environ["GITHUB_RUN_ID"] + " inner",
            "runner_group_id": 1,
            "labels": [
                "self-hosted",
                "macOS",
                "ARM64",
                "e2e-vm",
            ],
            "work_folder": "/tmp/_work",
        }
    )
    owner, repo = os.environ["GITHUB_REPOSITORY"].split("/", 1)
    request = urllib.request.Request(
        f"https://api.github.com/repos/{owner}/{repo}/actions/runners/generate-jitconfig",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        data=body.encode("utf-8"),
    )
    with urllib.request.urlopen(request) as response:
      jit_config = json.loads(response.read())["encoded_jit_config"]

    logging.info("Got JIT runner config")

    # Create a disk image to inject startup script
    init_dmg = pathlib.Path(snapshot_dir) / "init.dmg"
    subprocess.check_output(
        [
            "hdiutil",
            "create",
            "-attach",
            "-size",
            "1G",
            "-fs",
            "APFS",
            "-volname",
            "init",
            init_dmg,
        ]
    )
    init_dmg_mount = pathlib.Path("/Volumes/init/")

    # And populate startup script with runner and JIT key
    with open(init_dmg_mount / "run.sh", "w") as run_sh:
      run_sh.write(
          f"""#!/bin/sh
set -xeuo pipefail

curl -L -o /tmp/runner.tar.gz 'https://github.com/actions/runner/releases/download/v2.316.0/actions-runner-osx-arm64-2.316.0.tar.gz'
echo "8442d39e3d91b67807703ec0825cec4384837b583305ea43a495a9867b7222ca  /tmp/runner.tar.gz" | shasum -a 256 -c -
mkdir /tmp/runner
cd /tmp/runner
tar -xzf /tmp/runner.tar.gz
./run.sh --jitconfig '{jit_config}'
"""
      )
    os.chmod(init_dmg_mount / "run.sh", 0o755)
    subprocess.check_output(["hdiutil", "detach", init_dmg_mount])

    logging.info("Created init.dmg")

    # Create a disk image for USB testing
    usb_dmg = pathlib.Path(snapshot_dir) / "usb.dmg"
    subprocess.check_output(
        [
            "hdiutil",
            "create",
            "-size",
            "100M",
            "-fs",
            "ExFAT",
            "-volname",
            "USB",
            usb_dmg,
        ]
    )

    logging.info("Created usb.dmg")

    try:
      logging.info("Starting VM")
      subprocess.check_output(
          [
              args.vmcli,
              pathlib.Path(snapshot_dir) / extracted_path.name,
              init_dmg,
              usb_dmg,
          ],
          timeout=TIMEOUT,
      )
    except subprocess.TimeoutExpired:
      logging.warning("VM timed out")

  logging.info("VM deleted")
