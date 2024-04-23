#!/usr/bin/env python3
"""Download and run the given Santa E2E testing VM image."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import urllib.request

VMCLI = "/opt/bin/VMCLI"
VMS_DIR = pathlib.Path.home() / "VMs"
TIMEOUT = 15 * 60  # in seconds

if __name__ == "__main__":
  tar_name = sys.argv[1]
  if not tar_name.endswith(".tar.gz"):
    print("Image name should be .tar.gz file", file=sys.stderr)
    sys.exit(1)

  tar_path = VMS_DIR / tar_name
  extracted_path = pathlib.Path(str(tar_path)[:-len(".tar.gz")])

  with tempfile.TemporaryDirectory() as snapshot_dir:
    print(f"Snapshot: {snapshot_dir}")
    # COW copy the image to this tempdir
    subprocess.check_output(["cp", "-rc", extracted_path, snapshot_dir])

    # Get a JIT runner key
    github_token = os.environ["RUNNER_REG_TOKEN"]
    body = json.dumps({
      "name": os.environ["GITHUB_RUN_ID"] + " inner",
      "runner_group_id":1,
      "labels":[
        "self-hosted",
        "ARM",
        "macOS",
        "e2e-vm",
      ],
      "work_folder":"/tmp/_work",
    })
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

    # Create a disk image to inject startup script
    init_dmg = pathlib.Path(snapshot_dir) / "init.dmg"
    subprocess.check_output(["hdiutil", "create", "-attach", "-size", "200M",
                                "-fs", "ExFAT", "-volname", "init", init_dmg])
    init_dmg_mount = pathlib.Path("/Volumes/init/")

    # And populate startup script with runner and JIT key
    with open(init_dmg_mount / "boot.sh", "w") as run_sh:
      run_sh.write(f"""#!/bin/sh
curl -L -o /tmp/runner.tar.gz 'https://github.com/actions/runner/releases/download/v2.316.0/actions-runner-osx-arm64-2.316.0.tar.gz'
mkdir /tmp/runner
cd /tmp/runner
tar -xzf /tmp/runner.tar.gz
./run.sh --jitconfig '{jit_config}'
""")
    os.chmod(init_dmg_mount / "boot.sh", 0o755)
    subprocess.check_output(["hdiutil", "unmount", init_dmg_mount])

    # Create a disk image for USB testing
    usb_dmg = pathlib.Path(snapshot_dir) / "usb.dmg"
    subprocess.check_output(["hdiutil", "create", "-size", "100M",
                                "-fs", "ExFAT", "-volname", "USB", usb_dmg])

    try:
      subprocess.check_output(
          [VMCLI, pathlib.Path(snapshot_dir) / extracted_path.name, init_dmg, usb_dmg],
          timeout=TIMEOUT,
      )
    except subprocess.TimeoutExpired:
      print("VM timed out")

  print("VM deleted")

