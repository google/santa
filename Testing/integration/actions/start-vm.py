#!/usr/bin/env python3
import datetime
import os
import pathlib
import subprocess
import sys
import tempfile

from google.cloud import storage

MINISIGN = "/opt/bin/minisign"
PUBKEY = "/opt/santa-e2e-vm-signer.pub"
BUCKET = "santa-e2e-vms"
VMCLI = "/opt/bin/VMCLI"
VMS_DIR = pathlib.Path.home() / 'VMs'
TIMEOUT = 15 * 60  # in seconds

if __name__ == "__main__":
    VMS_DIR.mkdir(exist_ok=True)

    tar_name = sys.argv[1]
    if not tar_name.endswith('.tar.gz'):
        print("Image name should be .tar.gz file", file=sys.stderr)
        sys.exit(1)

    tar_path = VMS_DIR / tar_name
    extracted_path = pathlib.Path(str(tar_path)[:-len('.tar.gz')])

    storage_client = storage.Client()
    bucket = storage_client.bucket(BUCKET)
    blob = bucket.get_blob(tar_name)

    if blob is None:
      print("Specified image doesn't exist in GCS", file=sys.stderr)
      sys.exit(1)

    try:
      local_ctime = os.stat(extracted_path).st_ctime
    except FileNotFoundError:
      local_ctime = 0

    if blob.updated > datetime.datetime.fromtimestamp(local_ctime, tz=datetime.timezone.utc):
        print(f"VM {extracted_path} not present or not up to date, downloading...")
        blob.download_to_filename(tar_path)
        sig_blob = bucket.get_blob(str(tar_name) + '.minisig')
        if sig_blob is None:
          print("Image signature doesn't exist in GCS", file=sys.stderr)
          sys.exit(1)

        sig_blob.download_to_filename(str(tar_path) + '.minisig')

        print("Verifying signature...")
        subprocess.check_output([MINISIGN, '-V', '-m', tar_path, '-p', PUBKEY])

        print("Extracting...")
        extracted_path.mkdir()
        subprocess.check_output(['tar', '-C', VMS_DIR, '-x', '-S', '-z', '-f', tar_path])
        tar_path.unlink()

    with tempfile.TemporaryDirectory() as snapshot_dir:
        print(f"Snapshot: {snapshot_dir}")
        # COW copy the image to this tempdir
        subprocess.check_output(['cp', '-rc', extracted_path, snapshot_dir])
        try:
            subprocess.check_output([VMCLI, pathlib.Path(snapshot_dir) / "VM.bundle"], timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            print("VM timed out")
        except:
            raise

    print("VM deleted")
