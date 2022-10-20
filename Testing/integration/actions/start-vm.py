#!/usr/bin/env python3
import datetime
import json
import os
import pathlib
import subprocess
import sys
import tempfile

from google.cloud import storage
from google.oauth2 import service_account

PROJECT = "santa-e2e"
SA_KEY = "/opt/santa-e2e-sa.json"
BUCKET = "santa-e2e-vms"
COSIGN = "/opt/bin/cosign"
PUBKEY = "/opt/santa-e2e-vm-signer.pub"
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

    storage_client = storage.Client(
      project=PROJECT,
      credentials=service_account.Credentials.from_service_account_info(
        json.loads(open(SA_KEY, 'r').read())
      ),
    )
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
        sig_blob = bucket.get_blob(str(tar_name) + '.sig')
        if sig_blob is None:
          print("Image signature doesn't exist in GCS", file=sys.stderr)
          sys.exit(1)

        sig_path = str(tar_path) + '.sig'
        sig_blob.download_to_filename(sig_path)

        print("Verifying signature...")
        subprocess.check_output([COSIGN, 'verify-blob', '--key', PUBKEY, '--signature', sig_path, tar_path])

        print("Extracting...")
        subprocess.check_output(['tar', '-C', VMS_DIR, '-x', '-S', '-z', '-f', tar_path])
        tar_path.unlink()

    with tempfile.TemporaryDirectory() as snapshot_dir:
        print(f"Snapshot: {snapshot_dir}")
        # COW copy the image to this tempdir
        subprocess.check_output(['cp', '-rc', extracted_path, snapshot_dir])
        try:
            subprocess.check_output([VMCLI, pathlib.Path(snapshot_dir) / extracted_path.name], timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            print("VM timed out")
        except:
            raise

    print("VM deleted")
