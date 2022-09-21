#!/usr/bin/env python3
import datetime
import os
import pathlib
import subprocess
import sys
import tempfile

from google.cloud import storage

AGE = "/opt/bin/age"
BUCKET = "buildkite-vms"
VMCLI = "/opt/bin/VMCLI"
VMS_DIR = pathlib.Path.home() / 'VMs'

if __name__ == "__main__":
    VMS_DIR.mkdir(exist_ok=True)

    tar_name = sys.argv[1]
    if not tar_name.endswith('.tar.gz.enc'):
        print("Image name should be .tar.gz.enc file", file=sys.stderr)
        sys.exit(1)

    encrypted_tar_path = VMS_DIR / tar_name
    decrypted_tar_path = pathlib.Path(str(encrypted_tar_path)[:-len('.enc')])
    extracted_path = pathlib.Path(str(decrypted_tar_path)[:-len('.tar.gz')])

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
        blob.download_to_filename(encrypted_tar_path)

        # decrypt
        print("Decrypting...")
        subprocess.check_output([AGE, '--decrypt', '-o', decrypted_tar_path, encrypted_tar_path])
        # TODO(nickmg): once we know this works it's fine to delete
        #encrypted_tar_path.unlink()

        # extract
        print("Extracting...")
        extracted_path.mkdir()
        subprocess.check_output(['tar', '-C', VMS_DIR, '-x', '-S', '-z', '-f', decrypted_tar_path])
        decrypted_tar_path.unlink()

    with tempfile.TemporaryDirectory() as snapshot_dir:
        print(f"Snapshot: {snapshot_dir}")
        # COW copy the image to this tempdir
        subprocess.check_output(['cp', '-rc', extracted_path, snapshot_dir])
        try:
            subprocess.check_output([VMCLI, pathlib.Path(snapshot_dir) / "VM.bundle"], timeout=15*60)
        except subprocess.TimeoutExpired:
            print("VM timed out after 15 minutes")
        except:
            raise

    print("VM deleted")
