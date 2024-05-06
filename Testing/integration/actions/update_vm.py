#!/usr/bin/env python3
"""Download/update the given Santa E2E testing VM image."""
import argparse
import datetime
import logging
import os
import pathlib
import shutil
import subprocess
import sys

from google.cloud import storage

PROJECT = "santa-e2e"
BUCKET = "santa-e2e-vms"
COSIGN = "/opt/bin/cosign"
PUBKEY = "/opt/santa-e2e-vm-signer.pub"
VMS_DIR = pathlib.Path.home() / "VMs"

if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO)

  parser = argparse.ArgumentParser(description="Start E2E VM")
  parser.add_argument("--vm", help="VM tar.gz. name", required=True)
  args = parser.parse_args()

  VMS_DIR.mkdir(exist_ok=True)

  tar_name = args.vm
  if not tar_name.endswith(".tar.gz"):
    logging.fatal("Image name should be .tar.gz file")

  tar_path = VMS_DIR / tar_name
  extracted_path = pathlib.Path(str(tar_path)[: -len(".tar.gz")])

  if "GOOGLE_APPLICATION_CREDENTIALS" not in os.environ:
    logging.fatal("Missing GCS credentials file")

  storage_client = storage.Client(project=PROJECT)
  bucket = storage_client.bucket(BUCKET)
  blob = bucket.get_blob(tar_name)

  if blob is None:
    logging.fatal("Specified image doesn't exist in GCS")

  try:
    local_ctime = os.stat(extracted_path).st_ctime
  except FileNotFoundError:
    local_ctime = 0

  if blob.updated > datetime.datetime.fromtimestamp(
      local_ctime, tz=datetime.timezone.utc
  ):
    logging.info(
        f"VM {extracted_path} not present or not up to date, downloading..."
    )

    # Remove the old version of the image if present
    try:
      shutil.rmtree(extracted_path)
    except FileNotFoundError:
      pass

    blob.download_to_filename(tar_path)

    hash_blob = bucket.get_blob(str(tar_name) + ".sha256")
    if hash_blob is None:
      logging.fatal("Image hash doesn't exist in GCS")

    sig_blob = bucket.get_blob(str(tar_name) + ".sha256.sig")
    if sig_blob is None:
      logging.fatal("Image signature doesn't exist in GCS")

    hash_path = str(tar_path) + ".sha256"
    hash_blob.download_to_filename(hash_path)
    sig_path = str(tar_path) + ".sha256.sig"
    sig_blob.download_to_filename(sig_path)

    # cosign OOMs trying to sign/verify the tarball itself, so sign/verify
    # the SHA256 of the tarball.
    logging.info("Verifying signature...")

    # Verify the signature of the hash file is OK
    subprocess.check_output(
        [
            COSIGN,
            "verify-blob",
            "--key",
            PUBKEY,
            "--signature",
            sig_path,
            hash_path,
        ]
    )
    # Then verify that the hash matches what we downloaded
    subprocess.check_output(
        ["shasum", "-a", "256", "-c", hash_path],
        cwd=VMS_DIR,
    )

    logging.info("Extracting...")
    subprocess.check_output(
        ["tar", "-C", VMS_DIR, "-x", "-S", "-z", "-f", tar_path]
    )
    tar_path.unlink()
