"""Backup destination backends.

Every destination here stores already-encrypted bytes handed to it by
sentinel_backup.py (see crypto_utils.py) - this module is only responsible
for getting those bytes to the destination and back again for read-back
verification and restore. For the network backends (S3, Azure Blob)
transport is HTTPS by default via the vendor SDKs, which combined with the
client-side encryption already applied covers both at-rest and in-transit
protection.

All relative paths passed to these methods use forward slashes (POSIX
style), matching S3/Azure object-key conventions; LocalDestination converts
them to the local OS separator internally.

`rename()` is the operation Sentinel's atomic-write and versioning design
relies on: a staged upload is promoted to its final name only after
read-back verification succeeds, and an existing file is relocated to a
version path before being overwritten. Each backend implements "rename" as
atomically as its storage model allows (a real filesystem rename for local
disk/SMB; copy-then-delete for S3 and Azure Blob, which have no native
rename).
"""

import os
import shutil
import time


class BackupDestination:
    def upload_file(self, local_path: str, relative_dest_path: str) -> None:
        raise NotImplementedError

    def download_file(self, relative_dest_path: str, local_path: str) -> None:
        raise NotImplementedError

    def exists(self, relative_dest_path: str) -> bool:
        raise NotImplementedError

    def delete_file(self, relative_dest_path: str) -> None:
        raise NotImplementedError

    def rename(self, src_relative_path: str, dest_relative_path: str) -> None:
        raise NotImplementedError

    def check_connectivity(self) -> "tuple[bool, str]":
        raise NotImplementedError


class LocalDestination(BackupDestination):
    """A local drive letter, or a network UNC path (\\\\server\\share\\...).

    Windows treats UNC paths like local paths, so this one class covers a
    plain external drive and an SMB share alike. If root_path is an SMB
    share, also enable SMB 3.x encryption on that share (`EncryptData`)
    for transport-level protection in addition to the at-rest file
    encryption already applied before upload_file() is called.
    """

    def __init__(self, root_path: str):
        self.root_path = root_path

    def _path_for(self, relative_dest_path: str) -> str:
        return os.path.join(self.root_path, *relative_dest_path.split("/"))

    def upload_file(self, local_path: str, relative_dest_path: str) -> None:
        dest_path = self._path_for(relative_dest_path)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(local_path, dest_path)
        # Force the bytes out of the OS write cache. Without this, a
        # subsequent read-back would just re-read our own write buffer and
        # verify nothing at all - the exact failure mode this tool exists
        # to catch (bad sectors, flaky USB bridges, truncated writes).
        # Opened "r+b" (not "rb"): fsync/FlushFileBuffers needs a handle with
        # write access on Windows, or it fails with EBADF even though the
        # file itself is only being read here.
        with open(dest_path, "r+b") as f:
            os.fsync(f.fileno())

    def download_file(self, relative_dest_path: str, local_path: str) -> None:
        src_path = self._path_for(relative_dest_path)
        if not os.path.exists(src_path):
            raise FileNotFoundError(src_path)
        shutil.copy2(src_path, local_path)

    def exists(self, relative_dest_path: str) -> bool:
        return os.path.exists(self._path_for(relative_dest_path))

    def delete_file(self, relative_dest_path: str) -> None:
        path = self._path_for(relative_dest_path)
        if os.path.exists(path):
            os.remove(path)

    def rename(self, src_relative_path: str, dest_relative_path: str) -> None:
        src_path = self._path_for(src_relative_path)
        dest_path = self._path_for(dest_relative_path)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        os.replace(src_path, dest_path)  # atomic on the same volume

    def check_connectivity(self) -> "tuple[bool, str]":
        if os.path.exists(self.root_path):
            return True, f"{self.root_path} reachable"
        parent = os.path.dirname(self.root_path.rstrip("\\/"))
        if parent and os.path.exists(parent):
            return True, f"{parent} reachable ({self.root_path} will be created)"
        return False, f"{self.root_path} not reachable"


class S3Destination(BackupDestination):
    """AWS S3 (or S3-compatible) destination. Uploads over HTTPS.

    Credentials come from the standard AWS credential chain (environment
    variables, ~/.aws/credentials, or an assumed role) - never hardcode
    keys in this script.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        region: str = None,
        endpoint_url: str = None,
        server_side_encryption: bool = True,
    ):
        import boto3

        if endpoint_url and not endpoint_url.lower().startswith("https://"):
            raise ValueError("S3 endpoint_url must use https:// to protect data in transit.")

        self.bucket = bucket
        self.prefix = prefix
        self.server_side_encryption = server_side_encryption
        self.client = boto3.client("s3", region_name=region, endpoint_url=endpoint_url)

    def _key_for(self, relative_dest_path: str) -> str:
        rel = relative_dest_path.replace(os.sep, "/")
        return f"{self.prefix.rstrip('/')}/{rel}" if self.prefix else rel

    def _extra_args(self) -> dict:
        return {"ServerSideEncryption": "AES256"} if self.server_side_encryption else {}

    def upload_file(self, local_path: str, relative_dest_path: str) -> None:
        self.client.upload_file(local_path, self.bucket, self._key_for(relative_dest_path), ExtraArgs=self._extra_args())

    def download_file(self, relative_dest_path: str, local_path: str) -> None:
        self.client.download_file(self.bucket, self._key_for(relative_dest_path), local_path)

    def exists(self, relative_dest_path: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self.client.head_object(Bucket=self.bucket, Key=self._key_for(relative_dest_path))
            return True
        except ClientError:
            return False

    def delete_file(self, relative_dest_path: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=self._key_for(relative_dest_path))

    def rename(self, src_relative_path: str, dest_relative_path: str) -> None:
        src_key = self._key_for(src_relative_path)
        dest_key = self._key_for(dest_relative_path)
        copy_source = {"Bucket": self.bucket, "Key": src_key}
        self.client.copy_object(Bucket=self.bucket, CopySource=copy_source, Key=dest_key, **self._extra_args())
        self.client.delete_object(Bucket=self.bucket, Key=src_key)

    def check_connectivity(self) -> "tuple[bool, str]":
        from botocore.exceptions import ClientError, NoCredentialsError

        try:
            self.client.head_bucket(Bucket=self.bucket)
            return True, f"s3://{self.bucket} reachable"
        except NoCredentialsError:
            return False, "AWS credentials not found"
        except ClientError as e:
            return False, f"s3://{self.bucket} not reachable: {e}"
        except Exception as e:
            return False, f"could not reach S3: {e}"


class AzureBlobDestination(BackupDestination):
    """Azure Blob Storage destination. Uploads over HTTPS.

    Reads the connection string from an environment variable rather than a
    hardcoded secret. The connection string's endpoint protocol must be
    https, which is validated below.
    """

    COPY_POLL_SECONDS = 0.5
    COPY_POLL_ATTEMPTS = 60

    def __init__(
        self,
        container: str,
        prefix: str = "",
        connection_string_env: str = "AZURE_STORAGE_CONNECTION_STRING",
    ):
        from azure.storage.blob import BlobServiceClient

        conn_str = os.environ.get(connection_string_env)
        if not conn_str:
            raise RuntimeError(f"Environment variable {connection_string_env} is not set.")
        if "DefaultEndpointsProtocol=http;" in conn_str.replace(" ", ""):
            raise ValueError("Azure connection string must use https, not http, to protect data in transit.")

        self.container = container
        self.prefix = prefix
        self.service_client = BlobServiceClient.from_connection_string(conn_str)
        self.container_client = self.service_client.get_container_client(container)
        try:
            self.container_client.create_container()
        except Exception:
            pass  # Container already exists.

    def _blob_name_for(self, relative_dest_path: str) -> str:
        rel = relative_dest_path.replace(os.sep, "/")
        return f"{self.prefix.rstrip('/')}/{rel}" if self.prefix else rel

    def _blob_client(self, relative_dest_path: str):
        return self.container_client.get_blob_client(self._blob_name_for(relative_dest_path))

    def upload_file(self, local_path: str, relative_dest_path: str) -> None:
        blob_client = self._blob_client(relative_dest_path)
        with open(local_path, "rb") as f:
            blob_client.upload_blob(f, overwrite=True)

    def download_file(self, relative_dest_path: str, local_path: str) -> None:
        blob_client = self._blob_client(relative_dest_path)
        with open(local_path, "wb") as f:
            downloader = blob_client.download_blob()
            downloader.readinto(f)

    def exists(self, relative_dest_path: str) -> bool:
        return self._blob_client(relative_dest_path).exists()

    def delete_file(self, relative_dest_path: str) -> None:
        blob_client = self._blob_client(relative_dest_path)
        if blob_client.exists():
            blob_client.delete_blob()

    def rename(self, src_relative_path: str, dest_relative_path: str) -> None:
        src_blob = self._blob_client(src_relative_path)
        dest_blob = self._blob_client(dest_relative_path)
        dest_blob.start_copy_from_url(src_blob.url)
        for _ in range(self.COPY_POLL_ATTEMPTS):
            status = dest_blob.get_blob_properties().copy.status
            if status == "success":
                break
            if status in ("failed", "aborted"):
                raise RuntimeError(f"Azure copy {src_relative_path} -> {dest_relative_path} {status}")
            time.sleep(self.COPY_POLL_SECONDS)
        else:
            raise TimeoutError(f"Azure copy {src_relative_path} -> {dest_relative_path} did not complete in time")
        src_blob.delete_blob()

    def check_connectivity(self) -> "tuple[bool, str]":
        try:
            self.container_client.get_container_properties()
            return True, f"azure container '{self.container}' reachable"
        except Exception as e:
            return False, f"azure container '{self.container}' not reachable: {e}"


def build_destination(destination_type: str, config: dict) -> BackupDestination:
    if destination_type == "local":
        return LocalDestination(config["root_path"])
    if destination_type == "s3":
        return S3Destination(
            bucket=config["bucket"],
            prefix=config.get("prefix", ""),
            region=config.get("region"),
            endpoint_url=config.get("endpoint_url"),
            server_side_encryption=config.get("server_side_encryption", True),
        )
    if destination_type == "azure":
        return AzureBlobDestination(
            container=config["container"],
            prefix=config.get("prefix", ""),
            connection_string_env=config.get("connection_string_env", "AZURE_STORAGE_CONNECTION_STRING"),
        )
    raise ValueError(f"Unknown destination_type: {destination_type}")
