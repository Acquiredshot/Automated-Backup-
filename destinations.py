"""Backup destination backends.

Every destination here receives already-encrypted file bytes from
backup_to_external_drive.py (see crypto_utils.py) — this module is only
responsible for getting those bytes to the destination. For the network
backends (S3, Azure Blob) transport is HTTPS by default via the vendor
SDKs, which combined with the client-side encryption already applied
covers both at-rest and in-transit protection.
"""

import os
import shutil


class BackupDestination:
    def upload_file(self, local_path: str, relative_dest_path: str) -> None:
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

    def upload_file(self, local_path: str, relative_dest_path: str) -> None:
        dest_path = os.path.join(self.root_path, relative_dest_path)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(local_path, dest_path)


class S3Destination(BackupDestination):
    """AWS S3 (or S3-compatible) destination. Uploads over HTTPS.

    Credentials come from the standard AWS credential chain (environment
    variables, ~/.aws/credentials, or an assumed role) — never hardcode
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

    def upload_file(self, local_path: str, relative_dest_path: str) -> None:
        extra_args = {"ServerSideEncryption": "AES256"} if self.server_side_encryption else {}
        self.client.upload_file(local_path, self.bucket, self._key_for(relative_dest_path), ExtraArgs=extra_args)


class AzureBlobDestination(BackupDestination):
    """Azure Blob Storage destination. Uploads over HTTPS.

    Reads the connection string from an environment variable rather than a
    hardcoded secret. The connection string's endpoint protocol must be
    https, which is validated below.
    """

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

    def upload_file(self, local_path: str, relative_dest_path: str) -> None:
        blob_client = self.container_client.get_blob_client(self._blob_name_for(relative_dest_path))
        with open(local_path, "rb") as f:
            blob_client.upload_blob(f, overwrite=True)


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
    raise ValueError(f"Unknown DESTINATION_TYPE: {destination_type}")
