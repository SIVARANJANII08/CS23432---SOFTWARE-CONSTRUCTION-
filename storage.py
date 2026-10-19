"""Where the evidence FILES are kept. Azure Blob Storage in the cloud,
a local folder while developing. Both expose the same two methods."""
import os


class LocalStorage:
    def __init__(self, folder):
        self.folder = folder
        os.makedirs(folder, exist_ok=True)

    def _path(self, key):
        return os.path.join(self.folder, os.path.basename(key))

    def save(self, source_path, key):
        if os.path.exists(self._path(key)):
            raise FileExistsError("Evidence object already exists (write-once).")
        with open(source_path, "rb") as src, open(self._path(key), "xb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)

    def iter_chunks(self, key, chunk_size=1024 * 1024):
        with open(self._path(key), "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    name = "Local folder"


class AzureBlobStorage:
    def __init__(self, connection_string, container):
        from azure.storage.blob import BlobServiceClient
        service = BlobServiceClient.from_connection_string(connection_string)
        self.container = service.get_container_client(container)
        if not self.container.exists():
            self.container.create_container()  # private by default (no public access)

    def save(self, source_path, key):
        with open(source_path, "rb") as data:
            self.container.upload_blob(name=key, data=data, overwrite=False)

    def iter_chunks(self, key):
        return self.container.download_blob(key).chunks()

    name = "Azure Blob Storage"


def build_storage(app):
    conn = app.config.get("AZURE_STORAGE_CONNECTION_STRING")
    if conn:
        return AzureBlobStorage(conn, app.config["AZURE_BLOB_CONTAINER"])
    return LocalStorage(app.config["LOCAL_STORAGE_DIR"])
