"""Immutable evidence storage, independent of database and vendor SDKs.

Local directories must be owned by the service account. A hostile OS user with
write access to those directories is outside this API's trust boundary.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Protocol

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_key(key: str) -> str:
    if not re.fullmatch(r'[0-9a-f]{64}', key):
        raise ValueError('Evidence key must be a SHA-256 digest')
    return key


class EvidenceStore(Protocol):
    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...


class LocalEvidenceStore:
    def __init__(self, root: str | Path):
        root = Path(root).absolute()
        if any(p.is_symlink() for p in [root, *root.parents]):
            raise ValueError('Symlink evidence roots are not permitted')
        root.mkdir(parents=True, exist_ok=True)
        self.root = root

    def _path(self, key):
        path = self.root / validate_key(key)
        if any(p.is_symlink() for p in [path, self.root, *self.root.parents]):
            raise ValueError('Symlink evidence paths are not permitted')
        return path

    def put(self, key, data):
        if len(data) > MAX_ARTIFACT_BYTES or digest(data) != validate_key(key):
            raise ValueError('Invalid evidence payload or size')
        path = self._path(key)
        # Serialize writers; publish a complete temporary file atomically below.
        from .orchestration import _evidence_lock
        lock = path.with_suffix('.lock')
        if lock.is_symlink():
            raise ValueError('Symlink lock is not permitted')
        with _evidence_lock(path):
            if path.exists():
                if self.get(key) != data:
                    raise ValueError('Existing evidence failed integrity verification')
                return
            fd, temporary = tempfile.mkstemp(prefix=".artifact-", dir=self.root)
            try:
                with os.fdopen(fd, 'wb') as output:
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
                # Hard-link publication is atomic and refuses to overwrite a key.
                os.link(temporary, path)
            finally:
                Path(temporary).unlink(missing_ok=True)

    def get(self, key):
        path = self._path(key)
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError('Evidence must be a regular file')
            data = source.read(MAX_ARTIFACT_BYTES + 1)
        if len(data) > MAX_ARTIFACT_BYTES:
            raise ValueError('Evidence exceeds maximum artifact size')
        return data


class S3EvidenceStore:
    """SDK injected by the adapter; requires conditional PutObject support."""
    def __init__(self, client, bucket: str, prefix='socmind-evidence/'):
        self.client, self.bucket, self.prefix = client, bucket, prefix.rstrip('/') + '/'

    def put(self, key, data):
        if len(data) > MAX_ARTIFACT_BYTES or digest(data) != validate_key(key):
            raise ValueError('Invalid evidence payload or size')
        try:
            self.client.put_object(Bucket=self.bucket, Key=self.prefix + key, Body=data,
                                   IfNoneMatch='*', Metadata={'sha256': key})
        except Exception as exc:
            code = getattr(exc, 'response', {}).get('Error', {}).get('Code')
            if code not in {'PreconditionFailed', '412'}:
                raise
            if self.get(key) != data:
                raise ValueError('Existing evidence failed integrity verification') from exc

    def get(self, key):
        validate_key(key)
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=self.prefix + key)
        except Exception as exc:
            code = getattr(exc, 'response', {}).get('Error', {}).get('Code')
            if code in {'NoSuchKey', '404', 'NotFound'}:
                raise FileNotFoundError('Evidence object is missing') from exc
            raise OSError('Evidence object could not be retrieved') from exc
        body = response['Body']
        try:
            data = body.read(MAX_ARTIFACT_BYTES + 1)
        finally:
            body.close()
        if len(data) > MAX_ARTIFACT_BYTES:
            raise ValueError('Evidence exceeds maximum artifact size')
        return data


def configured_store(*, directory=None, bucket=None, endpoint=None, prefix='socmind-evidence/'):
    """Boto3 is confined to this optional adapter factory; credentials use its normal chain."""
    if bucket:
        from urllib.parse import urlparse
        if endpoint and urlparse(endpoint).scheme != 'https':
            raise ValueError('Object storage endpoint must use HTTPS')
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("S3 support requires pip install 'socmind[storage]'") from exc
        return S3EvidenceStore(boto3.client('s3', endpoint_url=endpoint), bucket, prefix)
    if directory is None:
        raise ValueError('An evidence directory or S3 bucket is required')
    return LocalEvidenceStore(directory)
