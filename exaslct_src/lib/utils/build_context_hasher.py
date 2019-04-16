import base64
import hashlib
from typing import Dict

from exaslct_src.lib.utils.directory_hasher import FileDirectoryListHasher
from exaslct_src.lib.data.image_info import ImageInfo


class BuildContextHasher:

    def __init__(self, task_id, build_directories_mapping: Dict[str, str], dockerfile: str):
        self.task_id = task_id
        self.dockerfile = dockerfile
        self.build_directories_mapping = build_directories_mapping

    def generate_image_hash(self, image_info_of_dependencies: Dict[str, ImageInfo]):
        hash_of_build_context = self._generate_build_context_hash()
        final_hash = self._generate_final_hash(hash_of_build_context, image_info_of_dependencies)
        return self._encode_hash(final_hash)

    def _generate_build_context_hash(self):
        files_directories_list_hasher = \
            FileDirectoryListHasher(hashfunc="sha256",
                                    hash_file_names=True,
                                    hash_directory_names=True,
                                    hash_permissions=False)
        files_directories_to_hash = list(self.build_directories_mapping.values()) + [str(self.dockerfile)]
        print(self.task_id,"files_directories_list_hasher", files_directories_to_hash)
        hash_of_build_context = files_directories_list_hasher.hash(files_directories_to_hash)
        print(self.task_id,"hash_of_build_context", self._encode_hash(hash_of_build_context))
        return hash_of_build_context

    def _generate_final_hash(self, hash_of_build_context: bytes, image_info_of_dependencies: Dict[str, ImageInfo]):
        hashes_of_dependencies = \
            [(key, image_info.hash) for key, image_info in image_info_of_dependencies.items()]
        hasher = hashlib.sha256()
        hashes_to_hash = sorted(hashes_of_dependencies, key=lambda t: t[0])
        print(self.task_id,"hashes_to_hash", hashes_to_hash)
        for key, image_name in hashes_to_hash:
            hasher.update(key.encode("utf-8"))
            hasher.update(image_name.encode("utf-8"))
        hasher.update(hash_of_build_context)
        final_hash = hasher.digest()
        return final_hash

    def _encode_hash(self, hash_of_build_directory):
        base32 = base64.b32encode(hash_of_build_directory)
        ascii = base32.decode("ASCII")
        trim = ascii.replace("=", "")
        return trim
