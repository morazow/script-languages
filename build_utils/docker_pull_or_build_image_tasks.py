import base64
import hashlib
import os
import pathlib
import shutil
from typing import Dict

import docker
import luigi

from build_utils.directory_hasher import FileDirectoryListHasher
from build_utils.docker_image_builder import DockerImageBuilder
from build_utils.docker_image_target import DockerImageTarget


class DockerPullOrBuildImageTask(luigi.Task):
    docker_base_url = luigi.Parameter("unix:///var/run/docker.sock")
    force_pull = luigi.BoolParameter(False)
    force_build = luigi.BoolParameter(False)
    log_build_context_content = luigi.BoolParameter(False)
    dont_remove_build_context = luigi.BoolParameter(False)
    build_context_base_directory = luigi.OptionalParameter(None)
    ouput_directory = luigi.Parameter("ouput")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.image_name = self.get_image_name()
        self.image_tag = self.get_image_tag()
        self.build_directories_mapping = self.get_build_directories_mapping()
        self.dockerfile = self.get_dockerfile()
        self._client = docker.DockerClient(base_url=self.docker_base_url)
        self.image_name_target = luigi.LocalTarget("%s/image_names/%s" % (self.ouput_directory, self.image_tag))
        if self.image_name_target.exists():
            self.image_name_target.remove()
        self.log_file_path = pathlib.Path("%s/logs/%s/%s/%s/"
                                          % (self.ouput_directory,
                                             type(self).__name__,
                                             self.image_name,
                                             self.image_tag))
        if self.log_file_path.exists():
            shutil.rmtree(self.log_file_path)
        os.makedirs(self.log_file_path)

    def __del__(self):
        self._client.close()

    def get_image_name(self) -> str:
        """
        Called by the constructor to get the image name. Sub classes need to implement this method.
        :return: image name
        """
        pass

    def get_image_tag(self) -> str:
        """
        Called by the constructor to get the image tag. Sub classes need to implement this method.
        :return: image tag
        """
        pass

    def get_build_directories_mapping(self) -> Dict[str, str]:
        """
        Called by the constructor to get the build directories mapping.
        The keys are the relative paths to the destination in build context and
        the values are the paths to the source directories or files.
        Sub classes need to implement this method.
        :return: dictionaries with destination path as keys and source paths in values
        """
        pass

    def get_dockerfile(self) -> str:
        """
        Called by the constructor to get the path to the dockerfile.
        Sub classes need to implement this method.
        :return: path to the dockerfile
        """
        pass

    def _get_complete_name(self):
        complete_name = f"{self.image_name}:{self.image_tag}"
        return complete_name

    def output(self):
        return {"image_name_target": self.image_name_target}

    def run(self):
        images_names_of_dependencies = self._get_image_names_of_dependencies()
        image_hash = self._generate_image_hash(images_names_of_dependencies)
        complete_tag = self.image_tag + "_" + image_hash
        image_target = DockerImageTarget(self.image_name, complete_tag)

        output_generator = None
        if self.force_build or self.force_pull:
            if image_target.exists():
                self._client.images.remove(image=image_target.get_complete_name(),force=True)
                print(f"Removed docker images {image_target.get_complete_name()}")
        if not image_target.exists():
            if not self.force_build and self._is_image_in_registry(image_target):
                self._pull_image(image_target)
            else:
                image_builder = DockerImageBuilder(
                    self.task_id,
                    self.docker_base_url,
                    self.build_context_base_directory,
                    self.build_directories_mapping,
                    self.dockerfile,
                    self.log_build_context_content,
                    self.log_file_path
                )
                output_generator = image_builder.build(image_target, images_names_of_dependencies)
        image_name_file = self.output()["image_name_target"]
        with image_name_file.open("wt") as image_name_file:
            image_name_file.write(image_target.get_complete_name())

    def _get_image_names_of_dependencies(self) -> Dict[str, str]:
        """
        Reads from input the image names produced by dependent tasks.
        :return Dictionary with dependency keys defined by requires method and images names as values
        """
        if isinstance(self.input(), Dict):
            return {key: self.get_image_name_of_depedency(value)
                    for key, value in self.input().items()
                    if isinstance(value, Dict) and "image_name_target" in value}
        else:
            return dict()

    def get_image_name_of_depedency(self, value):
        with value["image_name_target"].open("r") as file:
            return file.read()

    def _pull_image(self, image_target: DockerImageTarget):
        print("execute pull", self.task_id)
        self._client.images.pull(image_target.get_complete_name())

    def _is_image_in_registry(self, image_target: DockerImageTarget):
        try:
            registry_data = self._client.images.get_registry_data(image_target.get_complete_name())
            return True
        except docker.errors.APIError as e:
            print("Exception while checking if image exists in registry", image_target.get_complete_name(), e)
            return False

    def _generate_image_hash(self, images_names_of_dependencies: Dict[str, str]):
        hash_of_build_context = self._generate_build_context_hash()
        final_hash = self._generate_final_hash(hash_of_build_context, images_names_of_dependencies)
        return self._encode_hash(final_hash)

    def _generate_build_context_hash(self):
        files_directories_list_hasher = \
            FileDirectoryListHasher(hashfunc="sha256",
                                    hash_file_names=True,
                                    hash_directory_names=True,
                                    hash_permissions=True)
        files_directories_to_hash = list(self.build_directories_mapping.values()) + [str(self.dockerfile)]
        hash_of_build_context = files_directories_list_hasher.hash(files_directories_to_hash)
        return hash_of_build_context

    def _generate_final_hash(self, hash_of_build_context: bytes, images_names_of_dependencies: Dict[str, str]):
        hasher = hashlib.sha256()
        for key, image_name in sorted(images_names_of_dependencies.items()):
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