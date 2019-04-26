import logging
from typing import Dict, Any

import docker
import luigi

from exaslct_src.lib.build_config import build_config
from exaslct_src.lib.utils.build_context_hasher import BuildContextHasher
from exaslct_src.lib.data.dependency_collector.dependency_image_info_collector import DependencyImageInfoCollector, \
    IMAGE_INFO
from exaslct_src.lib.docker_config import docker_config
from exaslct_src.lib.docker.docker_image_builder import DockerImageBuilder
from exaslct_src.lib.docker.docker_image_target import DockerImageTarget
from exaslct_src.lib.data.image_info import ImageInfo
from exaslct_src.stoppable_task import StoppableTask


class DockerPullOrBuildImageTask(StoppableTask):
    logger = logging.getLogger('luigi-interface')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._build_config = build_config()
        self._docker_config = docker_config()
        self._image_name = self.get_image_name()
        self._image_tag = self.get_image_tag()
        self._mapping_of_build_files_and_directories = \
            self.get_mapping_of_build_files_and_directories()
        self._dockerfile = self.get_dockerfile()
        self._prepare_outputs()
        self._build_context_hasher = \
            BuildContextHasher(self.task_id,
                               self._mapping_of_build_files_and_directories,
                               self._dockerfile)
        self._image_builder = \
            DockerImageBuilder(
                self.task_id,
                self._mapping_of_build_files_and_directories,
                self._dockerfile,
                self.get_additional_docker_build_options())
        self._client = docker_config().get_client()

    def _prepare_outputs(self):
        self._image_info_target = luigi.LocalTarget(
            "%s/info/image/%s/%s"
            % (self._build_config.output_directory,
               self._image_name, self._image_tag))
        if self._image_info_target.exists():
            self._image_info_target.remove()

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
        return "latest"

    def get_mapping_of_build_files_and_directories(self) -> Dict[str, str]:
        """
        Called by the constructor to get the build files and directories mapping.
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

    def get_additional_docker_build_options(self) -> Dict[str, Any]:
        return {}

    def is_rebuild_requested(self) -> bool:
        pass

    def output(self):
        return {IMAGE_INFO: self._image_info_target}

    def run_task(self):
        image_info_of_dependencies = DependencyImageInfoCollector().get_from_dict_of_inputs(self.input())
        image_hash = self._build_context_hasher.generate_image_hash(image_info_of_dependencies)
        complete_tag = self._image_tag + "_" + image_hash
        image_target = DockerImageTarget(self._image_name, complete_tag)
        image_info = ImageInfo(
            complete_name=image_target.get_complete_name(),
            name=self._image_name, tag=self._image_tag, hash=image_hash,
            depends_on_images=list(image_info_of_dependencies.values()),
            was_pulled=None, was_build=None
        )
        was_build, was_pulled = \
            self.create_image_or_use_locally_existing(
                image_info_of_dependencies, image_target, image_info)
        image_info.was_build = was_build
        image_info.was_pulled = was_pulled
        self.write_image_info_to_output(image_info)

    def create_image_or_use_locally_existing(
            self,
            image_info_of_dependencies: Dict[str, ImageInfo],
            image_target: DockerImageTarget,
            image_info: ImageInfo):
        is_any_dependency_newly_build = \
            self.is_any_dependency_newly_build(image_info_of_dependencies)
        self.remove_image_if_requested(image_target, is_any_dependency_newly_build)
        if not image_target.exists():
            was_build, was_pulled = \
                self.pull_or_build_image(
                    image_target, image_info,
                    image_info_of_dependencies,
                    is_any_dependency_newly_build)
        else:
            was_build = False
            was_pulled = False
            self.logger.info("Task %s: Using locally existing docker images %s",
                             self.task_id, image_target.get_complete_name())
        return was_build, was_pulled

    def is_any_dependency_newly_build(self, image_info_of_dependencies: Dict[str, ImageInfo]) -> bool:
        return any(image_info.was_build for image_info
                   in image_info_of_dependencies.values())

    def remove_image_if_requested(self, image_target: DockerImageTarget,
                                  is_any_dependency_newly_build: bool):
        if self.image_removal_requested(is_any_dependency_newly_build):
            if image_target.exists():
                self._client.images.remove(image=image_target.get_complete_name(), force=True)
                self.logger.warning("Task %s: Removed docker images %s",
                                    self.task_id, image_target.get_complete_name())

    def image_removal_requested(self, is_any_dependency_newly_build: bool):
        return self.is_rebuild_requested() or \
               self._build_config.force_pull or \
               is_any_dependency_newly_build

    def pull_or_build_image(self,
                            image_target: DockerImageTarget, image_info: ImageInfo,
                            image_info_of_dependencies: Dict[str, ImageInfo],
                            is_any_dependency_newly_build: bool):
        if not self.is_rebuild_necessary(is_any_dependency_newly_build):
            was_build, was_pulled = \
                self.try_pull_or_fallback_to_build(
                    image_target, image_info,
                    image_info_of_dependencies)
        else:
            self._image_builder.build(image_info, image_info_of_dependencies)
            was_build = True
            was_pulled = False
        return was_build, was_pulled

    def is_rebuild_necessary(self, is_any_dependency_newly_build: bool):
        return is_any_dependency_newly_build or self.is_rebuild_requested()

    def try_pull_or_fallback_to_build(self,
                                      image_target: DockerImageTarget, image_info: ImageInfo,
                                      image_info_of_dependencies: Dict[str, ImageInfo]):
        was_build = False
        was_pulled = self.try_pull(image_target)
        if not was_pulled:
            self._image_builder.build(image_info, image_info_of_dependencies)
            was_build = True
        return was_build, was_pulled

    def try_pull(self, image_target: DockerImageTarget):
        try:
            self._pull_image(image_target)
            return True
        except Exception as e:
            self.logger.warning("Task %s: Could not pull image %s, got exception %s", self.task_id,
                                image_target.get_complete_name(), e)
            return False

    def _pull_image(self, image_target: DockerImageTarget):
        self.logger.info("Task %s: Try to pull docker image %s", self.task_id, image_target.get_complete_name())
        if self._docker_config.username is not None and \
                self._docker_config.password is not None:
            auth_config = {
                "username": self._docker_config.username,
                "password": self._docker_config.password
            }
        else:
            auth_config = None
        self._client.images.pull(repository=image_target.image_name, tag=image_target.image_tag,
                                 auth_config=auth_config)

    def _is_image_in_registry(self, image_target: DockerImageTarget):
        try:
            self.logger.info("Task %s: Try to pull image %s", self.task_id,
                             image_target.get_complete_name())
            registry_data = self._pull_image(image_target)
            return True
        except docker.errors.APIError as e:
            self.logger.warning("Task %s: Image %s not in registry, got exception %s", self.task_id,
                                image_target.get_complete_name(), e)
            return False

    def write_image_info_to_output(self, image_info: ImageInfo):
        with  self.output()[IMAGE_INFO].open("wt") as file:
            file.write(image_info.to_json())
