import json

import docker
import luigi

from build_utils.build_config import build_config
from build_utils.docker_config import docker_config
from build_utils.image_dependency_collector import ImageDependencyCollector


class DockerPushImageTask(luigi.Task):
    flavor_path = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._docker_config = docker_config()
        self._build_config = build_config()
        self._client = docker.DockerClient(base_url=self._docker_config.base_url)
        self._prepare_outputs()

    def __del__(self):
        self._client.close()

    def _prepare_outputs(self):
        self._log_target = luigi.LocalTarget(
            "%s/logs/docker-push/%s"
            % (self._build_config.ouput_directory, self.task_id))
        if self._log_target.exists():
            self._log_target.remove()

    def output(self):
        return self._log_target

    def requires(self):
        return self.get_docker_image_task(self.flavor_path)

    def get_docker_image_task(self, flavor_path):
        pass

    def run(self):
        image_info = ImageDependencyCollector().get_image_info_of_dependency(self.input())
        generator = self._client.images.push(repository=image_info.name, tag=image_info.tag + "_" + image_info.hash,
                                             auth_config={
                                                 "username": self._docker_config.username,
                                                 "password": self._docker_config.password
                                             },
                                             stream=True)
        self._handle_output(generator, image_info.complete_name)

    def _handle_output(self, output_generator, complete_name):
        with self._log_target.open("w") as log_file:
            error = False
            error_message = None
            complete_log = []
            for log_line in output_generator:
                error, error_message = self.handle_log_line(complete_log, error, error_message, log_file, log_line)
        if self._build_config.log_to_stdout:
            self.logger.info("Task %s: Build Log of image %s\n%s",
                             self._task_id,
                             complete_name,
                             "\n".join(complete_log))
        if error:
            raise Exception(
                "Error occured during the push of the image %s. Received error \"%s\" ."
                "The whole log can be found in %s"
                % (complete_name, error_message, self._log_target.path))

    def handle_log_line(self, complete_log, error, error_message, log_file, log_line):
        log_line = log_line.decode("utf-8")
        log_line = log_line.strip('\r\n')
        json_output = json.loads(log_line)
        if "status" in json_output and json_output["status"] != "Pushing":
            complete_log.append(log_line)
            log_file.write(log_line)
            log_file.write("\n")
        if 'errorDetail' in json_output:
            error = True
            error_message = json_output["errorDetail"]["message"]
        return error, error_message
