import docker
import luigi

from build_utils.lib.build_config import build_config
from build_utils.lib.data.environment_info import EnvironmentInfo
from build_utils.lib.docker_config import docker_config


class PopulateData(luigi.Task):
    test_environment_info_dict = luigi.DictParameter()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._docker_config = docker_config()
        self._client = docker.DockerClient(base_url=self._docker_config.base_url)
        self._build_config = build_config()
        test_environment_info = EnvironmentInfo.from_dict(self.test_environment_info_dict)
        self._test_container_info = test_environment_info.test_container_info
        self._database_info = test_environment_info.database_info
        self._prepare_outputs()

    def _prepare_outputs(self):
        self._log_target = luigi.LocalTarget(
            "%s/logs/test-runner/db-test/populate_data/%s/%s"
            % (self._build_config.ouput_directory,
               self._test_container_info.container_name,
               self.task_id))
        if self._log_target.exists():
            self._log_target.remove()

    def output(self):
        return self._log_target

    def run(self):
        username = "sys"
        password = "exasol"
        test_container = self._client.containers.get(self._test_container_info.container_name)
        cmd = f"""cd /tests/test/enginedb_small; $EXAPLUS -c '{self._database_info.host}:{self._database_info.db_port}' -u '{username}' -p '{password}' -f import.sql"""
        bash_cmd = f"""bash -c "{cmd}" """
        exit_code, output = test_container.exec_run(cmd=bash_cmd)
        print(output.decode("utf-8"))
        self.write_logs(output)
        if exit_code != 0:
            raise Exception("Failed to populate the database with data.\nLog: %s" % cmd + "\n" + output.decode("utf-8"))

    def write_logs(self, output):
        with self._log_target.open("w") as file:
            file.write(output.decode("utf-8"))
