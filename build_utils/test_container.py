import luigi

from build_utils import ReleaseContainer
from build_utils.docker_build import DockerBuild_Release, DockerBuild_BaseTestBuildRun, DockerBuild_FlavorTestBuildRun
from build_utils.lib.flavor_task import FlavorWrapperTask
from build_utils.lib.test_runner.test_runner_db_test_task import TestRunnerDBTestTask
from build_utils.release_container import ReleaseContainer_BaseTest, ReleaseContainer_FlavorTest, \
    ReleaseContainer_Release
from build_utils.release_type import ReleaseType


class TestContainer_Release(TestRunnerDBTestTask):
    def get_release_task(self, flavor_path):
        return ReleaseContainer_Release(flavor_path=flavor_path)

    def get_release_type(self):
        return ReleaseType.Release


class TestContainer_BaseTest(TestRunnerDBTestTask):
    def get_release_task(self, flavor_path):
        return ReleaseContainer_BaseTest(flavor_path=flavor_path)

    def get_release_type(self):
        return ReleaseType.BaseTest


class TestContainer_FlavorTest(TestRunnerDBTestTask):
    def get_release_task(self, flavor_path):
        return ReleaseContainer_FlavorTest(flavor_path=flavor_path)

    def get_release_type(self):
        return ReleaseType.FlavorTest


class TestContainer(FlavorWrapperTask):

    release_types = luigi.ListParameter(["Release"])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.actual_release_types = [ReleaseType[release_type] for release_type in self.release_types]

    def requires(self):
        return [self.generate_tasks_for_flavor(flavor_path) for flavor_path in self.actual_flavor_paths]

    def generate_tasks_for_flavor(self, flavor_path):
        result = []
        if ReleaseType.Release in self.actual_release_types:
            result.append(TestContainer_Release(flavor_path=flavor_path))
        if ReleaseType.BaseTest in self.actual_release_types:
            result.append(TestContainer_BaseTest(flavor_path=flavor_path))
        if ReleaseType.FlavorTest in self.actual_release_types:
            result.append(TestContainer_FlavorTest(flavor_path=flavor_path))
        return result
