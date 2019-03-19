from typing import Dict

from build_utils.lib.data.database_info import DatabaseInfo
from build_utils.lib.data.release_info import ReleaseInfo
from build_utils.lib.data.dependency_collector.dependency_collector import DependencyInfoCollector


class DependencyDatabaseInfoCollector(DependencyInfoCollector[DatabaseInfo]):

    def is_info(self, input):
        return isinstance(input, Dict) and DATABASE_INFO in input

    def read_info(self, value) -> DatabaseInfo:
        with value[DATABASE_INFO].open("r") as file:
            return ReleaseInfo.from_json(file.read())


DATABASE_INFO = "database_info"
