import getpass
import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Tuple

import luigi
import networkx
from networkx import MultiDiGraph, DiGraph

from exaslct_src.stoppable_task import StoppableTask
from exaslct_src.task_dependency import TaskDependency, DependencyState


def set_build_config(force_rebuild: bool,
                     force_rebuild_from: Tuple[str, ...],
                     force_pull: bool,
                     log_build_context_content: bool,
                     output_directory: str,
                     temporary_base_directory: str):
    luigi.configuration.get_config().set('build_config', 'force_rebuild', str(force_rebuild))
    luigi.configuration.get_config().set('build_config', 'force_rebuild_from', json.dumps(force_rebuild_from))
    luigi.configuration.get_config().set('build_config', 'force_pull', str(force_pull))
    set_output_directory(output_directory)
    if temporary_base_directory is not None:
        luigi.configuration.get_config().set('build_config', 'temporary_base_directory', temporary_base_directory)
    luigi.configuration.get_config().set('build_config', 'log_build_context_content', str(log_build_context_content))


def set_output_directory(output_directory):
    if output_directory is not None:
        luigi.configuration.get_config().set('build_config', 'output_directory', output_directory)


def set_docker_config(docker_base_url, docker_password, docker_repository_name, docker_username):
    if docker_base_url is not None:
        luigi.configuration.get_config().set('docker_config', 'base_url', docker_base_url)
    if docker_repository_name is not None:
        luigi.configuration.get_config().set('docker_config', 'repository_name', docker_repository_name)
    if docker_username is not None:
        if docker_password is not None:
            luigi.configuration.get_config().set('docker_config', 'username', docker_username)
            luigi.configuration.get_config().set('docker_config', 'password', docker_password)
        else:
            password = getpass.getpass("Docker Registry Password for User %s:" % docker_username)
            luigi.configuration.get_config().set('docker_config', 'username', docker_username)
            luigi.configuration.get_config().set('docker_config', 'password', password)


# TODO add watchdog, which uploads the logs after given ammount of time, to get logs before travis kills the job
def run_tasks(tasks_creator: Callable[[], List[luigi.Task]],
              workers: int, task_dependencies_dot_file: str,
              on_success: Callable[[], None] = None,
              on_failure: Callable[[], None] = None):
    setup_worker()
    start_time = datetime.now()
    tasks = remove_stoppable_task_targets(tasks_creator)
    no_scheduling_errors = luigi.build(tasks, workers=workers, local_scheduler=True, log_level="INFO")
    if StoppableTask().failed_target.exists() or not no_scheduling_errors:
        handle_failure(on_failure)
    else:
        handle_success(on_success, task_dependencies_dot_file, start_time)


def handle_success(on_success: Callable[[], None], task_dependencies_dot_file: str, start_time: datetime):
    generate_graph_from_task_dependencies(task_dependencies_dot_file)
    if on_success is not None:
        on_success()
    timedelta = datetime.now() - start_time
    print("The command took %s s" % timedelta.total_seconds())
    exit(0)


def generate_graph_from_task_dependencies(task_dependencies_dot_file: str):
    if task_dependencies_dot_file is not None:
        print(f"Generate Task Dependency Graph to {task_dependencies_dot_file}")
        print()
        dependencies = collect_dependencies()
        g = DiGraph()
        for dependency in dependencies:
            g.add_node(dependency.source, label=dependency.source.representation)
            g.add_node(dependency.target, label=dependency.target.representation)
            g.add_edge(dependency.source, dependency.target,
                       dependency=dependency,
                       label=f"\"type={dependency.type.name}, index={dependency.index}\"")
        networkx.nx_pydot.write_dot(g, task_dependencies_dot_file)


def collect_dependencies():
    stoppable_task = StoppableTask()
    dependencies = set()
    for root, directories, files in os.walk(stoppable_task.dependencies_dir):
        for file in files:
            file_path = Path(root).joinpath(file)
            with open(file_path) as f:
                for line in f.readlines():
                    task_dependency = TaskDependency.from_json(line)
                    if task_dependency.state == DependencyState.requested:
                        dependencies.add(task_dependency)
    return dependencies


def handle_failure(on_failure: Callable[[], None]):
    if on_failure is not None:
        on_failure()
    exit(1)


def remove_stoppable_task_targets(tasks_creator):
    stoppable_task = StoppableTask()
    if stoppable_task.failed_target.exists():
        stoppable_task.failed_target.remove()
    if stoppable_task.timers_dir.exists():
        shutil.rmtree(str(stoppable_task.timers_dir))
    if stoppable_task.dependencies_dir.exists():
        shutil.rmtree(str(stoppable_task.dependencies_dir))
    tasks = tasks_creator()
    return tasks


def setup_worker():
    luigi.configuration.get_config().set('worker', 'wait_interval', str(0.1))
    luigi.configuration.get_config().set('worker', 'wait_jitter', str(0.5))


def add_options(options):
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func

    return _add_options
