from typing import Tuple

from build_utils import ExportContainer
from build_utils.cli.cli import cli
from build_utils.cli.common import set_build_config, set_docker_config, run_tasks, add_options
from build_utils.cli.options \
    import build_options, flavor_options, docker_options, system_options


@cli.command()
@add_options(flavor_options)
@add_options(build_options)
@add_options(docker_options)
@add_options(system_options)
def export(flavor_path: Tuple[str, ...],
           release_type: str,
           force_build: bool,
           force_pull: bool,
           output_directory: str,
           temporary_base_directory: str,
           log_build_context_content: bool,
           docker_base_url: str,
           docker_repository_name: str,
           docker_username: str,
           docker_password: str,
           workers: int):
    """
    This command exports the whole script language container package of the flavor,
    ready for the upload into the bucketfs. If the stages do not exists locally,
    the system will build or pull them before the exporting the packaged container.
    """
    set_build_config(force_build, force_pull, log_build_context_content, output_directory, temporary_base_directory)
    set_docker_config(docker_base_url, docker_password, docker_repository_name, docker_username)
    tasks = [ExportContainer(flavor_paths=list(flavor_path), release_types=list([release_type]))]
    run_tasks(tasks, workers)

