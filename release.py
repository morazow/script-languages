import subprocess

if __name__ == '__main__':
    command = "luigi --log-level INFO --local-scheduler --workers 5 " \
              "--module build_utils ReleaseContainer " \
              "--docker-config-repository exasol/script-language-container " \
              "--flavor-path build_utils/test/resources/test-flavor/"
    p=subprocess.Popen(args=command.split(" "))
    p.communicate()