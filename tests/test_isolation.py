import unittest

from firebreak.errors import ProtocolError
from firebreak.isolation import docker_adapter_command


class IsolationTests(unittest.TestCase):
    def test_container_command_removes_ambient_capabilities(self):
        command = docker_adapter_command("technocore-firebreak-adapter:test")
        joined = " ".join(command)
        for required in (
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--pids-limit 64",
            "--memory 128m",
            "--cpus 1",
            "noexec",
            "nosuid",
        ):
            self.assertIn(required, joined)

    def test_image_reference_cannot_inject_arguments(self):
        for image in ("", "--privileged", "image name", "x\n--network=host"):
            with self.subTest(image=image), self.assertRaises(ProtocolError):
                docker_adapter_command(image)


if __name__ == "__main__":
    unittest.main()
