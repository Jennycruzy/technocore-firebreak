import tomllib
import unittest
from pathlib import Path

import firebreak


class MetadataTests(unittest.TestCase):
    def test_package_versions_match(self):
        project = tomllib.loads(
            Path(__file__).parent.parent.joinpath("pyproject.toml").read_text()
        )
        self.assertEqual(project["project"]["version"], firebreak.__version__)


if __name__ == "__main__":
    unittest.main()
