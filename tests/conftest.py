import fnmatch
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hardenaudit.context import Context  # noqa: E402


class FakeContext(Context):
    """Contexto en memoria: archivos, comandos y stats simulados."""

    def __init__(self, files=None, commands=None, stats=None, env=None,
                 root=True, online=False):
        super().__init__(online=online)
        self.is_root = root
        self.files = files or {}
        self.commands = commands or {}
        self.stats = stats or {}
        self.env = env or {}

    def run(self, argv, timeout=30):
        return self.commands.get(" ".join(argv))

    def read(self, path):
        return self.files.get(path)

    def exists(self, path):
        return path in self.files or path in self.stats

    def stat(self, path):
        return self.stats.get(path)

    def glob(self, pattern):
        return sorted(p for p in self.files if fnmatch.fnmatch(p, pattern))

    def getenv(self, name):
        return self.env.get(name)


def ids(findings):
    return [f.id for f in findings]
