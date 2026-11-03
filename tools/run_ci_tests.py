"""Run the normal unittest suite and expose failures as GitHub check annotations."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def escape_annotation(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


class AnnotatedResult(unittest.TextTestResult):
    def annotate(self, test, error):
        message = self._exc_info_to_string(error, test)[-6000:]
        title = escape_annotation(test.id()).replace(",", "%2C").replace(":", "%3A")
        print(f"::error title={title}::{escape_annotation(message)}", flush=True)

    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.annotate(test, error)

    def addError(self, test, error):
        super().addError(test, error)
        self.annotate(test, error)

    def addSubTest(self, test, subtest, error):
        super().addSubTest(test, subtest, error)
        if error is not None:
            self.annotate(subtest, error)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2, resultclass=AnnotatedResult).run(
        suite
    )
    raise SystemExit(0 if result.wasSuccessful() else 1)
