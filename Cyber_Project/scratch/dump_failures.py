import unittest
import traceback

loader = unittest.TestLoader()
suite = loader.discover(".", pattern="test_phase3_suite.py")
runner = unittest.TextTestRunner(verbosity=1)
result = runner.run(suite)

with open("scratch/failures.txt", "w") as f:
    f.write(f"Total: {result.testsRun}, Errors: {len(result.errors)}, Failures: {len(result.failures)}\n\n")
    for test, err in result.failures:
        f.write(f"--- FAILURE: {test} ---\n{err}\n\n")
    for test, err in result.errors:
        f.write(f"--- ERROR: {test} ---\n{err}\n\n")
