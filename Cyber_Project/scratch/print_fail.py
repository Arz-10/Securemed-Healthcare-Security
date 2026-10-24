import sys
sys.path.insert(0, ".")
import unittest

loader = unittest.TestLoader()
suite = loader.loadTestsFromName("test_security_harness")
runner = unittest.TextTestRunner(verbosity=0)
res = runner.run(suite)
for f in res.failures:
    print("FAILED TEST:", f[0].id())
    print("EXCEPTION:")
    print(f[1])
