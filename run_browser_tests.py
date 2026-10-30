
import subprocess
import sys

TEST_FILES = [
    "browser_xss_tests.py",
    "browser_stored_xss_tests.py",
]

overall_success = True

for test_file in TEST_FILES:
    print(f"\nRunning {test_file}...")

    result = subprocess.run(
        [sys.executable, test_file],
        check=False
    )

    if result.returncode != 0:
        overall_success = False

if overall_success:
    print("\nAll browser tests passed.")
    sys.exit(0)

print("\nOne or more browser tests failed.")
sys.exit(1)
