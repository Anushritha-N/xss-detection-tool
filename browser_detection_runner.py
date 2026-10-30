
import subprocess
import sys

TEST_FILES = [
    "browser_xss_tests.py",
    "browser_stored_xss_tests.py",
    "test_vulnerable_fixture.py",
    "test_remediation.py",
]

results = []

for test_file in TEST_FILES:
    print(f"\nRunning {test_file}...", flush=True)

    result = subprocess.run(
        [sys.executable, test_file],
        check=False,
    )

    status = "PASS" if result.returncode == 0 else "FAIL"
    results.append((test_file, status))

print("\n========== BROWSER DETECTION SUMMARY ==========")

for test_file, status in results:
    print(f"{status:4} | {test_file}")

passed = sum(status == "PASS" for _, status in results)
failed = len(results) - passed

print(f"\nTest scripts: {len(results)}")
print(f"Passed: {passed}")
print(f"Failed: {failed}")

sys.exit(1 if failed else 0)
