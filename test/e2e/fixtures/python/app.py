import subprocess


def synthetic_handler(value):
    # Safe fixture marker: this function is never executed by the tests.
    return subprocess.run(value, shell=True, check=False, capture_output=True, text=True)
