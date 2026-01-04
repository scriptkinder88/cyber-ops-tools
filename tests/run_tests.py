import importlib
import sys
from pathlib import Path

# ensure repo root on sys.path for test imports
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))

mod = importlib.import_module('tests.test_azure_csv_pretty')

failed = 0
for name in dir(mod):
    if name.startswith('test_'):
        func = getattr(mod, name)
        try:
            # some tests expect pytest fixtures; our tests use simple functions
            if callable(func):
                func()
            print(f'OK: {name}')
        except AssertionError as e:
            print(f'FAIL: {name} - {e}')
            failed += 1
        except Exception as e:
            print(f'ERROR: {name} - {e}')
            failed += 1

if failed:
    print(f'Failing tests: {failed}')
    sys.exit(1)
print('All tests passed')
