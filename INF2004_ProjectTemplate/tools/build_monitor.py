"""Run a target build with a durable log and compact output (inside WSL/Linux)."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
log_dir = root / 'testing' / 'build_logs'
log_dir.mkdir(parents=True, exist_ok=True)
options = sys.argv[1:]
name = '_'.join(arg.replace('=', '-') for arg in options if not arg.startswith('PICO_SDK_PATH=')) or 'default'
log = log_dir / (name + '.log')
with log.open('w') as output:
    result = subprocess.run(['make', '-j8', *options], cwd=root / 'build_make',
                            stdout=output, stderr=subprocess.STDOUT)
lines = log.read_text(errors='replace').splitlines()
problems = [line for line in lines if len(line) < 1000 and
            ('error:' in line or 'warning:' in line or 'undefined reference' in line or 'Stop.' in line)]
for line in problems[-30:]:
    print(line)
for line in lines[-7:]:
    if len(line) < 1000:
        print(line)
print(f'Build exit={result.returncode}; log={log}')
sys.exit(result.returncode)
