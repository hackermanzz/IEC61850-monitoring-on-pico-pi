"""Foundation-only checks: production kernel memory/stack code and target interfaces."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
tests = root / 'testing/host'
with tempfile.TemporaryDirectory(prefix='iec-foundation-host-') as tmp:
    for name in ('kernel_heap', 'stack_diagnostics'):
        exe = Path(tmp) / name
        flags = ['-DUSE_TASK_STACK_DIAG=1', '-DPICO_RP2040'] if name == 'stack_diagnostics' else []
        subprocess.run(['gcc', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Wno-sign-compare',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', *flags,
                        '-I' + str(tests / 'heap_stubs'), '-I' + str(root / 'include'),
                        '-I' + str(root / 'kernel/tkernel'), str(tests / ('test_' + name + '.c')),
                        str(root / 'kernel/tkernel/memory.c'), str(root / 'lib/libtk/kmalloc.c'),
                        '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
    for smp in (0, 1):
        subprocess.run(['arm-none-eabi-gcc', '-std=gnu11', '-mcpu=cortex-m0plus', '-mthumb',
                        '-ffreestanding', '-Wall', '-Wextra', '-Werror', '-fsyntax-only',
                        '-D_PICO_RP2040_', '-DCNF_SMP=' + str(smp),
                        '-I' + str(root), '-I' + str(root / 'include'), '-I' + str(root / 'config'),
                        str(tests / 'test_interfaces.c')], check=True)
    print('Foundation target interfaces: UP/SMP header closure, frame ABI and copied record/ACK contracts PASS')
print('Foundation checks PASS; application subsystem behavior is not implemented or tested here.')
