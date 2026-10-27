#!/usr/bin/env python3
"""Generate the UniXNU platform-stage ADT for judyln (SDM845, LG G7 ThinQ).

Same SoC description as make-polaris-adt.py (GICv3 layout, timer PPI 19,
A55/A75 topology, upper DDR bank), only the board identity differs. The
platform kernel matches no board strings. G710EM ships 4 GiB, ending at
0x1_80000000, so polaris' 6 GiB bank value 0x7cc00000 also fits below the
top reservation here.
"""
import argparse
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('polaris_adt', ROOT / 'scripts/make-polaris-adt.py')
_polaris = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_polaris)

DRAM_BASE = _polaris.DRAM_BASE
DRAM_SIZE_4 = 0x7CC00000
SILVER_HZ = 1766400000

IDENTITY = [
    (b'polaris-platform-bringup\0', b'judyln-platform-bringup\0'),
    (b'xiaomi,polaris\0qcom,sdm845\0', b'lge,judyln\0qcom,sdm845\0'),
    (b'Mi MIX 2S\0', b'LG G7 ThinQ\0'),
    (b'xiaomi,polaris\0', b'lge,judyln\0'),
    (b'polaris-io\0', b'judyln-io\0'),
]


def build(*, cpu_count=1, dram_size=DRAM_SIZE_4, owned_memory_size=0x40000000, seed=None):
    _polaris.SILVER_HZ = SILVER_HZ
    _polaris.node = _node
    return _polaris.build(cpu_count=cpu_count, dram_size=dram_size,
                          owned_memory_size=owned_memory_size, seed=seed)


_polaris_node = _polaris.node


def _node(name, properties=(), children=()):
    mapped = []
    for key, value in properties:
        for old, new in IDENTITY:
            if value == old:
                value = new
                break
        mapped.append((key, value))
    if name == 'chosen':
        # Original AMFI (prelinked iPadOS 17) panics without it; same value as
        # UniXNU's qemu-entry/make-dt.py --amfi-platform-only.
        mapped.append(('amfi-only-platform-code', _polaris.u32(1)))
    return _polaris_node(name, mapped, children)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--owned-memory-size', type=lambda value: int(value, 0), default=0x40000000)
    parser.add_argument('--cpus', type=int, default=1)
    args = parser.parse_args()
    args.output.write_bytes(build(cpu_count=args.cpus, owned_memory_size=args.owned_memory_size))
    print(f'{args.output}: judyln platform ADT, host-generated only')


if __name__ == '__main__':
    main()
