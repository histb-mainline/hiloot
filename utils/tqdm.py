import sys
import time
from typing import TYPE_CHECKING, Collection, Protocol, TypeVar

if TYPE_CHECKING:
    from _typeshed import SupportsWrite, SupportsFlush

    _T_contra = TypeVar('_T_contra', contravariant=True)

    class _SupportsWriteAndFlush(
            SupportsWrite[_T_contra], SupportsFlush, Protocol[_T_contra]):
        ...


__all__ = ['tqdm']


_T = TypeVar('_T')


def tqdm(
        it: Collection[_T], prefix='', ncols=80, unit='it',
        file: '_SupportsWriteAndFlush[str] | None' = sys.stdout, **__):
    count = len(it)
    digit = len(str(count))
    start = time.time()

    try:
        for i, item in enumerate(it):
            yield item

            j = i + 1

            ratio = j / count
            elapsed = time.time() - start
            expect = elapsed * ((count - j) / j)
            elapsed_min, elapsed_sec = divmod(int(elapsed), 60)
            expect_min, expect_sec = divmod(int(expect), 60)

            head = f'{prefix}{ratio:4.0%}|'
            tail = (
                f'| {j:{digit}}/{count} [{elapsed_min:02}:{elapsed_sec:02}<'
                f'{expect_min:02}:{expect_sec:02}, {j / elapsed:.1f}{unit}/s]')

            bar_size = ncols - len(head) - len(tail)
            bar_len = int(bar_size * ratio + .5)
            print(
                '' if not i else '\r', head, '#' * bar_len,
                ' ' * (bar_size - bar_len), tail, sep='', end='', file=file,
                flush=True)
    finally:
        print(file=file)


if not TYPE_CHECKING:
    try:
        from tqdm import tqdm
    except ImportError:
        pass
