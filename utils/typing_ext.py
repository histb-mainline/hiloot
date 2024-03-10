from typing import *


__all__ = [
    'Buffer', 'LengthBuffer', 'ByteLike', 'Slicable',
]


@runtime_checkable
class Buffer(Protocol):
    def __buffer__(self, __flags: int) -> memoryview: ...


@runtime_checkable
class LengthBuffer(Protocol):
    def __buffer__(self, __flags: int) -> memoryview: ...

    def __len__(self) -> int: ...


ByteLike = Iterable[SupportsIndex] | SupportsIndex | SupportsBytes | Buffer


Slicable = TypeVar('Slicable', bound='_Slicable')


class _Slicable(Protocol):
    def __getitem__(self: Slicable, i: slice) -> Slicable: ...
