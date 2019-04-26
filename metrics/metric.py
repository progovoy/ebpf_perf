import itertools
from dataclasses import dataclass
from typing import Iterable, Callable, Any

import numpy as np


@dataclass()
class Dim(object):
    name: str
    value: Any


@dataclass
class Metric(object):
    name: str
    shape: Iterable[int]
    collection_algorithm: Callable

    def __post_init__(self):
        self._dim_names = {}

    def set_dim_name(self, dim: Iterable[int], name: str):
        self._dim_names[dim] = name

    def update_dim(self, dim: Iterable[int], value):
        self.collection_algorithm(dim, value)

    def export_dims(self):
        dims = [range(i) for i in self.shape]

        for dim in itertools.product(*dims):
            name = self._dim_names[dim]
            value = self.collection_algorithm.data[dim]

            yield Dim(name=name, value=value)


@dataclass
class Latest(object):
    shape: Iterable[int]

    def __post_init__(self):
        self.data = np.zeros(self.shape)

    def __call__(self, dim: Iterable[int], value):
        self.data[dim] = value


@dataclass
class SlidingWindow(object):
    shape: Iterable[int]
    window_size: int
    dim_calc: Callable

    def __post_init__(self):
        shape_with_window = list(self.shape)
        shape_with_window.append(self.window_size)

        self._raw_data = np.zeros(shape_with_window)
        self.data = np.ndarray(self.shape)

        self._current_sample_index = 0

    def __call__(self, dim: Iterable[int], value):
        shape_index = list(dim)
        shape_index.append(self._current_sample_index)
        shape_index = tuple(shape_index)

        self._raw_data[shape_index] = value

        self._current_sample_index = (self._current_sample_index + 1) % self.window_size

        self.data[dim] = self.dim_calc(self._raw_data[dim])
