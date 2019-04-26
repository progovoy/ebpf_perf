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

    _dim_names = {}

    def __post_init__(self):
        self._std_matrix = np.ndarray(self.shape)

    def set_dim_name(self, dim: Iterable[int], name: str):
        self._dim_names[dim] = name

    def update_dim(self, dim: Iterable[int], value):
        self.collection_algorithm(dim, value)

        std_axis = len(self.collection_algorithm.shape) - 1
        self._std_matrix = np.std(self.collection_algorithm.data, axis=std_axis)

    def export_dims(self):
        dims = [range(i) for i in self.shape]
        for dim in itertools.product(*dims):
            # export standard deviation for each dimension
            yield Dim(name=self._dim_names[dim] + '_std', value=self._std_matrix[dim])


@dataclass
class SlidingWindow(object):
    shape: Iterable[int]
    window_size: int

    def __post_init__(self):
        shape_with_window = list(self.shape)
        shape_with_window.append(self.window_size)

        self.data = np.zeros(shape_with_window)

        self._current_sample_index = 0

    def __call__(self, dim: Iterable[int], value):
        shape_index = list(dim)
        shape_index.append(self._current_sample_index)

        self.data[shape_index] = value

        self._current_sample_index = (self._current_sample_index + 1) % self.window_size
