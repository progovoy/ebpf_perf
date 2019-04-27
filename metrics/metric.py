import itertools
import logging
from dataclasses import dataclass
from typing import Iterable, Any, Callable

import numpy as np

LOGGER = logging.getLogger()


@dataclass()
class Dim(object):
    name: str
    value: Any


@dataclass
class Metric(object):
    name: str
    shape: Iterable[int]
    collector: Any
    stats: Iterable[Callable] = None

    def __post_init__(self):
        self._dim_names = {}
        if self.stats:
            self.stat_data = {}

    def set_dim_name(self, dim: Iterable[int], name: str):
        self._dim_names[dim] = name

    def update_dim(self, dim: Iterable[int], value):
        self.collector.update_dim(dim, value)

    def update_done(self):
        self.collector.update_done()

        if self.stats:
            std_axis = len(self.collector.shape) - 1
            for stat in self.stats:
                self.stat_data[stat] = stat(self.collector.raw_data, axis=std_axis)

    def export_stats(self):
        dims = [range(i) for i in self.shape]

        for dim in itertools.product(*dims):
            if self.stats:
                for stat in self.stats:
                    name = self._dim_names[dim] + '_' + stat.__name__
                    value = self.stat_data[stat][dim]

                    yield Dim(name=name, value=value)
            else:
                name = self._dim_names[dim]
                value = self.collector.raw_data[dim]

                yield Dim(name=name, value=value)


@dataclass
class Latest(object):
    shape: Iterable[int]

    def __post_init__(self):
        self.raw_data = np.zeros(self.shape)

    def update_dim(self, dim: Iterable[int], value):
        self.raw_data[dim] = value

    def update_done(self):
        pass


@dataclass
class SlidingWindow(object):
    shape: Iterable[int]
    window_size: int

    def __post_init__(self):
        shape_with_window = list(self.shape)
        shape_with_window.append(self.window_size)

        self.raw_data = np.zeros(shape_with_window)

        self._sample_index = 0

    def update_dim(self, dim: Iterable[int], value):
        shape_index = list(dim)
        shape_index.append(self._sample_index)
        shape_index = tuple(shape_index)

        self.raw_data[shape_index] = value

    def update_done(self):
        self._sample_index = (self._sample_index + 1) % self.window_size
