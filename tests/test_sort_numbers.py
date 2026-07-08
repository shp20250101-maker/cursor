"""sorting/sort_numbers.py 정렬 알고리즘 테스트."""

import io
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sorting"))

from sort_numbers import ALGORITHMS, heap_sort, merge_sort, quick_sort, read_input


CASES = [
    [],
    [1],
    [2, 1],
    [3, 1, 2],
    [5, 4, 3, 2, 1],
    [1, 2, 3, 4, 5],
    [7, 7, 7],
    [3, -1, 0, -5, 2],
    [1.5, -2.5, 0.0, 1.5],
]


@pytest.mark.parametrize("algorithm", sorted(ALGORITHMS))
@pytest.mark.parametrize("case", CASES, ids=repr)
def test_matches_builtin_sorted(algorithm, case):
    assert ALGORITHMS[algorithm](case) == sorted(case)


@pytest.mark.parametrize("algorithm", [merge_sort, heap_sort, quick_sort])
def test_random_large_input(algorithm):
    rng = random.Random(42)
    nums = [rng.randint(-10**6, 10**6) for _ in range(5000)]
    assert algorithm(nums) == sorted(nums)


@pytest.mark.parametrize("algorithm", [merge_sort, heap_sort, quick_sort])
def test_does_not_mutate_input(algorithm):
    nums = [3, 1, 2]
    original = list(nums)
    algorithm(nums)
    assert nums == original


def test_read_input_valid():
    assert read_input(io.StringIO("3\n5 1 3")) == [5, 1, 3]
    assert read_input(io.StringIO("2\n1.5\n-2")) == [1.5, -2]


@pytest.mark.parametrize(
    "text",
    ["", "abc\n1 2", "0\n", "3\n1 2", "2\n1 x"],
    ids=["empty", "non-int-n", "n-zero", "too-few", "non-number"],
)
def test_read_input_invalid(text):
    with pytest.raises(ValueError):
        read_input(io.StringIO(text))
