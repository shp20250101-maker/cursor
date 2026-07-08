#!/usr/bin/env python3
"""임의의 숫자 n개를 입력받아 오름차순으로 정렬하는 프로그램.

비교 기반 정렬 알고리즘 중 시간 복잡도가 가장 빠른 세 가지를 사용한다.

+------------+------------------+------------------+------------------+-----------+
| 알고리즘   | 최선             | 평균             | 최악             | 공간      |
+------------+------------------+------------------+------------------+-----------+
| 병합 정렬  | O(n log n)       | O(n log n)       | O(n log n)       | O(n)      |
| 힙 정렬    | O(n log n)       | O(n log n)       | O(n log n)       | O(1)      |
| 퀵 정렬    | O(n log n)       | O(n log n)       | O(n^2)*          | O(log n)  |
+------------+------------------+------------------+------------------+-----------+
* 퀵 정렬은 무작위 피벗을 사용하므로 최악의 경우가 발생할 확률은 사실상 0에
  가깝고, 평균적으로는 세 알고리즘 중 가장 빠르다.

비교 기반 정렬의 이론적 하한이 Ω(n log n)이므로, 위 세 알고리즘이
시간 복잡도 기준으로 가장 빠른 축에 속한다. (버블/선택/삽입 정렬은 O(n^2))

사용법:
    python sorting/sort_numbers.py            # 대화형 입력
    echo "5
    3.1 -2 10 0 7" | python sorting/sort_numbers.py --algorithm merge

입력 형식:
    첫 줄: 자연수 n (숫자의 개수)
    다음:  공백/줄바꿈으로 구분된 숫자 n개 (정수 또는 실수)
"""

from __future__ import annotations

import argparse
import random
import sys
from typing import Callable, List


# ---------------------------------------------------------------------------
# 1. 병합 정렬 (Merge Sort) — 최악에도 O(n log n), 안정 정렬
# ---------------------------------------------------------------------------
def merge_sort(nums: List[float]) -> List[float]:
    if len(nums) <= 1:
        return list(nums)

    mid = len(nums) // 2
    left = merge_sort(nums[:mid])
    right = merge_sort(nums[mid:])

    merged: List[float] = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            merged.append(left[i])
            i += 1
        else:
            merged.append(right[j])
            j += 1
    merged.extend(left[i:])
    merged.extend(right[j:])
    return merged


# ---------------------------------------------------------------------------
# 2. 힙 정렬 (Heap Sort) — 최악에도 O(n log n), 추가 메모리 O(1)
# ---------------------------------------------------------------------------
def heap_sort(nums: List[float]) -> List[float]:
    result = list(nums)
    n = len(result)

    def sift_down(start: int, end: int) -> None:
        """result[start:end+1]에서 start를 루트로 하는 최대 힙 속성 복구."""
        root = start
        while True:
            child = 2 * root + 1
            if child > end:
                break
            if child + 1 <= end and result[child] < result[child + 1]:
                child += 1
            if result[root] < result[child]:
                result[root], result[child] = result[child], result[root]
                root = child
            else:
                break

    # 최대 힙 구성: O(n)
    for start in range(n // 2 - 1, -1, -1):
        sift_down(start, n - 1)

    # 최댓값을 뒤로 보내며 힙 크기를 줄임: O(n log n)
    for end in range(n - 1, 0, -1):
        result[0], result[end] = result[end], result[0]
        sift_down(0, end - 1)

    return result


# ---------------------------------------------------------------------------
# 3. 퀵 정렬 (Quick Sort) — 평균 O(n log n), 무작위 피벗으로 최악 경우 회피
# ---------------------------------------------------------------------------
def quick_sort(nums: List[float]) -> List[float]:
    result = list(nums)
    _quick_sort_inplace(result, 0, len(result) - 1)
    return result


def _quick_sort_inplace(arr: List[float], low: int, high: int) -> None:
    # 재귀 대신 반복 + 작은 쪽 먼저 처리로 스택 깊이를 O(log n)으로 제한
    while low < high:
        pivot_index = _partition(arr, low, high)
        if pivot_index - low < high - pivot_index:
            _quick_sort_inplace(arr, low, pivot_index - 1)
            low = pivot_index + 1
        else:
            _quick_sort_inplace(arr, pivot_index + 1, high)
            high = pivot_index - 1


def _partition(arr: List[float], low: int, high: int) -> int:
    rand = random.randint(low, high)
    arr[rand], arr[high] = arr[high], arr[rand]
    pivot = arr[high]

    i = low - 1
    for j in range(low, high):
        if arr[j] <= pivot:
            i += 1
            arr[i], arr[j] = arr[j], arr[i]
    arr[i + 1], arr[high] = arr[high], arr[i + 1]
    return i + 1


ALGORITHMS: dict[str, Callable[[List[float]], List[float]]] = {
    "merge": merge_sort,
    "heap": heap_sort,
    "quick": quick_sort,
}


# ---------------------------------------------------------------------------
# 입출력
# ---------------------------------------------------------------------------
def parse_number(token: str) -> float:
    """정수는 int로, 실수는 float로 파싱한다."""
    try:
        return int(token)
    except ValueError:
        return float(token)


def read_input(stream) -> List[float]:
    tokens = stream.read().split()
    if not tokens:
        raise ValueError("입력이 비어 있습니다. 첫 줄에 n, 이어서 숫자 n개를 입력하세요.")

    try:
        n = int(tokens[0])
    except ValueError:
        raise ValueError(f"첫 번째 값은 자연수 n이어야 합니다: {tokens[0]!r}")
    if n < 1:
        raise ValueError(f"n은 자연수(1 이상)여야 합니다: {n}")

    values = tokens[1:]
    if len(values) != n:
        raise ValueError(f"숫자 {n}개가 필요하지만 {len(values)}개가 입력되었습니다.")

    try:
        return [parse_number(v) for v in values]
    except ValueError as exc:
        raise ValueError(f"숫자가 아닌 값이 포함되어 있습니다: {exc}")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="숫자 n개를 입력받아 오름차순으로 정렬합니다.",
        epilog="입력 형식 — 첫 줄: n, 다음: 숫자 n개 (공백/줄바꿈 구분)",
    )
    parser.add_argument(
        "--algorithm",
        "-a",
        choices=sorted(ALGORITHMS) + ["all"],
        default="all",
        help="사용할 정렬 알고리즘 (기본값: all, 세 알고리즘 모두 실행)",
    )
    args = parser.parse_args(argv)

    if sys.stdin.isatty():
        print("첫 줄에 n, 이어서 숫자 n개를 입력하세요 (입력 후 Ctrl-D):")

    try:
        numbers = read_input(sys.stdin)
    except ValueError as exc:
        print(f"입력 오류: {exc}", file=sys.stderr)
        return 1

    selected = sorted(ALGORITHMS) if args.algorithm == "all" else [args.algorithm]
    names = {"merge": "병합 정렬", "heap": "힙 정렬", "quick": "퀵 정렬"}

    for key in selected:
        sorted_numbers = ALGORITHMS[key](numbers)
        print(f"[{names[key]}] {' '.join(str(x) for x in sorted_numbers)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
