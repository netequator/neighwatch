"""Unit tests for sliding window rate counter and cooldown."""

from __future__ import annotations

from neighwatch.window import SlidingWindowCounter


def test_window_counter_basic_threshold() -> None:
    counter = SlidingWindowCounter(window_sec=10.0)
    # Threshold 3 events within 10s
    c1, trig1, cool1 = counter.record("key1", 100.0, 3)
    assert (c1, trig1, cool1) == (1, False, False)

    c2, trig2, cool2 = counter.record("key1", 102.0, 3)
    assert (c2, trig2, cool2) == (2, False, False)

    c3, trig3, cool3 = counter.record("key1", 104.0, 3)
    assert (c3, trig3, cool3) == (3, True, False)


def test_window_counter_cooldown() -> None:
    counter = SlidingWindowCounter(window_sec=10.0)
    counter.record("key1", 100.0, 2)
    _, trig, cool = counter.record("key1", 101.0, 2)
    assert trig is True
    assert cool is False

    # Immediate follow-up packet within window -> in cooldown
    c3, trig3, cool3 = counter.record("key1", 103.0, 2)
    assert trig3 is False
    assert cool3 is True
    assert c3 == 3

    # Packet after window expires -> triggers new alert
    c4, trig4, cool4 = counter.record("key1", 112.0, 2)
    # Since earlier timestamps (100, 101, 103) fell out of window (112 - 10 = 102, so only 103 remains)
    assert c4 == 2  # 103 and 112
    assert trig4 is True
    assert cool4 is False


def test_window_counter_sliding_eviction() -> None:
    counter = SlidingWindowCounter(window_sec=5.0)
    counter.record("k", 10.0, 3)
    counter.record("k", 12.0, 3)
    # At t=18, events at 10 and 12 are outside 5s window
    c, trig, _cool = counter.record("k", 18.0, 3)
    assert c == 1
    assert not trig


def test_window_counter_disabled() -> None:
    counter = SlidingWindowCounter(window_sec=0.0)
    c, trig, cool = counter.record("k", 10.0, 5)
    assert (c, trig, cool) == (0, False, False)

    c2, trig2, cool2 = counter.record("k", 10.0, 0)
    assert (c2, trig2, cool2) == (0, False, False)
