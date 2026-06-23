"""Tests for the desktop entry helpers (main.py). The pywebview window itself
isn't unit-tested (it needs a display); these cover the testable plumbing."""

import os

import main


def test_free_port_is_usable():
    p = main.free_port()
    assert isinstance(p, int) and 0 < p < 65536


def test_single_instance_lock_is_exclusive():
    s1 = main.single_instance_lock(49533)
    assert s1 is not None
    s2 = main.single_instance_lock(49533)      # second instance can't grab it
    assert s2 is None
    s1.close()
    s3 = main.single_instance_lock(49533)      # released -> available again
    assert s3 is not None
    s3.close()


def test_data_dir_exists_and_named():
    d = main.data_dir()
    assert os.path.isdir(d) and "securitysight" in d
