"""Typed structures for classified disk data."""

from __future__ import annotations

from typing import TypedDict


class DiskBase(TypedDict):
    kind: str
    e01: str
    raw: str


class MdDisk(DiskBase):
    uuid: str
    level: int
    layout: int
    chunk_sectors: int
    raid_disks: int
    data_offset_sectors: int
    data_size_sectors: int
    dev_number: int
    role: int
    sb_byte_offset: int
    partition_byte_offset: int


class LdmDisk(DiskBase):
    disk_group_guid: str
    per_disk_guid: str | None


class StandaloneDisk(DiskBase):
    fs_offset: int
    fs_type: str | None


class UnknownDisk(DiskBase):
    pass


type ClassifiedDisk = MdDisk | LdmDisk | StandaloneDisk | UnknownDisk


class HwOverrides(TypedDict, total=False):
    level: int | None
    stripe: int | None
    offset: int | None
    order: list[str] | None


class PartitionEntry(TypedDict):
    start: int
    end: int
    length: int
    desc: str
