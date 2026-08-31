# SPDX-License-Identifier: GPL-2.0-only
"""Privacy-safe offline compatibility check for copied macOS Catacombs."""

from __future__ import annotations

import os
import stat
import tarfile
from pathlib import Path
from pathlib import PurePosixPath

import t2_catacomb_codec as codec


MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256


class FixtureCheckError(ValueError):
    pass


def _caller_uid() -> int:
    sudo_uid = os.environ.get("SUDO_UID", "")
    if os.geteuid() == 0 and sudo_uid.isdecimal() and int(sudo_uid) > 0:
        return int(sudo_uid)
    return os.geteuid()


def read_components(path: Path, apple_user_id: int) -> dict[str, bytes]:
    if not 0 <= apple_user_id <= 0xFFFFFFFF:
        raise FixtureCheckError("Apple user ID is outside uint32 range")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FixtureCheckError("cannot safely open private archive") from error
    expected = {
        "master.cat",
        "biolockout.cat",
        f"user_{apple_user_id:08x}.cat",
    }
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid not in {0, _caller_uid()}
            or info.st_mode & 0o077
            or not 0 < info.st_size <= MAX_ARCHIVE_BYTES
        ):
            raise FixtureCheckError("private archive ownership, mode, or size is unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            try:
                archive = tarfile.open(fileobj=stream, mode="r:*")
            except tarfile.TarError as error:
                raise FixtureCheckError("private archive is not a readable tar file") from error
            components: dict[str, bytes] = {}
            try:
                with archive:
                    for index, member in enumerate(archive):
                        if index >= MAX_ARCHIVE_MEMBERS:
                            raise FixtureCheckError("private archive has too many members")
                        member_path = PurePosixPath(member.name)
                        name = member_path.name
                        if name not in expected:
                            continue
                        if member_path.is_absolute() or ".." in member_path.parts:
                            raise FixtureCheckError("Catacomb component path is unsafe")
                        if (
                            name in components
                            or not member.isfile()
                            or not 0 < member.size <= codec.MAX_FILE_BYTES
                        ):
                            raise FixtureCheckError("Catacomb component member is unsafe")
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            raise FixtureCheckError("Catacomb component cannot be read")
                        data = extracted.read(codec.MAX_FILE_BYTES + 1)
                        if len(data) != member.size:
                            raise FixtureCheckError(
                                "Catacomb component length is inconsistent"
                            )
                        components[name] = data
            except tarfile.TarError as error:
                raise FixtureCheckError("private archive is malformed") from error
    finally:
        os.close(descriptor)
    if set(components) != expected:
        raise FixtureCheckError("archive does not contain the exact Catacomb component set")
    return components


def check_components(components: dict[str, bytes], apple_user_id: int) -> dict[str, object]:
    if not 0 <= apple_user_id <= 0xFFFFFFFF:
        raise FixtureCheckError("Apple user ID is outside uint32 range")
    user_name = f"user_{apple_user_id:08x}.cat"
    if set(components) != {"master.cat", "biolockout.cat", user_name}:
        raise FixtureCheckError("component set does not match the selected Apple user")
    try:
        user = codec.decode_user_catacomb(components[user_name], apple_user_id)
        master = codec.decode_master_catacomb(components["master.cat"])
        biolockout = codec.decode_biolockout_catacomb(components["biolockout.cat"])

        # Re-emit the same semantics. Each encoder performs a second read with
        # t2_catacomb_oracle, which is independent of the primary graph reader.
        user_output = user.replace_secure_data(user.secure_data)
        master_output = master.encode()
        biolockout_output = biolockout.encode()
        user_round = codec.decode_user_catacomb(user_output, apple_user_id)
        master_round = codec.decode_master_catacomb(master_output)
        biolockout_round = codec.decode_biolockout_catacomb(biolockout_output)
    except codec.CatacombCodecError as error:
        raise FixtureCheckError("Catacomb fixture compatibility check failed") from error

    user_equal = (
        user.identities == user_round.identities
        and user.account_uuid == user_round.account_uuid
        and user.keybag_uuid == user_round.keybag_uuid
    )
    secure_equal = (
        user.secure_data == user_round.secure_data
        and master.secure_data == master_round.secure_data
        and biolockout.secure_data == biolockout_round.secure_data
    )
    master_equal = (
        master.enrollment_count == master_round.enrollment_count
        and master.current_time == master_round.current_time
    )
    if not user_equal or not secure_equal or not master_equal:
        raise FixtureCheckError("Catacomb semantic round trip did not reconcile")
    return {
        "schema_version": 1,
        "component_count": 3,
        "identity_count": len(user.identities),
        "original_schemas_valid": True,
        "independent_oracle_readback": True,
        "semantic_round_trip_equal": True,
        "opaque_secure_envelopes_preserved": True,
        "account_and_keybag_bindings_preserved": True,
        "binary_identity_required": False,
        "identifiers_redacted": True,
    }


def check_archive(path: Path, apple_user_id: int) -> dict[str, object]:
    return check_components(read_components(path, apple_user_id), apple_user_id)
