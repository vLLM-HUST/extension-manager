"""Real temp-parent SGID tests, source only: not imported or run here."""
import os
import stat
import tempfile
import unittest
from pathlib import Path
from experiments.formal_campaign.h3_observer_paths import (
    create_private_directory,require_or_create_private_directory)


class PrivateDirectoryTests(unittest.TestCase):
    def test_fresh_child_under_real_2770_parent_is_exact700(self):
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td)/'evidence';parent.mkdir();parent.chmod(0o2770)
            old=parent.stat();child=parent/'run'
            create_private_directory(child)
            self.assertEqual(stat.S_IMODE(child.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode),0o2770)
            self.assertEqual((old.st_dev,old.st_ino),(parent.stat().st_dev,parent.stat().st_ino))

    def test_all_new_intermediate_parents_clear_inherited_sgid(self):
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td);parent.chmod(0o2770)
            leaf=parent/'new-packet'/'slot'/'native'
            create_private_directory(leaf,parents=True)
            for path in (parent/'new-packet',parent/'new-packet/slot',leaf):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode),0o2770)

    def test_existing2700_is_rejected_without_chmod(self):
        with tempfile.TemporaryDirectory() as td:
            existing=Path(td)/'external';existing.mkdir();existing.chmod(0o2700)
            with self.assertRaises(ValueError):require_or_create_private_directory(existing)
            self.assertEqual(stat.S_IMODE(existing.stat().st_mode),0o2700)
            with self.assertRaises(FileExistsError):create_private_directory(existing)
            self.assertEqual(stat.S_IMODE(existing.stat().st_mode),0o2700)

    def test_symlink_component_cannot_change_external_target(self):
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td);external=parent/'external';external.mkdir();external.chmod(0o2770)
            alias=parent/'alias';alias.symlink_to(external,target_is_directory=True)
            with self.assertRaises(ValueError):create_private_directory(alias/'run',parents=True)
            self.assertFalse((external/'run').exists())
            self.assertEqual(stat.S_IMODE(external.stat().st_mode),0o2770)
