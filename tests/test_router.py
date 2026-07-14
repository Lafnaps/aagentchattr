import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from router import Router


class RouterMentionTests(unittest.TestCase):
    def test_hyphenated_agent_name_is_parsed_as_full_mention(self):
        router = Router(["telegram-bridge"], default_mention="none")

        self.assertEqual(
            set(router.parse_mentions("please ask @telegram-bridge to check")),
            {"telegram-bridge"},
        )

    def test_shorter_agent_name_does_not_match_prefix_of_hyphenated_unknown(self):
        router = Router(["telegram"], default_mention="none")

        self.assertEqual(router.parse_mentions("@telegram-bridge check"), [])
        self.assertEqual(router.get_targets("ben", "@telegram-bridge check"), [])

    def test_longest_hyphenated_name_wins_when_prefix_agent_also_exists(self):
        router = Router(["telegram", "telegram-bridge"], default_mention="none")

        self.assertEqual(
            set(router.parse_mentions("@telegram-bridge check")),
            {"telegram-bridge"},
        )

    def test_unknown_exact_handle_still_does_not_route(self):
        router = Router(["telegram-bridge"], default_mention="none")

        self.assertEqual(router.parse_mentions("@telegram-bot check"), [])
        self.assertEqual(router.get_targets("ben", "@telegram-bot check"), [])


class RouterLoopGuardTests(unittest.TestCase):
    def test_positive_limit_still_pauses_after_configured_hops(self):
        router = Router(["alpha", "beta"], default_mention="none", max_hops=2)

        self.assertEqual(router.get_targets("alpha", "@beta first"), ["beta"])
        self.assertEqual(router.get_targets("alpha", "@beta second"), ["beta"])
        self.assertEqual(router.get_targets("alpha", "@beta blocked"), [])
        self.assertTrue(router.is_paused())

    def test_zero_disables_loop_guard(self):
        router = Router(["alpha", "beta"], default_mention="none", max_hops=0)

        for index in range(100):
            self.assertEqual(
                router.get_targets("alpha", f"@beta hop {index}"),
                ["beta"],
            )
        self.assertFalse(router.is_paused())

    def test_disabling_guard_releases_existing_pause_and_resets_state(self):
        router = Router(["alpha", "beta"], default_mention="none", max_hops=1)
        self.assertEqual(router.get_targets("alpha", "@beta allowed"), ["beta"])
        self.assertEqual(router.get_targets("alpha", "@beta blocked"), [])
        self.assertTrue(router.is_paused())
        router.set_guard_emitted()

        router.max_hops = 0

        self.assertFalse(router.is_paused())
        self.assertFalse(router.is_guard_emitted())
        self.assertEqual(router.get_targets("alpha", "@beta resumed"), ["beta"])

        # Re-enabling starts from a clean counter rather than the old pause.
        router.max_hops = 1
        self.assertEqual(router.get_targets("alpha", "@beta allowed again"), ["beta"])
        self.assertEqual(router.get_targets("alpha", "@beta blocked again"), [])
        self.assertTrue(router.is_paused())


if __name__ == "__main__":
    unittest.main()
