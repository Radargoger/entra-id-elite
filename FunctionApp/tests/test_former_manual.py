"""apply_manual + reconcile-union etkileşimi birim testleri.

Kritik senaryo: elle eklenen former kaydı, timer reconcile'ında formül onu
istemese bile SİLİNMEMELİ (manual store union'ı). Azure'a gidilmez, her şey
fake/mock.

Çalıştırma: python3 tests/test_former_manual.py  (FunctionApp kökünden)
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# azure importlarını stub'la
azure_pkg = types.ModuleType("azure")
tables_mod = types.ModuleType("azure.data.tables")
tables_mod.TableServiceClient = object
tables_mod.TableEntity = dict
core_mod = types.ModuleType("azure.core.exceptions")
core_mod.ResourceNotFoundError = type("ResourceNotFoundError", (Exception,), {})
core_mod.ResourceExistsError = type("ResourceExistsError", (Exception,), {})
sys.modules.setdefault("azure", azure_pkg)
sys.modules["azure.data.tables"] = tables_mod
sys.modules["azure.core.exceptions"] = core_mod

from actions.former_manual import apply_manual


class FakeStore:
    def __init__(self):
        self.data = set()

    def get_set(self):
        return set(self.data)

    def add(self, emails):
        self.data |= set(emails)
        return len(emails)

    def remove(self, emails):
        n = len(self.data & set(emails))
        self.data -= set(emails)
        return n


class FakeClient:
    """SOCRadar listesi simülasyonu (mock client ile aynı semantik)."""

    def __init__(self, push_fails=False):
        self.listed = set()
        self.add_calls = []
        self.push_fails = push_fails  # yanlış actor email simülasyonu

    def get_list(self):
        return set(self.listed)

    def add(self, emails, source):
        self.add_calls.append((list(emails), source))
        if self.push_fails:
            return 0
        self.listed |= set(emails)
        return len(emails)

    def remove(self, emails):
        n = len(self.listed & set(emails))
        self.listed -= set(emails)
        return n


def reconcile(formula_desired, store, client):
    """function_app.former_employee_sync'in çekirdek diff mantığının kopyası:
    desired = formül ∪ manual; add/remove diff'i uygulanır."""
    desired = set(formula_desired) | store.get_set()
    current = client.get_list()
    client.add(sorted(desired - current), source="elite-sync")
    client.remove(sorted(current - desired))
    return desired


class TestApplyManual(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        self.client = FakeClient()

    def test_add_persists_and_pushes(self):
        r = apply_manual("add", ["Ali@X.com", "ali@x.com", "bozuk-email"], self.store, self.client)
        self.assertEqual(r["accepted"], ["ali@x.com"])  # lowercase + dedup
        self.assertEqual(r["invalid"], ["bozuk-email"])
        self.assertEqual(self.store.data, {"ali@x.com"})
        self.assertEqual(self.client.listed, {"ali@x.com"})
        self.assertEqual(self.client.add_calls[0][1], "manual")  # source etiketi

    def test_manual_entry_survives_reconcile(self):
        # Analist elle ekledi; formül bu email'i İSTEMİYOR
        apply_manual("add", ["gidici@firma.com"], self.store, self.client)
        # Timer tick: formül boş küme istiyor
        reconcile(set(), self.store, self.client)
        # M-CLOBBER OLMAMALI: manuel kayıt listede kalır
        self.assertIn("gidici@firma.com", self.client.get_list())

    def test_without_store_union_would_clobber(self):
        # Kontrast testi: union OLMASAYDI silinirdi (tasarım gerekçesinin kanıtı)
        self.client.add(["gidici@firma.com"], source="manual")
        desired = set()  # formül istemiyor, manual union YOK
        current = self.client.get_list()
        self.client.remove(sorted(current - desired))
        self.assertNotIn("gidici@firma.com", self.client.get_list())

    def test_manual_remove_then_formula_readds(self):
        # Formül birini former istiyor, analist elle çıkardı -> sonraki tick geri ekler
        formula = {"eski@firma.com"}
        reconcile(formula, self.store, self.client)
        apply_manual("remove", ["eski@firma.com"], self.store, self.client)
        self.assertNotIn("eski@firma.com", self.client.get_list())
        reconcile(formula, self.store, self.client)  # politika kazanır
        self.assertIn("eski@firma.com", self.client.get_list())

    def test_remove_clears_store_and_list(self):
        apply_manual("add", ["a@x.com", "b@x.com"], self.store, self.client)
        r = apply_manual("remove", ["a@x.com"], self.store, self.client)
        self.assertEqual(r["stored"], 1)
        self.assertEqual(self.store.data, {"b@x.com"})
        self.assertEqual(self.client.listed, {"b@x.com"})

    def test_invalid_action_raises(self):
        with self.assertRaises(ValueError):
            apply_manual("purge", ["a@x.com"], self.store, self.client)

    def test_all_invalid_emails(self):
        r = apply_manual("add", ["yok", "", "  "], self.store, self.client)
        self.assertEqual(r["accepted"], [])
        self.assertEqual(len(r["invalid"]), 3)
        self.assertEqual(r["note"], "no valid emails")
        self.assertEqual(self.client.listed, set())

    def test_reconcile_mixed_manual_and_formula(self):
        # Formül A'yı, analist B'yi istiyor; ikisi de listede olmalı, C silinmeli
        self.client.listed = {"c@x.com"}
        apply_manual("add", ["b@x.com"], self.store, self.client)
        desired = reconcile({"a@x.com"}, self.store, self.client)
        self.assertEqual(desired, {"a@x.com", "b@x.com"})
        self.assertEqual(self.client.get_list(), {"a@x.com", "b@x.com"})

    # ---- Adversary bulgularından türetilen testler (Q4 + Q6) ----

    def test_q4_hostile_inputs_rejected(self):
        # Adversary'nin geçirdiği girdilerin HEPSİ artık invalid olmalı
        hostile = [
            "a@b",                    # TLD yok
            "a@@b.com",               # çift @
            "a@b,c@d.com",            # virgülle birleşik
            "a@b\tc.com",             # iç tab (RowKey'i patlatırdı)
            "a@b\nc.com",             # iç newline
            "x" * 1500 + "@y.com",    # 254 üstü
            "<script>@x.com",         # RFC dışı karakterler
        ]
        r = apply_manual("add", hostile, self.store, self.client)
        self.assertEqual(r["accepted"], [])
        self.assertEqual(len(r["invalid"]), len(hostile))
        self.assertEqual(self.store.data, set())

    def test_q6_push_failure_note_is_honest(self):
        # Yanlış actor email: SOCRadar push 0 döner ama store'a yazılır.
        # Not YALAN söylememeli, retry bilgisini vermeli.
        failing = FakeClient(push_fails=True)
        r = apply_manual("add", ["ali@x.com"], self.store, failing)
        self.assertEqual(r["stored"], 1)
        self.assertEqual(r["pushed"], 0)
        self.assertIn("push incomplete", r["note"])
        self.assertIn("FORMER_ACTOR_EMAIL", r["note"])
        # store'da durduğu için sonraki reconcile push'u tekrar dener (self-healing)
        healthy = FakeClient()
        reconcile(set(), self.store, healthy)
        self.assertIn("ali@x.com", healthy.get_list())

    def test_q6_success_note_unchanged(self):
        r = apply_manual("add", ["ali@x.com"], self.store, self.client)
        self.assertIn("added to manual store and SOCRadar list", r["note"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
