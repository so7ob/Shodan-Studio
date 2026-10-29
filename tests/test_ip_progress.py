import unittest
from pathlib import Path
import sys

from studio.ip_progress import calculate_ip_progress, attach_ip_progress, progress_from_job


class IPProgressTests(unittest.TestCase):
    def test_source_reference_does_not_fabricate_a_distinct_ip_estimate(self):
        job={'status':'running','stats':{'unique_ips':100,'source_total_records':579},
             '_ip_progress_inputs':{'planning_complete':False,'branches':[]}}
        value=progress_from_job(job)
        self.assertEqual(value['source_record_reference'],{'total_records':579,'progress_percent':17})
        self.assertIsNone(value['progress_percent'])
        self.assertIsNone(value['estimated_total_ips'])
        self.assertEqual(job['stats']['unique_ips'],100)
        for total in [None,False,0,-1,'579',1.5,9007199254740992]:
            job['stats']['source_total_records']=total
            self.assertIsNone(progress_from_job(job)['source_record_reference'])
        job['stats']['source_total_records']=80
        self.assertEqual(progress_from_job(job)['source_record_reference']['progress_percent'],99)

    def make(self, **changes):
        params = dict(extracted_unique_ips=512, branches=[
            {"expected_records": 270, "processed_records": 0, "status": "pending"},
            {"expected_records": 530, "completed": True},
        ], planning_complete=True, job_status="running")
        params.update(changes)
        return calculate_ip_progress(**params)

    def test_requested_example_estimate(self):
        value = self.make()
        self.assertEqual(value["extracted_unique_ips"], 512)
        self.assertEqual(value["estimated_total_ips"], 782)
        self.assertEqual(value["remaining_estimated_ips"], 270)
        self.assertEqual(value["progress_percent"], 65)
        self.assertTrue(value["is_estimate"])

    def test_finished_not_double_counted(self):
        self.assertEqual(self.make()["remaining_leaves"], 1)
        self.assertEqual(self.make()["remaining_estimated_ips"], 270)

    def test_only_successful_processed_rows_reduce_remaining(self):
        value = self.make(branches=[{"expected_records": 100, "processed_records": 70, "status": "running"}])
        self.assertEqual(value["remaining_estimated_ips"], 30)

    def test_prior_dedup_yield_ratio(self):
        value = self.make(successfully_processed_records=1024)
        self.assertLess(value["remaining_estimated_ips"], 270)
        self.assertGreaterEqual(value["estimated_total_ips"], 512)
        self.assertEqual(value["yield_basis"], "observed_dedup_ratio")

    def test_percent_unknown_during_planning(self):
        value = self.make(planning_complete=False)
        self.assertIsNone(value["progress_percent"])
        self.assertIsNone(value["estimated_total_ips"])

    def test_unknown_count_must_not_appear_complete(self):
        value = self.make(branches=[{"expected_records": None, "status": "pending"}])
        self.assertIsNone(value["progress_percent"])
        self.assertEqual(value["unknown_remaining_leaves"], 1)

    def test_completed_100_even_when_no_ip(self):
        value = self.make(extracted_unique_ips=0,
                          branches=[{"expected_records": 0, "status": "done"}], job_status="completed")
        self.assertEqual(value["progress_percent"], 100)
        self.assertEqual(value["estimated_total_ips"], 0)

    def test_paused_is_never_100(self):
        value = self.make(branches=[{"expected_records": 5, "status": "done"}], job_status="paused")
        self.assertEqual(value["progress_percent"], 99)

    def test_failed_is_not_complete(self):
        value = self.make(branches=[{"expected_records": 5, "status": "failed"}], job_status="failed")
        self.assertLess(value["progress_percent"], 100)

    def test_no_completed_job_without_all_leaves(self):
        value = self.make(job_status="completed")
        self.assertLess(value["progress_percent"], 100)

    def test_zero_pending_zero_extracted_before_completion(self):
        value = self.make(extracted_unique_ips=0,
                          branches=[{"expected_records": 0, "status": "done"}], job_status="running")
        self.assertEqual(value["progress_percent"], 0)

    def test_no_leaves_is_unknown_while_running(self):
        value = self.make(branches=[])
        self.assertIsNone(value["progress_percent"])

    def test_no_negative_remaining_after_changed_count(self):
        value = self.make(branches=[{"expected_records": 10, "processed_records": 50, "status": "running"}])
        self.assertEqual(value["remaining_estimated_ips"], 0)

    def test_strings_supported_from_sql_json(self):
        value = self.make(extracted_unique_ips="512", branches=[{"expected_records": "270", "status": "pending"}])
        self.assertEqual(value["estimated_total_ips"], 782)

    def test_bad_values_rejected(self):
        for bad in (-1, True, 1.5, "-2", "nan"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.make(extracted_unique_ips=bad)

    def test_adapter_does_not_break_legacy_branch_progress(self):
        existing = {"id": "job-1", "unique_ips": 512, "status": "running", "progress_percent": 21}
        merged = attach_ip_progress(existing, branches=[{"expected_records": 270}], planning_complete=True)
        self.assertEqual(merged["progress_percent"], 21)
        self.assertEqual(merged["ip_progress"]["progress_percent"], 65)
        self.assertNotIn("ip_progress", existing)

    def test_ratio_floor(self):
        value = self.make(extracted_unique_ips=1, successfully_processed_records=10_000,
                          branches=[{"expected_records": 1000}])
        self.assertEqual(value["remaining_estimated_ips"], 50)

    def test_duplicate_leaves_not_added_to_unique_num(self):
        value = self.make(branches=[{"expected_records": 10}, {"expected_records": 10}])
        self.assertEqual(value["extracted_unique_ips"], 512)
        self.assertEqual(value["estimated_total_ips"], 532)

    def test_empty_unknown_unresolved(self):
        value = self.make(branches=[{"status": "failed"}])
        self.assertEqual(value["calculation_mode"], "unknown_unresolved_branches")

    def test_unknown_finished_count_not_blocking(self):
        value = self.make(branches=[{"status": "done", "expected_records": None},
                                          {"status": "running", "expected_records": 10}])
        self.assertEqual(value["remaining_estimated_ips"], 10)
        self.assertEqual(value["unknown_remaining_leaves"], 0)


if __name__ == "__main__":
    unittest.main()
