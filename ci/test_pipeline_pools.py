#!/usr/bin/env python3

import re
import unittest
from pathlib import Path


CI_DIR = Path(__file__).parent
JOB_PATTERN = re.compile(r"^      - job: (\w+)$", re.MULTILINE)
HETZNER_POOL = "        pool:\n          name: hetzner-incus"
INCUS_PREPARE = "          - template: templates/incus_prepare.yaml"


def load_job_blocks(pipeline_name):
    pipeline = (CI_DIR / pipeline_name).read_text()
    matches = list(JOB_PATTERN.finditer(pipeline))
    return {
        match.group(1): pipeline[
            match.start() : matches[index + 1].start()
            if index + 1 < len(matches)
            else len(pipeline)
        ]
        for index, match in enumerate(matches)
    }


class FuzzPipelinePoolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jobs = load_job_blocks("run_fuzz_pipeline.yaml")

    def test_qwp_egress_linux_fuzz_uses_hetzner(self):
        hosted_job = self.jobs["TestQwpEgressFuzz"]
        self.assertNotIn("            linux:", hosted_job)
        self.assertIn("            mac:", hosted_job)
        self.assertIn("            windows-2022:", hosted_job)

        linux_job = self.jobs["TestQwpEgressFuzzLinux"]
        self.assertIn(HETZNER_POOL, linux_job)
        self.assertIn("          imageName: hetzner-incus", linux_job)
        self.assertIn(INCUS_PREPARE, linux_job)

    def test_qwp_egress_live_server_fuzz_uses_hetzner(self):
        job = self.jobs["TestQwpEgressLiveServerFuzz"]
        self.assertIn(HETZNER_POOL, job)
        self.assertIn("          imageName: hetzner-incus", job)
        self.assertIn(INCUS_PREPARE, job)
        self.assertNotIn("api.adoptium.net", job)

    def test_slack_notification_uses_hetzner(self):
        job = self.jobs["NotifyOnFailure"]
        self.assertIn(HETZNER_POOL, job)
        self.assertIn("          - TestQwpEgressFuzzLinux", job)


class PullRequestPipelinePoolTest(unittest.TestCase):
    def test_pr_pipeline_has_no_microsoft_hosted_linux_jobs(self):
        jobs = load_job_blocks("run_tests_pipeline.yaml")
        hosted_linux_jobs = [
            name for name, job in jobs.items() if "ubuntu-latest" in job
        ]
        self.assertEqual([], hosted_linux_jobs)
        for name in ("VersionMatrix", "RustMsrvAndDocs"):
            self.assertIn(HETZNER_POOL, jobs[name])
            self.assertIn(INCUS_PREPARE, jobs[name])


if __name__ == "__main__":
    unittest.main()
