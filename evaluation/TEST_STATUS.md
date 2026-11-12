# NIDS test status

Updated: 2026-11-04

## Latest offline test run

Command:

```powershell
python -m pytest tests -q --tb=short --disable-warnings --ignore=tests/test_live_e2e.py --ignore=tests/test_live_e2e_corrected.py --ignore=tests/test_phase1_smoke.py --ignore=tests/test_stage9_live.py
```

Result: **241 passed, 0 failed, 0 errors**. Pytest reported 158 warnings.

The prior three generator test failures were fixed by changing the test import
blocker to patch `builtins.__import__` through the `builtins` module. The prior
collection error was fixed by renaming the unused `test_scenario` helper to
`run_scenario`, so pytest no longer treats its arguments as fixtures.

## Not covered by that run

The four excluded live capture tests require packet capture and local network
activity. They were not run, so live NIC capture remains unverified.

## Dataset benchmark

The CICIDS2017 sample and the in-memory holdout benchmark are documented in
[`datasets/README.md`](datasets/README.md) and
[`results/cicids2017_sample_holdout.json`](results/cicids2017_sample_holdout.json).
That benchmark trained a temporary model and did not overwrite the saved model.

An external cross-dataset check was also run with the public CSE-CIC-IDS2018
Thursday 2018-03-01 CICFlowMeter file. After dropping 25 repeated CSV headers,
the saved model scored 68.00% accuracy and 58.46% weighted F1 on 331,100 flows.
Recall for the dataset's Infilteration label (mapped to RECONNAISSANCE) was
0.0064%; the model missed almost all such flows. This day contains only benign
and infiltration traffic. Details are in
[`results/cse_cic_ids2018_external.json`](results/cse_cic_ids2018_external.json).

A second public CSE-CIC-IDS2018 day (Friday 2018-03-02) was then evaluated in
chunks using the existing saved model. It contained 762,384 Benign and 286,191
Bot flows. After mapping Bot to DOS as the project's label mapper specifies,
the model scored 66.40% accuracy and 58.13% weighted F1; DOS recall was only
0.2484%. Details are in
[`results/cse_cic_ids2018_bot_external.json`](results/cse_cic_ids2018_bot_external.json).
The model file was not changed.

## Full-suite attempt

Running `python -m pytest tests -q` is currently blocked during collection:
`test_phase1_smoke.py` starts Scapy capture at import time, and Windows denied
capture on `\\Device\\NPF_Loopback` because the Npcap interface is in
Admin-only mode. The script then exits the pytest process. Run live capture
checks from an authorized elevated environment; the offline suite above passes.

## Ubuntu VM / Windows browser workflow

The dashboard now supports server-side capture configured with
`NIDS_CAPTURE_INTERFACE` and optional `NIDS_MODEL_PATH`, uses one shared live
source across browser sessions, refreshes live pages every two seconds, and
keeps Streamlit's CORS/XSRF protections enabled. Ubuntu setup, VirtualBox
networking, systemd, and Windows browser access are documented in
[`../deploy/ubuntu-server/README.md`](../deploy/ubuntu-server/README.md).

The app and static audit pass after these changes, and the offline suite still
passes. The actual VirtualBox bridged interface and traffic from the second
laptop could not be exercised from this Windows workspace; live capture still
needs an end-to-end check inside the VM.

## Latest workflow verification

On 2026-11-04, the offline suite passed again (**241 passed, 158 warnings**),
both `app.py` and the `dashboard.py` compatibility entry passed Streamlit's
script runner without app exceptions, the static audit passed, and a temporary
localhost Streamlit server returned HTTP 200 from `/_stcore/health`. The local
HTTP check used replay mode; it does not verify Ubuntu packet capture or
VirtualBox networking.
