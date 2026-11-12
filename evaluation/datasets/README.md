# Evaluation dataset

`CICIDS2017_sample.csv` is a 56,661-row public sample of the CICIDS2017
flow dataset. It was downloaded from the GitHub mirror below because this
project's `data_extractor.py` already maps CICIDS2017's 78-column CSV into the
NIDS 18-feature format.

- Sample file: <https://github.com/NirmalaKTomar/CICIDS2017_Sample_dataset>
- Original dataset page and citation: <https://www.unb.ca/cic/datasets/ids-2017.html>
- CICIDS2017 evaluation output: `../results/cicids2017_sample_holdout.json`

`CSE-CIC-IDS2018_Thursday-2018-03-01.csv` is the public CICFlowMeter export
for the 2018 dataset. The column names were aligned to the existing 18-feature
extractor and the model's five-class label set for a cross-dataset check.

`CSE-CIC-IDS2018_Friday-2018-03-02.csv` is a second public CICFlowMeter export
from the same release, containing benign and bot traffic. The project maps Bot
to DOS, matching its existing CICIDS2017 label mapping.

- Dataset files: <https://huggingface.co/datasets/c01dsnap/CIC-IDS2018>
- Official dataset description and citation: <https://www.unb.ca/cic/datasets/ids-2018.html>
- CICIDS2018 evaluation output: `../results/cse_cic_ids2018_external.json`
- Bot day evaluation output: `../results/cse_cic_ids2018_bot_external.json`

The test removed all rows whose extracted 18-feature vector was duplicated,
then used a stratified random 80/20 split. It trained a temporary model in
memory; it did not overwrite `models/nids_model.joblib`.
