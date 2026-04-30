# From Red Flags to Detection Rules

## An LLM-driven Pipeline for Real-Time GOOSE Intrusion Detection and Prevention

**Authors:** Lucas A. Martins¹, Camilla B. Quincozes¹², Silvio E. Quincozes¹²  
¹ Universidade Federal de Uberlândia (UFU) – Uberlândia, Brazil  
² Universidade Federal do Pampa (UNIPAMPA) – Alegrete, Brazil  

`{lucas.martins, camillaquincozes, sequincozes, gsiervo}@ufu.br`

`{marceloluizelli}@unipampa.edu.br`

---

## Artifact Badges

This repository complies with the following artifact evaluation badges:

| Badge | Status | Description |
|:---|:---:|:---|
| **Available (D)** | Source code, notebook, and sample data are publicly available in this repository. |
| **Functional (F)** | The notebook can be executed from start to finish (requires Groq API key). |
| **Sustainable (S)** | Modular structure, fixed dependencies in `requirements.txt`, clear documentation. |
| **Reproducible (R)** | Fixed random seeds (`random_state=42`) and step-by-step documentation for experiment reproduction. |

---

## Overview

This repository accompanies the proof-of-concept notebook submitted to **SBRC 2026**. The work presents an **LLM-driven pipeline** that automates the generation of intrusion detection rules for IEC 61850 digital substations using the **GOOSE** protocol.

The approach removes the need for domain experts to write rules by hand: given labeled samples from the ERENO dataset, an LLM identifies behavioral *red flags* and translates them into executable Python rules. Those rules are then evaluated inside a programmable switch simulator for real-time detection.

---

## Problem Statement

Specification-based Intrusion Detection Systems (IDS) are widely adopted in IEC 61850 substations due to their **low computational overhead** and **interpretability**. However, they rely on rules written manually by domain experts — a costly, hard-to-scale, and poorly adaptable process.

The GOOSE protocol, in particular, was not designed with robust native security mechanisms, making it vulnerable to:

- **Denial-of-Service (DoS)** / *poisoned_high_rate*
- **Message Injection** (*masquerade_fake_fault*)
- **Replay attacks** (*inverse_replay*)
- **Grayhole**

---

## Pipeline

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐
│  Labeled GOOSE  │───▶│ Red Flag Extract.│───▶│  Rule Generation  │───▶│ Switch Simulation│
│  Dataset        │     │  (LLM-based)     │     │  (Python rules)   │     │  (Real-time)     │
│  (ERENO)        │     │                  │     │                   │     │                  │
└─────────────────┘     └──────────────────┘     └───────────────────┘     └──────────────────┘
```


| Stage | Responsibility |
|-------|----------------|
| **1. Source Ingestion** | Loads the ERENO dataset, selects relevant features, and prepares structured prompts |
| **2. Red Flag Extraction** | LLM inspects normal and attack samples to identify suspicious patterns |
| **3. Rule Generation** | Translates red flags into executable Python functions (`rules.py`) |
| **4. Simulated Deployment** | Applies the rules over GOOSE traffic in a programmable switch simulator |

---

## Dataset

The pipeline uses the **ERENO–IEC–61850** dataset, a public collection of labeled GOOSE traffic samples under normal conditions and various attack scenarios.

### Training Dataset (`train.csv`)

Used by the LLM to identify red flags and generate detection rules:

- **Samples:** 207
- **Original features:** 52 columns (15 used in the LLM prompt)
- **Classes:** 9 types (1 normal + 8 attacks)

### Full Evaluation Dataset (`ERENO-2.0-100K.csv`)

Used to execute and validate the generated rules:

- **Samples:** 200,052 rows (199,998 after type cleaning)
- **Classes:** 9 distinct types

| Class | Type | Samples |
|---|---:|---:|
| `normal` | Legitimate traffic | 39,999 |
| `grayhole` | Attack | 19,999 |
| `high_StNum` | Attack | 20,000 |
| `injection` | Attack | 20,000 |
| `inverse_replay` | Attack | 20,000 |
| `masquerade_fake_fault` | Attack | 20,000 |
| `masquerade_fake_normal` | Attack | 20,000 |
| `poisoned_high_rate` | Attack | 20,000 |
| `random_replay` | Attack | 20,000 |

### Features Used in the Prompt

The LLM generates rules based on the following 15 features (derived from the original dataset columns):

| Category | Features |
|---|---|
| Protocol-level | `SqNum`, `StNum`, `cbStatus`, `goID` |
| Temporal | `timestampDiff`, `tDiff`, `timeFromLastChange`, `delay` |
| Derived (differences) | `stDiff`, `sqDiff`, `gooseLengthDiff`, `cbStatusDiff`, `apduSizeDiff`, `frameLengthDiff` |
| Label (reference only) | `class` — not used in rules, only to distinguish normal from attack behavior |

> **Note:** The `class` column is used exclusively for the LLM to differentiate normal from attack samples. It is **not** used inside the generated detection functions.

---

## Repository Structure


```
.
├── SBRC_2026_LLM_IDS_GOOSE.ipynb # Main notebook (proof of concept)
├── small_dataset/
│ ├── train.csv # Training dataset – 207 samples, 52 features
│ └── ERENO-2.0-100K.csv # Full test dataset – 200,052 samples, 9 classes
├── rules.py # Clean detection rules generated by the LLM
├── rules.py.bak # Original LLM output (rules with markdown)
├── old_rules/ # Previous versions of generated rules (.bak files)
├── red_flags.json # Red flags extracted per attack class
├── matriz_regras_ataques.csv # Rule × attack class trigger-count matrix
├── matriz_regras_ataques_plot.png # Stacked horizontal bar chart of the matrix
├── deteccoes_por_amostra.csv # Per-sample detection flags (all 200,052 rows)
├── deteccoes_agregado_classes.csv # Total detections per attack class
├── latencia_regras.csv # Per-rule execution latency (in µs)
├── detection_results.csv # BLOCK/ALLOW decisions for each sample
├── confusion_matrix.csv # Confusion matrix per class (TP, FP, TN, FN)
├── requirements.txt # Python dependencies (pinned versions)
├── .env.example # Template for GROQ_API_KEY
├── LICENSE # MIT License
└── .gitignore # Git ignore rules
```
---

##  Experimental Infrastructure

The experiments described in the paper were conducted on the following setup:

| Component | Specification |
|---|---|
| **Operating System** | Ubuntu 24.04.2 LTS (64-bit) |
| **CPU** | Intel® Core™ i7-1360P (16 cores @ 2.20 GHz) |
| **RAM** | 32 GB DDR5 |
| **Python** | 3.14.3 (CPython) |
| **GPU** | Not required — all inference is performed via Groq Cloud API |
| **LLM Model** | `groq/compound` (accessed via Groq API key) |

> **Note:** The pipeline uses cloud-based LLM inference. No local GPU is needed. A stable internet connection is required to call the Groq API.

---

## Requirements

- Python 3.12+
- A [Groq](https://console.groq.com) account and API key (with access to the `compound` model)

### Main dependencies

```
numpy==2.3.3
pandas==2.3.3
groq==1.1.2
python-dotenv==1.0.0
httpx==0.28.1
pydantic>=1.9.0
```


---

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd <folder>

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## Configuration

Create a `.env` file at the project root with your Groq API key:

```
GROQ_API_KEY=gsk_...
```

> **Warning:** never commit the `.env` file. Add it to `.gitignore`.

---

## Usage Instructions

### Step-by-Step Commands

Follow these commands in order to reproduce the full experiment:

```bash
# 1. Clone the repository
git clone https://github.com/lucastuxnet/SBRC_2026.git
cd SBRC_2026

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API key
cp .env.example .env
# Edit .env and add your Groq API key: GROQ_API_KEY=gsk_...

# 5. Launch the notebook
jupyter notebook SBRC_2026_LLM_IDS_GOOSE.ipynb
```

---

Minimal Test
To verify that the environment is correctly configured, run:

```
python -c "import pandas, groq; print('Dependencies OK')"
```

---

## Running the Notebook

Open the notebook in Jupyter or VSCode and run the cells in order:

```bash
jupyter notebook SBRC_2026_LLM_IDS_GOOSE.ipynb
```

| Section | What it does |
|---------|--------------|
| **§4 – Setup** | Installs dependencies, imports libraries, and configures Groq client |
| **§5 – Data Ingestion** | Loads the ERENO dataset, selects relevant features, and displays class distribution |
| **§6 – Red Flag Extraction** | Extracts red flags via LLM from normal and attack samples |
| **§6.1 – Red Flag Extraction** | Identifies behavioral patterns for each attack class |
| **§6.2 – Rule Generation** | Translates red flags into Python detection functions (`rules.py`) |
| **§7 – Rule Execution** | Applies generated rules to GOOSE traffic and registers results |
| **§8 – Matrix Generation** | Generates confusion matrix and evaluation metrics |
| **§8.1 – Simplified Pipeline** | Linear version for quick rule-class matrix generation |
| **§8.2 – Complete Pipeline** | Structured pipeline with BLOCK/ALLOW decision and latency measurement |
| **§8.3 – Visual Matrix** | Generates bar chart visualization of rule-class matrix |

---

### Expected Execution Time & Resources

All measurements were taken on the infrastructure described above.

| Stage | Approximate Time | Notes |
|---|---|---|
| **Setup + Data Loading (§4–§5)** | < 5 seconds | Installs dependencies (if needed) and loads CSV |
| **Red Flag Extraction (§6.1)** | 2–5 minutes | Depends on Groq API rate limits (8 attack classes × API calls) |
| **Rule Generation (§6.2)** | 3–8 minutes | May trigger rate-limit retries with exponential backoff |
| **Rule Execution + Matrix (§7–§8)** | 10–30 seconds | 29 rules applied to 200,052 samples |
| **Visual Matrix (§8.3)** | < 3 seconds | Generates `matriz_regras_ataques_plot.png` |
| **Total (typical)** | **5–15 minutes** | Varies with Groq API availability |

### Resource Usage

| Metric | Peak Value |
|---|---|
| **Memory (RAM)** | ~1.2 GB |
| **Disk (outputs)** | ~50 MB for all generated CSVs and plots |
| **Network** | ~100 KB per LLM API call (prompt + response) |
| **GPU** | Not used |

> **If rate-limited by Groq**, the notebook uses exponential backoff and will retry automatically up to 5 times per call.

---

## Generated Outputs & Artifacts

After running the complete notebook, the following files will be created in the project root:

| File | Description | Format |
|---|---|---|
| `red_flags.json` | Red flags identified by the LLM for each attack class | JSON |
| `rules.py` | Clean detection rules (Python functions) | Python |
| `rules.py.bak` | Original LLM output before cleaning | Python |
| `matriz_regras_ataques.csv` | Trigger-count matrix: rules × attack classes | CSV |
| `matriz_regras_ataques_plot.png` | Stacked horizontal bar chart of the matrix | PNG |
| `deteccoes_por_amostra.csv` | Per-sample detection flags (200,052 rows) | CSV |
| `deteccoes_agregado_classes.csv` | Total detections per attack class | CSV |
| `latencia_regras.csv` | Per-rule execution latency (mean, std, min, max, P99 in µs) | CSV |
| `detection_results.csv` | BLOCK/ALLOW decisions for each sample | CSV |
| `confusion_matrix.csv` | Confusion matrix per class (TP, FP, TN, FN, TPR, FPR) | CSV |

---

### Key Result Files

- **`matriz_regras_ataques_plot.png`** — Visual summary: which rules fire for which attacks
- **`confusion_matrix.csv`** — Performance metrics per attack class
- **`latencia_regras.csv`** — Shows the low per-rule overhead (all rules < 1 µs)

---

## Expected Results

- Automatically generated Python rules detect anomalous behavior across all ERENO attack classes
- Low per-packet operational overhead, suitable for real-time substation environments
- Reproducible pipeline: every run starts from the labeled dataset and ends with auditable rules

---

## Conclusions and Future Work

This work demonstrates that LLMs can replace the manual rule-writing step in specification-based IDS, reducing reliance on domain experts and improving adaptability to new attack vectors. Planned future work includes:

- Validation on larger and more diverse datasets
- Comparison against classical ML-based IDS approaches
- Integration with real programmable switch hardware (P4/OpenFlow)

---

## References

- IEC 61850-8-1: *Communication networks and systems in substations*, IEC, 2003.
- Hong, J. & Liu, C. (2019). Intelligent electronic devices with collaborative intrusion detection systems. *IEEE Transactions on Smart Grid*, 10(1):271–281.
- Hong, J., Liu, C., & Govindarasu, M. (2014). Detection of cyber intrusions using network-based multicast messages for substation automation. *ISGT, IEEE*.
- Quincozes, S. E. et al. ERENO–IEC–61850 dataset.

---

## Citation

If you use this work, please cite the corresponding paper published at **SBRC 2026**.
