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
├── SBRC_2026_LLM_IDS_GOOSE_v1.ipynb # Main notebook (proof of concept)
├── rules.py # Clean & refined detection rules (latest version)
├── rules_raw.py # Raw LLM-generated rules (before refinement)
├── requirements.txt # Python dependencies (pinned versions)
├── .env.example # Template for GROQ_API_KEY
├── LICENSE # MIT License
├── CHANGELOG.md # Version history and changes
├── .gitignore # Git ignore rules
│
├── small_dataset/ # Dataset files
│ ├── train.csv # Training dataset – 207 samples, 52 features
│ └── ERENO-2.0-100K.csv # Full test dataset – 200,052 samples, 9 classes
│
├── old_rules/ # Backup of previous rule versions
│ ├── rules_20260508_023144.py # Older version of refined rules
│ ├── rules_raw_20260508_023144.py # Older version of raw LLM rules
│ ├── red_flags_20260508_022814.json # Older version of Red flags extracted per attack class
│ └── ... # Additional timestamped backups
│
├── old_data/ # Backup of previous evaluation results
│ ├── detection_results_20260508_023304.csv # Previous detection results
│ ├── confusion_matrix_20260508_023551.csv # Previous confusion matrix
│ ├── deteccoes_agregado_classes_20260508_023551.csv # Previous total detections per attack class
│ ├── latencia_regras_20260508_023556.csv # Previous per-rule execution latency (in µs)
│ ├── matriz_regras_ataques_20260508_023545.csv # Previous rule × attack class trigger-count matrix
│ └── ... # Additional timestamped backups
│
├── old_charts/ # Backup of previous visualizations
│ ├── matriz_regras_ataques_plot_20260508_023638.png
│ └── ... # Additional timestamped chart backups
│
├── red_flags.json # Red flags extracted per attack class
├── matriz_regras_ataques.csv # Rule × attack class trigger-count matrix
├── matriz_regras_ataques_plot.png # Stacked horizontal bar chart of the matrix
├── deteccoes_por_amostra.csv # Per-sample detection flags (all 200,052 rows)
├── deteccoes_agregado_classes.csv # Total detections per attack class
├── latencia_regras.csv # Per-rule execution latency (in µs)
├── detection_results.csv # BLOCK/ALLOW decisions for each sample (latest)
├── confusion_matrix.csv # Confusion matrix per class (TP, FP, TN, FN) (latest)
└── README.md # This file   
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
| **LLM Model** | `openai/gpt-oss-120b` (accessed via Groq API key) |

> **Note:** The pipeline uses cloud-based LLM inference. No local GPU is needed. A stable internet connection is required to call the Groq API.

---

## LLM Configuration Details

### Model: `openai/gpt-oss-120b`

| Property | Value | Source |
|----------|-------|--------|
| **Provider** | Groq API (via `groq` Python library) | - |
| **Model type** | 120B parameter Mixture-of-Experts (MoE) | [citation:10] |
| **Context window** | 131,072 tokens | [citation:8] |
| **License** | Apache 2.0 | [citation:10] |
| **Release date** | August 2025 | [citation:10] |

### Available Parameters (per Groq API)

| Parameter | Configurable? | Notes |
|-----------|---------------|-------|
| `model` | Yes | Set to `openai/gpt-oss-120b` |
| `max_tokens` | Yes | Set to 2000 |
| `temperature` | No | Uses Groq default (not user-configurable) |
| `seed` | No | Not exposed via Groq API |

### Reproducibility Guarantee

Despite the non-configurable `temperature` and `seed` parameters:

1. **Raw outputs are saved** - Every LLM response is backed up with timestamp
2. **Evaluation is deterministic** - Final detection uses `rules.py` (no LLM dependency)
3. **Prompts are documented** - Complete prompts visible in notebook cells

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
jupyter notebook SBRC_2026_LLM_IDS_GOOSE_v1.ipynb
```

---

Minimal Test
To verify that the environment is correctly configured, run:

```
python -c "import pandas, groq; print('Dependencies OK')"
```

---

## Running with Docker

> **Note:** The repository does not include a pre-configured `Dockerfile`. Follow the steps below to containerize the pipeline from scratch.

### Prerequisites

- Docker installed on your machine
- Git installed on your machine
- A Groq account and API key with access to the `openai/gpt-oss-120b` model

### Step-by-Step Instructions

#### 1. Clone the Repository

```bash
git clone https://github.com/lucastuxnet/SBRC_2026.git
```
```bash
cd SBRC_2026
```

#### 2. Create the Dockerfile

Create a file named `Dockerfile` in the project root:

```dockerfile
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir jupyter

COPY . .

EXPOSE 8888

CMD ["jupyter", "notebook", "--ip=0.0.0.0", "--port=8888", "--no-browser", "--allow-root"]
```

#### 3. Configure the API Key

Create a `.env` file at the project root with your Groq API key:

```
GROQ_API_KEY=gsk_your_api_key_here
```

> **Warning:** Never commit the `.env` file. It is already included in `.gitignore`.

#### 4. Build the Docker Image

```bash
docker build -t sbrc2026 .
```

#### 5. Run the Container (without persistence)

```bash
docker run -p 8888:8888 --env-file .env sbrc2026
```

#### 6. Run the Container (with persistent output folder)

```bash
mkdir -p ./output_do_projeto
```
```bash
docker run -p 8888:8888 --env-file .env -v $(pwd)/output_do_projeto:/app sbrc2026
```

#### 7. Access the Notebook

After running the container, the terminal will display a URL similar to:

```
http://127.0.0.1:8888/tree?token=ed2cad5686f5d722ba7cb341fbbc2d65ca124f66a54ff1db
```

Open this URL in your browser and click on `SBRC_2026_LLM_IDS_GOOSE_v1.ipynb`.

#### 8. Execute the Pipeline

Run the notebook cells in order:

| Section | Description |
|---------|-------------|
| **§4 – Setup** | Imports libraries and configures Groq client |
| **§5 – Data Ingestion** | Loads the ERENO dataset and displays class distribution |
| **§6.1 – Red Flag Extraction** | LLM identifies behavioral patterns for each attack class |
| **§6.2 – Rule Generation** | LLM translates red flags into Python detection functions |
| **§7 – Rule Execution** | Applies generated rules to GOOSE traffic |
| **§8 – Matrix Generation** | Generates confusion matrix and evaluation metrics |

### Expected Execution Time

| Stage | Approximate Time |
|-------|-----------------|
| Setup + Data Loading (§4–§5) | < 5 seconds |
| Red Flag Extraction (§6.1) | 2–5 minutes |
| Rule Generation (§6.2) | 3–8 minutes |
| Rule Execution + Matrix (§7–§8) | 10–30 seconds |
| **Total** | **5–15 minutes** |

### Resource Usage

| Metric | Peak Value |
|--------|------------|
| RAM | ~1.2 GB |
| Disk (outputs) | ~50 MB |
| Network per API call | ~100 KB |
| GPU | Not used |

### Important Notes

- **API Key:** The Groq API key is mandatory for sections 6.1 and 6.2. Without a valid key with access to the `openai/gpt-oss-120b` model, rule generation will fail.
- **Internet:** The LLM stages require a stable internet connection to call the Groq Cloud API.
- **Rate Limits:** The notebook automatically retries up to 5 times with exponential backoff if rate-limited by Groq.
- **Reproducibility:** All LLM outputs are saved with timestamps. Final evaluation uses deterministic `rules.py` with no LLM dependency.
- **Operating System:** Commands above are for Linux/macOS. On Windows, replace `$(pwd)` with `%cd%` in the volume mount path.

### Troubleshooting

| Problem | Solution |
|---------|----------|
| `git: command not found` | Install Git: `sudo apt install git` (Linux) or download from git-scm.com (Windows/macOS) |
| Authentication error in §6 | Verify `.env` contains `GROQ_API_KEY=gsk_...` with no quotes or extra spaces |
| API rate limit reached | Wait a few minutes and re-run the cell; notebook retries automatically |
| Connection refused on port 8888 | Ensure container is running and port not blocked by firewall |
| Module not found errors | Rebuild image with `docker build --no-cache -t sbrc2026 .` |
| Permission denied on volume mount | Use absolute paths or check folder permissions |


---

## Running the Notebook

Open the notebook in Jupyter or VSCode and run the cells in order:

```bash
jupyter notebook SBRC_2026_LLM_IDS_GOOSE_v1.ipynb
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

## Version History

| Version | Tag | Description | Date |
|---------|-----|-------------|------|
| v1.2 | `sbrc2026-camera-ready` | Final camera-ready version | May 2026 |
| v1.1 | `sbrc2026-revised` | Post-review revisions | Apr 2026 |
| v1.0 | `sbrc2026-submission` | Initial submission version | Mar 2026 |

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
