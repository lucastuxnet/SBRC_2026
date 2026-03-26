# 🔐 GOOSE-LLM-IDS 🔐

#### EN 🇺🇸

### ✔️ Overview

**GOOSE-LLM-IDS** is an LLM-driven pipeline that automates the generation of detection rules for real-time intrusion detection and prevention in IEC 61850 digital substations.

The pipeline consumes labeled GOOSE communication samples from the **ERENO** dataset, identifies suspicious behavioral patterns (*red flags*) using a Large Language Model, and converts them into executable Python detection rules deployed in a simulated programmable switching environment.

> 📄 This repository accompanies the paper:
> **"From Red Flags to Detection Rules: An LLM-driven Pipeline for Real-Time GOOSE Intrusion Detection and Prevention"**
> Lucas A. Martins, Silvio E. Quincozes — UFU / UNIPAMPA — SBRC 2026

---

## 📚 Index

* [Architecture](#architecture)
* [Pipeline Stages](#pipeline-stages)
* [Test Environment](#test-environment)
* [Requirements](#requirements)
* [Installation](#installation)
* [Execution](#execution)
* [Configuration](#configuration)
* [Dataset](#dataset)
* [Outputs and Artifacts](#outputs-and-artifacts)
* [🇧🇷 PT](#pt-)

---

## 🏗️ Architecture

The project is organized into four main modules:

```
goose-llm-ids/
│
├── data/                  # ERENO dataset (not included — see Dataset section)
├── pipeline/
│   ├── ingestion.py       # Source ingestion and prompt preparation
│   ├── red_flags.py       # LLM-based red flag extraction
│   ├── rule_gen.py        # Detection rule generation
│   └── switch_sim.py      # Programmable switch simulation
├── rules/                 # Auto-generated Python detection rules
├── logs/                  # Execution logs and detection artifacts
├── config/
│   └── pipeline_config.json
├── GOOSE_LLM_IDS.ipynb    # Full pipeline as a Jupyter Notebook
└── requirements.txt
```

---

## 🔄 Pipeline Stages

```
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Labeled GOOSE   │───▶│  Red Flag Extr.  │───▶│  Rule Generation │───▶│ Switch Simulation│
│  Dataset (ERENO) │    │  (LLM-based)     │    │  (Python rules)  │    │  (Real-time)     │
└──────────────────┘    └──────────────────┘    └──────────────────┘    └──────────────────┘
```

| Stage | Description |
|-------|-------------|
| **1. Source Ingestion** | Loads the ERENO dataset, organizes features, and builds structured LLM prompts |
| **2. Red Flag Extraction** | LLM identifies suspicious patterns and behavioral inconsistencies in labeled samples |
| **3. Rule Generation** | Translates red flags into executable Python detection rules |
| **4. Simulated Deployment** | Applies rules over GOOSE traffic in a real-time programmable switch emulator |

---

## 🖥️ Test Environment

The tool was tested under the following configurations:

| Setting | Environment I | Environment II |
|---------|--------------|----------------|
| OS | Windows 11 | Ubuntu 20.04 LTS |
| Processor | AMD Ryzen 7 5700X3D | Intel Core i5-10300H |
| RAM | 16 GB | 16 GB |
| Architecture | 64-bit | 64-bit |

---

## 📝 Requirements

The pipeline is implemented in Python.

| Dependency | Recommended Version |
|------------|-------------------|
| Python | 3.9+ |
| Jupyter Notebook | 7.0+ |
| pandas | 2.0+ |
| numpy | 1.24+ |
| scikit-learn | 1.3+ |
| openai / anthropic | latest |

All libraries are listed in:

```
requirements.txt
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/sequincozes/goose-llm-ids.git
cd goose-llm-ids
```

Create and activate a virtual environment (optional but recommended):

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

---

## ▶️ Execution

### Jupyter Notebook (recommended)

Open the full pipeline notebook:

```bash
jupyter notebook GOOSE_LLM_IDS.ipynb
```

The notebook walks through all stages interactively:

1. Dataset loading and prompt preparation
2. LLM-based red flag extraction
3. Python rule generation
4. Switch simulation and evaluation

### Command-line (single node)

```bash
python -m pipeline.run --config config/pipeline_config.json
```

During execution, logs will display:

* Loaded dataset statistics
* Extracted red flags per attack class
* Generated detection rules
* Per-packet detection decisions (ALLOW / BLOCK)
* Detection metrics and latency benchmarks

---

## ⚙️ Configuration

Each pipeline run is parameterized via:

```
config/pipeline_config.json
```

Configurable parameters include:

| Parameter | Description |
|-----------|-------------|
| `dataset_path` | Path to the ERENO CSV file |
| `llm_provider` | LLM backend (`openai`, `anthropic`, `ollama`) |
| `llm_model` | Model identifier (e.g. `gpt-4`, `claude-opus-4-6`) |
| `n_normal_samples` | Number of normal samples sent to the LLM per prompt |
| `n_attack_samples` | Number of attack samples sent to the LLM per prompt |
| `flood_threshold_pps` | Packets-per-second threshold for flood detection rule |
| `max_timestamp_diff_ms` | Maximum allowed timestamp difference (ms) |

This enables reproducible and parameterized experiments.

---

## 📦 Dataset

This pipeline uses the **ERENO–IEC–61850** dataset, which provides labeled GOOSE communication traces under normal and attack conditions (DoS, Message Injection, Masquerade).

> Quincozes, S. E., Passos, D., Albuquerque, C., Mossé, D., and Ochi, L. S. (2022).
> *ERENO: An Extensible Tool for Generating Realistic IEC–61850 Intrusion Detection Datasets.*
> PhD thesis, Universidade Federal Fluminense.

Place the dataset file at:

```
data/ereno_goose.csv
```

---

## 📁 Outputs and Artifacts

Each pipeline run produces the following artifacts:

| Artifact | Location | Description |
|----------|----------|-------------|
| Red flags | `logs/red_flags.txt` | Semi-structured suspicious patterns identified by the LLM |
| Detection rules | `rules/generated_rules.py` | Executable Python rules derived from red flags |
| Execution log | `logs/switch_execution.csv` | Per-packet decisions from the switch simulator |
| Detection report | `logs/detection_report.txt` | Classification metrics (precision, recall, F1) |

---

## 📖 Citation

If you use this tool in your research, please cite:

```bibtex
@inproceedings{martins2026goosellm,
  title     = {From Red Flags to Detection Rules: An LLM-driven Pipeline for Real-Time GOOSE Intrusion Detection and Prevention},
  author    = {Martins, Lucas A. and Quincozes, Silvio E.},
  booktitle = {Anais do XLIV Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC)},
  year      = {2026}
}
```

---

---

#### PT 🇧🇷

## ✔️ Visão Geral

**GOOSE-LLM-IDS** é um pipeline orientado por LLM que automatiza a geração de regras de detecção para detecção e prevenção de intrusões em tempo real em subestações digitais IEC 61850.

O pipeline consome amostras rotuladas de comunicação GOOSE do dataset **ERENO**, identifica padrões comportamentais suspeitos (*red flags*) usando um Grande Modelo de Linguagem (LLM) e os converte em regras Python executáveis, implantadas em um ambiente de switch programável simulado.

> 📄 Este repositório acompanha o artigo:
> **"From Red Flags to Detection Rules: An LLM-driven Pipeline for Real-Time GOOSE Intrusion Detection and Prevention"**
> Lucas A. Martins, Silvio E. Quincozes — UFU / UNIPAMPA — SBRC 2026

---

## 📚 Índice

* [Arquitetura](#arquitetura)
* [Estágios do Pipeline](#estágios-do-pipeline)
* [Ambiente de Testes](#ambiente-de-testes)
* [Requerimentos](#requerimentos)
* [Instalação](#instalação)
* [Execução](#execução)
* [Configuração](#configuração)
* [Dataset](#dataset-1)
* [Saídas e Artefatos](#saídas-e-artefatos)

---

## 🏗️ Arquitetura

Estrutura principal do projeto:

```
goose-llm-ids/
│
├── data/                  # Dataset ERENO (não incluído — veja seção Dataset)
├── pipeline/
│   ├── ingestion.py       # Ingestão de dados e preparação de prompts
│   ├── red_flags.py       # Extração de red flags via LLM
│   ├── rule_gen.py        # Geração de regras de detecção
│   └── switch_sim.py      # Simulação do switch programável
├── rules/                 # Regras Python geradas automaticamente
├── logs/                  # Logs de execução e artefatos de detecção
├── config/
│   └── pipeline_config.json
├── GOOSE_LLM_IDS.ipynb    # Pipeline completo como Jupyter Notebook
└── requirements.txt
```

---

## 🔄 Estágios do Pipeline

```
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Dataset GOOSE   │───▶│  Extração de     │───▶│  Geração de      │───▶│  Simulação do    │
│  Rotulado (ERENO)│    │  Red Flags (LLM) │    │  Regras (Python) │    │  Switch          │
└──────────────────┘    └──────────────────┘    └──────────────────┘    └──────────────────┘
```

| Estágio | Descrição |
|---------|-----------|
| **1. Ingestão** | Carrega o dataset ERENO, organiza as features e constrói prompts estruturados para o LLM |
| **2. Extração de Red Flags** | O LLM identifica padrões suspeitos e inconsistências comportamentais nas amostras rotuladas |
| **3. Geração de Regras** | Traduz as red flags em regras Python executáveis |
| **4. Simulação** | Aplica as regras sobre o tráfego GOOSE em um emulador de switch programável em tempo real |

---

## 🖥️ Ambiente de Testes

A ferramenta foi testada nas seguintes configurações:

| Configuração | Ambiente I | Ambiente II |
|-------------|-----------|-------------|
| Sistema Operacional | Windows 11 | Ubuntu 20.04 LTS |
| Processador | AMD Ryzen 7 5700X3D | Intel Core i5-10300H |
| RAM | 16 GB | 16 GB |
| Arquitetura | 64-bit | 64-bit |

---

## 📝 Requerimentos

O pipeline é implementado em Python.

| Dependência | Versão Recomendada |
|-------------|-------------------|
| Python | 3.9+ |
| Jupyter Notebook | 7.0+ |
| pandas | 2.0+ |
| numpy | 1.24+ |
| scikit-learn | 1.3+ |
| openai / anthropic | latest |

As bibliotecas estão listadas em:

```
requirements.txt
```

---

## ⚙️ Instalação

Clone o repositório:

```bash
git clone https://github.com/sequincozes/goose-llm-ids.git
cd goose-llm-ids
```

Crie e ative um ambiente virtual (opcional, mas recomendado):

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

---

## ▶️ Execução

### Jupyter Notebook (recomendado)

Abra o notebook completo do pipeline:

```bash
jupyter notebook GOOSE_LLM_IDS.ipynb
```

O notebook percorre todos os estágios de forma interativa:

1. Carregamento do dataset e preparação dos prompts
2. Extração de red flags via LLM
3. Geração de regras Python
4. Simulação do switch e avaliação

### Linha de comando

```bash
python -m pipeline.run --config config/pipeline_config.json
```

Durante a execução, os logs exibirão:

* Estatísticas do dataset carregado
* Red flags extraídas por classe de ataque
* Regras de detecção geradas
* Decisões por pacote (ALLOW / BLOCK)
* Métricas de detecção e benchmarks de latência

---

## ⚙️ Configuração

Cada execução do pipeline é parametrizada via:

```
config/pipeline_config.json
```

Parâmetros configuráveis:

| Parâmetro | Descrição |
|-----------|-----------|
| `dataset_path` | Caminho para o arquivo CSV do ERENO |
| `llm_provider` | Backend LLM (`openai`, `anthropic`, `ollama`) |
| `llm_model` | Identificador do modelo (ex: `gpt-4`, `claude-opus-4-6`) |
| `n_normal_samples` | Número de amostras normais enviadas ao LLM por prompt |
| `n_attack_samples` | Número de amostras de ataque enviadas ao LLM por prompt |
| `flood_threshold_pps` | Limiar de pacotes/segundo para a regra de flood |
| `max_timestamp_diff_ms` | Diferença máxima de timestamp permitida (ms) |

---

## 📦 Dataset

Este pipeline utiliza o dataset **ERENO–IEC–61850**, que fornece traços rotulados de comunicação GOOSE em condições normais e sob ataque (DoS, Injeção de Mensagens, Mascaramento).

> Quincozes, S. E., Passos, D., Albuquerque, C., Mossé, D., e Ochi, L. S. (2022).
> *ERENO: An Extensible Tool for Generating Realistic IEC–61850 Intrusion Detection Datasets.*
> Tese de Doutorado, Universidade Federal Fluminense.

Coloque o arquivo do dataset em:

```
data/ereno_goose.csv
```

---

## 📁 Saídas e Artefatos

Cada execução do pipeline produz os seguintes artefatos:

| Artefato | Local | Descrição |
|----------|-------|-----------|
| Red flags | `logs/red_flags.txt` | Padrões suspeitos identificados pelo LLM |
| Regras de detecção | `rules/generated_rules.py` | Regras Python derivadas das red flags |
| Log de execução | `logs/switch_execution.csv` | Decisões por pacote do simulador de switch |
| Relatório de detecção | `logs/detection_report.txt` | Métricas de classificação (precisão, recall, F1) |

---

## 📖 Citação

Se você utilizar esta ferramenta em sua pesquisa, por favor cite:

```bibtex
@inproceedings{martins2026goosellm,
  title     = {From Red Flags to Detection Rules: An LLM-driven Pipeline for Real-Time GOOSE Intrusion Detection and Prevention},
  author    = {Martins, Lucas A. and Quincozes, Silvio E.},
  booktitle = {Anais do XLIV Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC)},
  year      = {2026}
}
```
