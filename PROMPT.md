# Prompt de Geração de Regras - LLM IDS GOOSE

> **Nota:** Este é o prompt utilizado no pipeline para converter *red flags* em funções Python de detecção. A implementação completa está disponível no notebook `SBRC_2026_LLM_IDS_GOOSE.ipynb`.

---

## Prompt Principal para Geração de Regras
Você é um modelo especializado em detecção de intrusões em tráfego IEC 61850-GOOSE.

=== RED FLAGS IDENTIFICADAS PARA A CLASSE '{attack_class}' ===
{red_flags_text}

Tarefa:
Converta essas red flags em FUNÇÕES DE REGRAS DE DETECÇÃO em Python para identificar pacotes suspeitos da classe '{attack_class}'.

Regras de saída:
Retorne APENAS código Python válido, sem explicações, comentários extras ou markdown.
Crie de 3 a 5 funções com a forma:

def rule_{attack_class}_<nome_curto>(packet: dict) -> bool:
"""Retorna True se o pacote for suspeito desse ataque."""

lógica usando apenas campos presentes em packet
...

Use nomes_curto descritivos em snake_case (ex.: jumps_stnum_time_diff, sqnum_reset_pattern).

Restrições:

NÃO use a coluna/atributo "class"

Use apenas campos do dataset: 'StNum', 'SqNum', 'timestampDiff', 'cbStatus', 'ethSrc', 'ethDst', 'appID', flags, contadores

Cada regra deve combinar DOIS OU MAIS campos

NÃO use igualdade exata para valores absolutos

PREFIRA condições relativas: diferenças, comparações (> ou <), padrões de origem/destino

Capture comportamento semântico do ataque (replay, jumps anômalos, resets, frequência anômala)

Estilo do código:

Apenas operações básicas (comparações, AND/OR/NOT, soma/subtração)

Não importe bibliotecas

Trate campos ausentes com packet.get("campo", valor_padrao)

---

## Prompt para Extração de Red Flags (Primeiro Estágio)

Analyze GOOSE traffic for IEC 61850 substation.

NORMAL (reference means):
{json.dumps(normal_means, indent=2)}

ATTACK class '{attack_class}' means:
{json.dumps(attack_means, indent=2)}

Task: List RED FLAGS (behavioral patterns) that distinguish this attack from normal traffic.

Format each red flag as:

RED FLAG: [name]
FIELDS: [fields]
REASON: [why anomalous per IEC 61850]

Focus on StNum, SqNum, timestampDiff patterns.


---

## Mensagem de Sistema (System Prompt)

Você é um especialista em segurança IEC 61850 e desenvolvedor Python. Dado o contexto e as red flags, você deve retornar SOMENTE código Python válido. Não inclua explicações, texto em linguagem natural ou markdown. Apenas código Python puro.


---

## Parâmetros da LLM

| Parâmetro | Valor |
|-----------|-------|
| Modelo | Groq (GPT-OSS 120B / Llama 4) |
| Temperature | 0 |
| Max tokens | 2048 |
| Top_p | 1 |

---

## Exemplo de Saída Esperada

Para um ataque da classe `masq_fake_normal`:

```python
def rule_masq_fake_normal_stnum_jumps(packet: dict) -> bool:
    stnum = packet.get("StNum", 0)
    ts_diff = packet.get("timestampDiff", 0)
    if ts_diff < 0.001 and stnum > 1:
        return True
    return False

def rule_masq_fake_normal_sqnum_reset(packet: dict) -> bool:
    sqnum = packet.get("SqNum", 0)
    if sqnum == 0 and packet.get("stNumDiff", 0) > 0:
        return True
    return False
```
---

## Referência no Código Fonte

| Função | Localização |
|-----------|-------|
| make_red_flags_prompt() | Célula 2 do notebook |
| make_rules_prompt_from_red_flags() | Célula 4 do notebook |
