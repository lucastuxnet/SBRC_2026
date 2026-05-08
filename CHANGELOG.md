# Changelog

## [1.2.0] - 2026-05-08 (Camera-ready)

### Changes
- Adicionado sistema automático de backup para todos arquivos gerados
- Adicionada pasta `old_charts/` para backups de imagens
- Adicionada pasta `old_data/` para backups de dados CSV
- Adicionado funções na ferramenta para escolha da data base CSV a ser utilizada
- Melhorada documentação do versionamento no README
- Melhorada documentação de estrutura da ferramenta no README
- Corrigido bug na extração de red flags para classe 'grayhole'
- Criado um arquivo para versionamento `CHANGELOG.md`
- Alterado o nome do arquivo de exemplo de API-key de `.env.example` para `.env.example`
- Criado um filtro para que o FRP não bloquei o trafego normal.
- Alterada a API de busca para `openai/gpt-oss-120b` a versão atende melhor as requisições do projeto

### Files Modified
- `SBRC_2026_LLM_IDS_GOOSE_v1.ipynb` (versão final)
- `README.md` (seção de versão anterior adicionada)
- `requirements.txt` (dependências atualizadas)

## [1.1.0] - 2026-04-18 (Post-review)

### Changes
- Adicionada pasta `old_rules/` para backups
- Melhorada legenda do gráfico de matriz
- Ajustados parâmetros de latência
- Criado arquivo de exemplo API-key `.env.example`

## [1.0.0] - 2026-03-26 (Initial submission)

### Changes
- Versão inicial submetida ao SBRC 2026
- Pipeline completo implementado
- Documentação inicial
