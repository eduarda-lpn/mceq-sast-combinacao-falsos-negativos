# Combinação de analisadores estáticos e falsos negativos em CVEs reais em C

MCEQ 12576 – PUC-Campinas – 2º semestre de 2026 – Projeto Final (Marco 2, 10/11/2026)
Equipe: Eduarda Luiza Pinheiro Nepomuceno (RA 24002529); Jhenifer Laís Barbosa (RA 24014979).

## Pergunta
Em programas C reais com CVEs conhecidas (Magma v1.1, Binutils, FFmpeg), a combinação dos seis
analisadores estáticos tem taxa de falsos negativos menor que a do melhor analisador sozinho?
A diferença muda entre CWE-664 e as demais classes? (Protocolo registrado em 02/11/2026.)

## Origem dos dados (secundários, experimento publicado)
- Lipp, Banescu, Pretschner. *An Empirical Study on the Effectiveness of Static C Code Analyzers for
  Vulnerability Detection.* ISSTA 2022. DOI 10.1145/3533767.3534380
- Pacote de replicação: Zenodo DOI 10.5281/zenodo.6584404 (v1.0.1); cópia em
  github.com/tum-i4/sast-tool-evaluation-artifacts (commit 078f4b1)
- Licença: CC BY 4.0 (Zenodo) e Apache-2.0 (GitHub). Acesso: 02/11/2026.
- Não executamos nenhum analisador (regra R4): só usamos os alertas publicados pelos autores.

## Como reexecutar
```bash
pip install -r requirements.txt
python src/marco2.py baixar        # baixa dataset.zip, cwe_mapping.zip e CSVs; grava SHA-256
python src/marco2.py inspecionar   # mostra o esquema real dos JSON/CSV (conferir CAMPOS no script)
python src/marco2.py limpar        # dados/limpos/*.csv + diario_limpeza.csv
python src/marco2.py descrever     # tabelas/*.csv + figuras/fig1_fn_e_custo.png
```
Se o download automático falhar, baixe o pacote do Zenodo e descompacte em `dados/brutos/`
(`dados/brutos/dataset/<programa>/…` e `dados/brutos/cwe_mapping/…`).

## Estrutura
- `dados/brutos/` – exatamente como baixado (nunca editar à mão)
- `dados/limpos/` – gerado pelo script (`cve_por_estrategia.csv`, `funcoes_marcadas.csv`, `diario_limpeza.csv`)
- `src/marco2.py` – baixar → inspecionar → limpar → descrever
- `testes/gerar_fixture_sintetica.py` – dados INVENTADOS só para testar o código; nunca usar no artigo
- `tabelas/`, `figuras/` – saídas da descritiva

## Status
O script foi escrito sem acesso aos arquivos reais (os nomes dos campos dos JSON estão em `CAMPOS`
e precisam ser conferidos com `inspecionar` na primeira execução). A conferência de totais
(192 CVEs; 117 CWE-664 e 75 demais; 55.203 funções; 223 funções vulneráveis) é impressa no diário.
