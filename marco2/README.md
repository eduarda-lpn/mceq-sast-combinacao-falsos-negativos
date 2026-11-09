# Combinação de analisadores estáticos e falsos negativos em CVEs reais em C

MCEQ 12576 – PUC-Campinas – 2º semestre de 2026 – Projeto Final (Marco 2)
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
python src/marco2.py baixar         # baixa dataset.zip, cwe_mapping.zip e CSVs; grava SHA-256
python src/marco2.py inspecionar    # mostra o esquema real dos JSON/CSV
python src/marco2.py limpar         # dados/limpos/*.csv, diário e conferências com os CSV dos autores
python src/marco2.py descrever      # tabelas/*.csv + figuras/fig1_fn_e_custo.png
```
Comandos de conferência (não alteram os dados limpos):
```bash
python src/marco2.py diagnosticar   # CWE dos alertas, evidências, intervalos de função suspeitos
python src/marco2.py mapeamento     # compara 12 regras alerta→função com sca_data_1.csv e fct_stats_2.csv
```
Se o download automático falhar (o `raw.githubusercontent` pode recusar o hash curto do commit),
use o hash completo em `COMMIT` ou baixe o pacote do Zenodo e descompacte em `dados/brutos/`
(`dados/brutos/dataset/dataset/<programa>/…` e `dados/brutos/cwe_mapping/cwe_mapping/…`).

## Estrutura
- `dados/brutos/` – exatamente como baixado (nunca editar à mão; ignorado pelo git, exceto `SHA256SUMS.txt`)
- `dados/limpos/` – gerado pelo script: `cve_por_estrategia.csv` (1 linha por CVE), `funcoes_marcadas.csv`
  (1 linha por função), `diario_limpeza.csv`, `melhor_individual.txt`, `conferencia_*.csv`,
  `calibracao_mapeamento.csv` e `diagnostico_*.csv` (quando os comandos de conferência são rodados)
- `src/marco2.py` – seis comandos: baixar, inspecionar, limpar, descrever, diagnosticar, mapeamento
- `testes/gerar_fixture_sintetica.py` – dados INVENTADOS só para testar o código; nunca usar no artigo
- `tabelas/` (`t1_deteccao_por_estrategia.csv`, `t2_A_vs_B_por_classe.csv`, `t3_custo_por_programa.csv`)
  e `figuras/` (`fig1_fn_e_custo.png`) – saídas da descritiva

## Decisões tomadas depois do protocolo (registrar no adendo datado)
Constantes no topo de `src/marco2.py`; cada uma aparece no diário de limpeza.
- `LL_AJUSTE` – reclassificação de 4 CWE brutas (17→20, 670→20, 754→119, 755→476), **inferida** das
  contagens de `cwe_distr.csv`; não é regra documentada pelos autores.
- `EXCLUIR_REF_AUSENTE = True` – exclui a CVE que cita função inexistente em `functions.json`
  (CVE-2018-1999015, ffmpeg), o que dá 192 CVEs (117 CWE-664 + 75 demais), como no protocolo.
- `BORDA = "incl"`, `MODO = "todas"` – regra alerta→função (linha dentro do `line_range`, bordas incluídas,
  todas as funções que contêm a linha), escolhida entre 12 variantes por reproduzir melhor os CSV dos
  autores. Nunca escolhida pelo efeito sobre H1.
- `CASAR_POR_SUFIXO = False` – casamento de caminhos por sufixo foi testado e descartado.

## Status (reprodução parcial dos números dos autores)
- Bate com o protocolo: 192 CVEs, 117 em CWE-664 e 75 nas demais; ranking dos analisadores individuais
  igual ao dos autores (melhor individual: CommSCA).
- Não bate totalmente: 42 de 54 detecções S1-1 (`sca_data_1.csv`) e 36 de 63 contagens de funções
  marcadas (`fct_stats_2.csv`); divergências concentradas em ffmpeg e Cppcheck, ainda sem explicação.
  Funções vulneráveis: 228 contra 223 dos autores. Detalhes no diário e no documento do Marco 2.
- A análise inferencial (McNemar exato, IC de Newcombe, Fisher, bootstrap por programa) é do Marco 3.

## Nota sobre IA
Este repositório foi desenvolvido com apoio de IA generativa (Claude, Anthropic); ver a Declaração de
Uso de Inteligência Artificial no artigo. Todos os números vêm da execução do código pela equipe.
