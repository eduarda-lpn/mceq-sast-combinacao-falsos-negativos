# Marco 3 – Limpeza reprodutível, descritiva e desenho (encontro de 10/11/2026)

MCEQ 12576 – PUC-Campinas – 2º semestre de 2026 – Projeto Final
Equipe: Eduarda Luiza Pinheiro Nepomuceno (RA 24002529); Jhenifer Laís Barbosa (RA 24014979).

O roteiro (Seção 2) pede para 10/11: **(i)** script que carrega os dados brutos e produz os dados limpos;
**(ii)** estatística descritiva e um gráfico das variáveis da hipótese principal; **(iii)** desenho
identificado. Ainda **não** há teste inferencial aqui (é o encontro de 17/11).

| Entregável | Onde |
|---|---|
| Documento do marco (diário, descritiva, figura, desenho) | `Marco3_Limpeza_Descritiva_Desenho.docx` |
| Adendo ao protocolo (09/11, antes de qualquer teste) | `Adendo_Protocolo.docx` |
| Script dados brutos → dados limpos → tabelas/figura | `src/analise.py` |
| Dados limpos e diário de limpeza | `dados/limpos/` |
| Tabelas descritivas e Figura 1 | `tabelas/`, `figuras/fig1_fn_e_custo.png` |

## Pergunta (protocolo de 02/11/2026, em `../Marco-2/`)
Em programas C reais com CVEs conhecidas (Magma v1.1, Binutils, FFmpeg), a combinação dos seis
analisadores estáticos tem taxa de falsos negativos menor que a do melhor analisador sozinho?
A diferença muda entre CWE-664 e as demais classes?

## Dados
Os dados brutos ficam em `../Marco-2/dados/brutos/` (base escolhida e baixada no Marco 2) e **nunca são
editados**. Origem: pacote de replicação de Lipp, Banescu e Pretschner (ISSTA 2022), Zenodo
DOI 10.5281/zenodo.6584404 (v1.0.1), cópia em github.com/tum-i4/sast-tool-evaluation-artifacts
(commit 078f4b1); licença CC BY 4.0 / Apache-2.0; acesso em 02/11/2026. Não executamos nenhum
analisador (regra R4).

## Como reexecutar (de dentro de `Marco-3/`)
```bash
pip install -r requirements.txt
python src/analise.py baixar         # só baixa o que faltar e confere o SHA-256 registrado no Marco 2
python src/analise.py limpar         # dados/limpos/*.csv, diário e conferências com os CSV dos autores
python src/analise.py descrever      # tabelas/*.csv + figuras/fig1_fn_e_custo.png
```
Comandos opcionais (não alteram os dados limpos): `inspecionar` (esquema dos JSON/CSV),
`diagnosticar` (evidências das divergências) e `mapeamento` (compara 12 regras alerta → função).

Reexecução conferida em 09/11/2026: as três tabelas e os CSV limpos saem idênticos byte a byte.

Teste com dados **sintéticos** (só para ver se o código roda; nunca usar no artigo):
```bash
python testes/gerar_fixture_sintetica.py /tmp/fx
MCEQ_FIXTURE=/tmp/fx python src/analise.py limpar
```

## Decisões tomadas depois do protocolo (registradas no Adendo de 09/11/2026)
Constantes no topo de `src/analise.py`; cada uma aparece em `dados/limpos/diario_limpeza.csv`.
- `LL_AJUSTE`: reclassificação de 4 CWE brutas (17→20, 670→20, 754→119, 755→476), **inferida** das
  contagens de `cwe_distr.csv`; não é regra documentada pelos autores.
- `EXCLUIR_REF_AUSENTE = True`: exclui a CVE que cita função inexistente em `functions.json`
  (CVE-2018-1999015, ffmpeg) → 192 CVEs (117 CWE-664 + 75 demais), como no protocolo.
- `BORDA = "incl"`, `MODO = "todas"`: regra alerta → função escolhida entre 12 variantes por reproduzir
  melhor os CSV dos autores, nunca pelo efeito sobre H1.
- `CASAR_POR_SUFIXO = False`: casamento de caminhos por sufixo testado e descartado.

## Reprodução dos números dos autores (parcial)
- Batem: 192 CVEs (117 + 75); ranking dos seis analisadores individuais; melhor individual = CommSCA.
- Não batem totalmente: 42 de 54 detecções S1-1 (`sca_data_1.csv`) e 36 de 63 contagens de funções
  marcadas (`fct_stats_2.csv`); combinação dos 6 = 141 CVEs no nosso cálculo e 135 nos CSV dos autores.
- Causa provável identificada (`dados/limpos/conferencia_json_vs_fct_stats_2.csv`): em 4 casos os autores
  contam **mais funções marcadas pelo Cppcheck do que existem linhas com alerta do Cppcheck** no
  `sca_results.json` publicado (ffmpeg 761 funções × 127 linhas; openssl 277 × 254; sqlite3 52 × 44;
  libxml2 13 × 10). Mesmo a regra mais generosa (marcar todas as funções que contêm a linha, a que usamos)
  só chega a 233, 108, 26 e 7 funções. Logo o JSON publicado não é exatamente o insumo dos CSV, e a
  divergência não vem do nosso código.

## Estrutura
- `src/analise.py` – pipeline (baixar, inspecionar, limpar, descrever, diagnosticar, mapeamento)
- `dados/limpos/` – `cve_por_estrategia.csv` (1 linha por CVE), `funcoes_marcadas.csv` (1 linha por
  função), `diario_limpeza.csv`, `melhor_individual.txt`, `conferencia_*.csv`, `calibracao_mapeamento.csv`,
  `diagnostico_*.csv`
- `tabelas/` – `t1_deteccao_por_estrategia.csv`, `t2_A_vs_B_por_classe.csv`, `t3_custo_por_programa.csv`
- `figuras/fig1_fn_e_custo.png`
- `testes/gerar_fixture_sintetica.py` – dados INVENTADOS para testar o código
