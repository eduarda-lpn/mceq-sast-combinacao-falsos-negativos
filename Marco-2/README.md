# Marco 2 – Base pública, protocolo e variáveis (encontro de 03/11/2026)

MCEQ 12576 – PUC-Campinas – 2º semestre de 2026 – Projeto Final
Equipe: Eduarda Luiza Pinheiro Nepomuceno (RA 24002529); Jhenifer Laís Barbosa (RA 24014979).

O roteiro (Seção 2) pede para 03/11: **(i)** base escolhida e já baixada, com data de acesso e
versão/DOI anotados; **(ii)** protocolo de 1 página concluído; **(iii)** lista das variáveis disponíveis
e de como cada uma foi medida; **(iv)** repositório da equipe criado.

| Entregável | Onde |
|---|---|
| Protocolo de 1 página (registrado em 02/11/2026) | `Protocolo_1pagina.docx` |
| Base, proveniência, variáveis e repositório | `Marco2_Base_Proveniencia_Variaveis.docx` |
| Base baixada, intocada, com SHA-256 | `dados/brutos/` (`SHA256SUMS.txt`) |
| Repositório | https://github.com/eduarda-lpn/mceq-sast-combinacao-falsos-negativos |

## Base escolhida
- **Pacote de replicação** de Lipp, Banescu e Pretschner, *An Empirical Study on the Effectiveness of
  Static C Code Analyzers for Vulnerability Detection*, ISSTA 2022, DOI 10.1145/3533767.3534380.
- Zenodo, DOI **10.5281/zenodo.6584404** (versão 1.0.1); cópia em
  github.com/tum-i4/sast-tool-evaluation-artifacts, commit **078f4b1**.
- Licença **CC BY 4.0** (Zenodo) e **Apache-2.0** (GitHub): permitem redistribuir com atribuição, por isso
  os arquivos estão neste repositório. Atribuição: © os autores do pacote acima; arquivos sem modificação.
- Data de acesso/download: **02/11/2026**.
- Tipo: experimento publicado (os autores rodaram as ferramentas; a equipe **não** executa nenhum
  analisador, regra R4).

## Conteúdo de `dados/brutos/` (nunca editar à mão)
| Arquivo | O que é |
|---|---|
| `dataset.zip` → `dataset/dataset/<programa>/` | por programa: `cve_data.json` (CVE → CWE e funções afetadas), `functions.json` (arquivo, nome, intervalo de linhas, LOC), `sca_results.json` (cada alerta: arquivo, linha, CWE, ferramenta), `cve_data/` (metadados NVD de cada CVE) |
| `cwe_mapping.zip` → `cwe_mapping/cwe_mapping/` | hierarquia de CWE (`buckets.json`) e mapeamento de regras de cada ferramenta para CWE |
| `cwe_distr.csv` | CVEs por programa, tipo de CWE (baixo nível) e classe (alto nível) |
| `fct_stats_1.csv` | uma linha por função (programa, arquivo, função, LOC, vulnerável) |
| `fct_stats_2.csv` | funções marcadas por analisador/combinação e programa |
| `sca_data_1.csv`, `sca_data_2.csv` | CVEs detectadas por analisador/combinação, programa (ou CWE) e cenário |

Conferir integridade: `sha256sum -c SHA256SUMS.txt` (de dentro de `dados/brutos/`). O arquivo
`.gitattributes` da raiz impede que o Git converta fim de linha nesses arquivos (no Windows, o
`core.autocrlf` alterava os CSV e o SHA-256 deixava de bater).

O script que transforma estes dados está no Marco 3 (`../Marco-3/src/analise.py`).
