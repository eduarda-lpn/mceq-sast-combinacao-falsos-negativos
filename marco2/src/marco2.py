"""
MCEQ 12576 - PUC-Campinas - Projeto Final - Marco 2
Combinacao de analisadores estaticos e falsos negativos em CVEs reais em C.

Fluxo (dados brutos -> dados limpos -> descritiva -> figura):
    python src/marco2.py baixar         # baixa os arquivos brutos e registra SHA-256
    python src/marco2.py inspecionar    # mostra o esquema real dos JSON/CSV
    python src/marco2.py limpar         # gera dados/limpos/ e o diario de limpeza (+ conferencias)
    python src/marco2.py descrever      # tabelas descritivas + figura
Comandos de conferencia (nao alteram os dados limpos):
    python src/marco2.py diagnosticar   # CWE dos alertas, evidencias, intervalos de funcao suspeitos
    python src/marco2.py mapeamento     # compara 12 regras alerta->funcao com os CSV dos autores

REGRAS DO PROTOCOLO (registrado em 02/11/2026) QUE ESTE SCRIPT SEGUE
  - Nao executamos analisadores (R4): so usamos os resultados publicados.
  - Cenario S1-1: CVE detectada se >= 1 funcao afetada recebeu >= 1 alerta
    (nao exige a CWE correta).
  - Estrategia A = analisador individual com MAIOR taxa de deteccao em S1-1
    (regra fixada antes de ver os dados). Estrategia B = uniao dos 6.
  - Classe CWE: CWE-664 x demais, pela hierarquia dos autores (cwe_distr.csv: tipo -> classe).
  - Os dados brutos nunca sao editados; toda transformacao esta aqui.

DECISOES POSTERIORES AO PROTOCOLO (a registrar no adendo datado; ver diario_limpeza.csv)
  - LL_AJUSTE: reclassificacao de 4 CWE brutas, inferida de cwe_distr.csv.
  - EXCLUIR_REF_AUSENTE: exclui CVE que cita funcao ausente de functions.json (1 CVE).
  - BORDA/MODO: regra alerta->funcao escolhida por reproduzir melhor sca_data_1.csv e
    fct_stats_2.csv (comando `mapeamento`), nunca pelo efeito sobre H1.
"""
import hashlib
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

# ----------------------------------------------------------------------------
# CONFIGURACAO (versao fixa da base: ver protocolo)
# ----------------------------------------------------------------------------
DOI_ZENODO = "10.5281/zenodo.6584404"          # versao 1.0.1
COMMIT = "078f4b1"                              # GitHub tum-i4/sast-tool-evaluation-artifacts
# ATENCAO: se o raw.githubusercontent nao aceitar o hash curto, troque pelo hash
# completo de 40 caracteres do commit 078f4b1 (ver pagina do commit) OU baixe o
# pacote do Zenodo e coloque os arquivos em dados/brutos/ manualmente.
URL_BASE = f"https://raw.githubusercontent.com/tum-i4/sast-tool-evaluation-artifacts/{COMMIT}/"
ARQUIVOS = ["dataset.zip", "cwe_mapping.zip",
            "data/cwe_distr.csv", "data/fct_stats_1.csv", "data/fct_stats_2.csv",
            "data/sca_data_1.csv", "data/sca_data_2.csv"]

RAIZ = Path(__file__).resolve().parent.parent
BRUTOS, LIMPOS = RAIZ / "dados" / "brutos", RAIZ / "dados" / "limpos"
FIGS, TABS = RAIZ / "figuras", RAIZ / "tabelas"

FERRAMENTAS = ["flawfinder", "cppcheck", "infer", "codechecker", "codeql", "commsca"]

# Valores que o PROTOCOLO/README afirmam (usados em assert de conferencia)
ESPERADO = {"n_cve": 192, "n_cwe664": 117, "n_demais": 75,
            "n_funcoes": 55203, "n_funcoes_vuln": 223}

# Nomes de campos dos JSON. Eu NAO tinha acesso aos arquivos ao escrever este
# script: cada lista abaixo traz os nomes candidatos; o primeiro que existir no
# registro e usado. Se nenhum existir, o script para e mostra as chaves reais.
# Depois de rodar `inspecionar`, ajuste aqui (e registre no diario).
CAMPOS = {
    # Esquema conferido com a saida real de `inspecionar` (06/11/2026):
    # functions.json = {"functions": [{file, name, line_range, LOC}]}
    # sca_results.json = {"findings": [{file, line, cwe, found_by}]}
    # cve_data.json = {CVE: {cwe: "CWE-476", functions: [...]}}
    "arquivo":   ["file", "filename", "file_name", "path", "filepath"],
    "intervalo": ["line_range", "lines", "range"],
    "linha":     ["line", "line_number", "lineno", "line_nr"],
    "ferramenta": ["found_by", "tool", "analyzer", "sca", "scanner"],
    "cve_id":    ["cve", "cve_id", "id", "name"],
    "cve_funcs": ["functions", "vulnerable_functions", "affected_functions", "funcs"],
    "cve_cwe":   ["cwe", "cwes", "cwe_id", "cwe_ids", "weaknesses"],
    "nome_func": ["name", "function", "func", "function_name"],
    "cwe_alerta": ["cwe", "cwe_id"],
}

# Reconciliacao com os numeros publicados (cwe_distr.csv). Quatro CWE "brutas" do cve_data.json
# nao estao entre as 21 CWE de baixo nivel dos autores; as contagens de cwe_distr.csv indicam que
# eles reclassificaram: 17->20 (openssl), 670->20 (poppler), 754->119 e 755->476 (sqlite3).
# E uma INFERENCIA a partir das contagens, nao uma regra documentada: registrar no adendo.
LL_AJUSTE = {"17": "20", "670": "20", "754": "119", "755": "476"}
# CVEs que os autores nao contam (192 de 193). Preencher DEPOIS de identificar no diario
# (candidata: a CVE de ffmpeg/CWE-125 com funcao nao encontrada em functions.json).
EXCLUIR_CVES = []
# Regra DOCUMENTAL (substitui a lista manual): excluir CVE que cita funcao inexistente em
# functions.json (nao ha como localizar a funcao afetada). So 1 CVE cai nela: ffmpeg/CVE-2018-1999015
# (CWE-125), o que reproduz 192 CVEs, 117 em CWE-664 e 23 funcoes vulneraveis em ffmpeg.
EXCLUIR_REF_AUSENTE = True

# Se True, alerta cujo arquivo nao esta em functions.json tenta casar por sufixo de caminho
# (ex.: 'src/a.c' x 'a.c'). Decisao registrada no diario; validar com a conferencia dos CSV.
CASAR_POR_SUFIXO = False   # desligado: casou so 14 (binutils) e 30 (poppler) alertas, provavelmente falsos

# Regra de ligacao alerta -> funcao. Calibrada contra os CSV publicados (comando `mapeamento`),
# NUNCA pelo efeito sobre H1.  borda: incl | ex_ini | ex_fim | ex_ambos ;
# modo: todas (todas as funcoes que contem a linha) | mais_interna | maior_inicio
BORDA = "incl"
MODO = "todas"

DIARIO = []   # (decisao, efeito) -> dados/limpos/diario_limpeza.csv


def registrar(decisao, efeito):
    DIARIO.append({"n": len(DIARIO) + 1, "decisao": decisao, "efeito": str(efeito)})
    print(f"[diario #{len(DIARIO)}] {decisao} -> {efeito}")


def pegar(reg, chave, obrigatorio=True, contexto=""):
    """Le reg[chave] usando os nomes candidatos de CAMPOS; erro didatico se faltar."""
    for nome in CAMPOS[chave]:
        if isinstance(reg, dict) and nome in reg:
            return reg[nome]
    if obrigatorio:
        chaves = list(reg.keys()) if isinstance(reg, dict) else type(reg).__name__
        raise KeyError(f"Campo '{chave}' nao encontrado {contexto}. Candidatos: "
                       f"{CAMPOS[chave]}. Chaves reais: {chaves}. "
                       f"Ajuste CAMPOS em src/marco2.py.")
    return None


# ----------------------------------------------------------------------------
# 1) BAIXAR
# ----------------------------------------------------------------------------
def sha256(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return h.hexdigest()


def baixar():
    BRUTOS.mkdir(parents=True, exist_ok=True)
    linhas = []
    for rel in ARQUIVOS:
        destino = BRUTOS / Path(rel).name
        if not destino.exists():                       # dado bruto, intocado
            urllib.request.urlretrieve(URL_BASE + rel, destino)
        linhas.append(f"{sha256(destino)}  {destino.name}")
    (BRUTOS / "SHA256SUMS.txt").write_text("\n".join(linhas) + "\n")
    for zname in ("dataset.zip", "cwe_mapping.zip"):
        alvo = BRUTOS / zname.replace(".zip", "")
        if not alvo.exists():
            with zipfile.ZipFile(BRUTOS / zname) as z:
                z.extractall(alvo)
    print("\n".join(linhas))


# ----------------------------------------------------------------------------
# 2) INSPECIONAR (esquema real dos arquivos)
# ----------------------------------------------------------------------------
def _resumo(obj, nivel=0, max_nivel=3):
    pad = "  " * nivel
    if isinstance(obj, dict):
        print(f"{pad}dict com {len(obj)} chaves; 5 primeiras: {list(obj)[:5]}")
        if nivel < max_nivel and obj:
            _resumo(next(iter(obj.values())), nivel + 1, max_nivel)
    elif isinstance(obj, list):
        print(f"{pad}list com {len(obj)} itens")
        if nivel < max_nivel and obj:
            _resumo(obj[0], nivel + 1, max_nivel)
    else:
        print(f"{pad}{type(obj).__name__}: {str(obj)[:80]}")


def achar(base, nome):
    achados = sorted(base.rglob(nome))
    return achados


def inspecionar():
    ds = BRUTOS / "dataset"
    for nome in ("cve_data.json", "functions.json", "sca_results.json"):
        for p in achar(ds, nome)[:1]:
            print(f"\n=== {p.relative_to(BRUTOS)}")
            _resumo(json.loads(p.read_text()))
    # exemplos concretos dos formatos que definem o parser
    pasta = achar(ds, "sca_results.json")[0].parent
    cves = json.loads((pasta / "cve_data.json").read_text())
    k, v = next(iter(cves.items()))
    print(f"\n[exemplo] cve_data[{k!r}] = {json.dumps(v)[:400]}")
    fj = json.loads((pasta / "functions.json").read_text())["functions"]
    print(f"[exemplo] functions[0] = {fj[0]}")
    fb = json.loads((pasta / "sca_results.json").read_text())["findings"]
    print(f"[exemplo] findings[0] = {fb[0]}")
    print("[exemplo] valores distintos de found_by:",
          pd.Series([str(x.get('found_by')) for x in fb]).value_counts().head(12).to_dict())
    for p in achar(BRUTOS / "cwe_mapping", "buckets.json")[:1]:
        print(f"\n=== {p.relative_to(BRUTOS)}")
        _resumo(json.loads(p.read_text()))
    for csv in sorted(BRUTOS.glob("*.csv")):
        print(f"\n=== {csv.name}")
        print(pd.read_csv(csv, nrows=4).to_string())


# ----------------------------------------------------------------------------
# 3) LIMPAR -> tabela por CVE e tabela por funcao
# ----------------------------------------------------------------------------
CLASSES_ALTAS = {"664", "682", "691", "703", "707"}


def so_digitos(x):
    m = re.findall(r"\d+", str(x))
    return m[0] if m else None


def mapa_cwe_para_classe():
    """cwe_distr.csv (dos autores): LL_CWE_ID (tipo) -> HL_CWE_ID (classe)."""
    d = pd.read_csv(BRUTOS / "cwe_distr.csv")
    mapa = {str(int(l)): str(int(h)) for l, h in
            d[["LL_CWE_ID", "HL_CWE_ID"]].drop_duplicates().itertuples(index=False)}
    return mapa


def classe_via_buckets(cwe, buckets, vistos=None):
    """Plano B: sobe a hierarquia (child_of) do buckets.json ate uma classe alta."""
    vistos = vistos or set()
    if cwe in CLASSES_ALTAS:
        return cwe
    vistos.add(cwe)
    reg = buckets.get(f"CWE-{cwe}", {})
    for pai in re.findall(r"\d+", str(reg.get("child_of", ""))):
        if pai not in vistos:
            r = classe_via_buckets(pai, buckets, vistos)
            if r:
                return r
    return None


def mapa_tokens():
    """Token das ferramentas (ex.: FLF) -> nome, a partir do sca_data_1.csv dos autores."""
    df = pd.read_csv(BRUTOS / "sca_data_1.csv")
    d = {}
    for a, t in df[["Analyzer_Comb", "Comb_Token"]].drop_duplicates().itertuples(index=False):
        if str(a).lower() in FERRAMENTAS:
            d[str(t).lower()] = str(a).lower()
    return d


def norm_ferr(v, tokens):
    v = str(v).strip().lower()
    return v if v in FERRAMENTAS else tokens.get(v, v)


def intervalo(x):
    n = re.findall(r"\d+", str(x))
    assert len(n) >= 2, f"line_range em formato inesperado: {x!r}"
    return int(n[0]), int(n[1])


def mapear(fun, al, borda="incl", modo="todas"):
    """Liga alertas a funcoes. Devolve (DataFrame[ferramenta, fid, cwe, linha], n_alertas_sem_arquivo)."""
    por_arq = {k: g for k, g in fun.groupby("arquivo")}
    out, sem = [], 0
    grande = np.iinfo(np.int64).max // 4
    for arq, g in al.groupby("arquivo_f"):
        fa = por_arq.get(arq)
        if fa is None:
            sem += len(g)
            continue
        L = g["linha"].to_numpy()[:, None]
        ini = fa["inicio"].to_numpy()[None, :]
        fim = fa["fim"].to_numpy()[None, :]
        ge = (ini <= L) if borda in ("incl", "ex_fim") else (ini < L)
        le = (L <= fim) if borda in ("incl", "ex_ini") else (L < fim)
        mask = ge & le
        if modo == "todas":
            ai, fi = np.nonzero(mask)
        else:
            larg = fim - ini
            chave = larg if modo == "mais_interna" else (-ini * 10_000_000 + larg)
            chave = np.where(mask, chave, grande)
            idx = chave.argmin(axis=1)
            ai = np.nonzero(mask.any(axis=1))[0]
            fi = idx[ai]
        out.append(pd.DataFrame({"ferramenta": g["ferramenta"].to_numpy()[ai],
                                 "fid": fa["fid"].to_numpy()[fi],
                                 "cwe": g["cwe"].to_numpy()[ai],
                                 "linha": g["linha"].to_numpy()[ai]}))
    marc = (pd.concat(out) if out else pd.DataFrame(columns=["ferramenta", "fid", "cwe", "linha"])
            ).drop_duplicates()
    return marc, sem


def carregar_programa(pasta, mapa_cls, buckets, tokens, borda=None, modo=None):
    borda, modo = borda or BORDA, modo or MODO
    nome = pasta.name.lower()
    funcs = json.loads((pasta / "functions.json").read_text())
    funcs = funcs["functions"] if isinstance(funcs, dict) and "functions" in funcs else funcs
    cves = json.loads((pasta / "cve_data.json").read_text())
    sca = json.loads((pasta / "sca_results.json").read_text())
    sca = sca["findings"] if isinstance(sca, dict) and "findings" in sca else sca

    # --- funcoes
    linhas = []
    for f in funcs:
        i, j = intervalo(pegar(f, "intervalo", contexto=f"({nome}/functions.json)"))
        linhas.append({"programa": nome, "arquivo": pegar(f, "arquivo", contexto=f"({nome})"),
                       "inicio": i, "fim": j, "nome": pegar(f, "nome_func", obrigatorio=False)})
    fun = pd.DataFrame(linhas)
    fun["fid"] = np.arange(len(fun))

    # --- alertas (found_by pode ser texto ou lista)
    al = []
    for a in sca:
        fb = pegar(a, "ferramenta", contexto=f"({nome}/sca_results.json)")
        for t in (fb if isinstance(fb, list) else [fb]):
            al.append((norm_ferr(t, tokens), pegar(a, "arquivo", contexto=f"({nome})"),
                       int(pegar(a, "linha", contexto=f"({nome})")),
                       so_digitos(pegar(a, "cwe_alerta", obrigatorio=False))))
    al = pd.DataFrame(al, columns=["ferramenta", "arquivo", "linha", "cwe"])

    # --- alerta -> funcao (linha dentro do intervalo), vetorizado por arquivo
    por_arq = {k: g for k, g in fun.groupby("arquivo")}
    sem_exato = [a for a in al["arquivo"].unique() if a not in por_arq]
    n_sem_exato = int(al["arquivo"].isin(sem_exato).sum())
    alias = {}
    if CASAR_POR_SUFIXO and sem_exato:
        por_base = {}
        for f in por_arq:
            por_base.setdefault(f.rsplit("/", 1)[-1], []).append(f)
        for a in sem_exato:
            cand = [f for f in por_base.get(a.rsplit("/", 1)[-1], [])
                    if f.endswith("/" + a) or a.endswith("/" + f)]
            if len(cand) == 1:
                alias[a] = cand[0]
    al["arquivo_f"] = al["arquivo"].map(lambda a: alias.get(a, a))
    sem_final = al[~al["arquivo_f"].isin(por_arq)]
    exemplos = sem_final["arquivo"].value_counts().head(6).to_dict()
    marc, sem_arquivo = mapear(fun, al, borda, modo)

    # --- CVEs: funcoes afetadas e classe
    reg, refs_zero, refs_multi = [], 0, 0
    itens = cves.items() if isinstance(cves, dict) else \
        [(pegar(r, "cve_id", contexto=f"({nome}/cve_data)"), r) for r in cves]
    for cid, r in itens:
        afet, nao_cas = set(), 0
        for it in (pegar(r, "cve_funcs", obrigatorio=False) or []):
            if isinstance(it, dict):
                nm = pegar(it, "nome_func", obrigatorio=False)
                arq = pegar(it, "arquivo", obrigatorio=False)
            else:
                nm, arq = str(it), None
            cand = fun[fun["nome"] == nm]
            if arq is not None:
                cand = cand[cand["arquivo"] == arq]
            nao_cas += len(cand) == 0
            refs_zero += len(cand) == 0
            refs_multi += len(cand) > 1
            afet.update(cand["fid"].tolist())
        cw = pegar(r, "cve_cwe", obrigatorio=False)
        cw = [] if cw is None else (cw if isinstance(cw, list) else [cw])
        cw = [so_digitos(c) for c in cw if so_digitos(c)]
        cw_bruto = ";".join(cw)
        cw = [LL_AJUSTE.get(c, c) for c in cw]
        cls = sorted({mapa_cls.get(c) or classe_via_buckets(c, buckets) or "?" for c in cw})
        reg.append({"programa": nome, "cve": str(cid), "n_func_afetadas": len(afet),
                    "cwes": ";".join(cw), "cwes_brutos": cw_bruto, "classes": ";".join(cls),
                    "refs_nao_casadas": nao_cas, "afet": afet})
    info = {"_al": al, "alertas": len(al), "sem_arquivo_exato": n_sem_exato, "casados_por_sufixo": len(alias),
            "alertas_sem_arquivo_em_functions": sem_arquivo,
            "arquivos_sem_correspondencia(top)": exemplos,
            "exemplo_arquivos_em_functions": sorted(por_arq)[:3],
            "refs_func_sem_correspondencia": refs_zero, "refs_func_ambiguas": refs_multi}
    return fun, marc, pd.DataFrame(reg), info


def conferir_csv(cve, fun, m):
    """Compara nossos numeros com os CSV publicados pelos autores (sem alterar nada)."""
    sd = pd.read_csv(BRUTOS / "sca_data_1.csv")
    sd = sd[sd["Scenario"].str.contains("S.1-1", regex=False)].copy()
    sd["Target"] = sd["Target"].str.lower(); sd["a"] = sd["Analyzer_Comb"].str.lower()
    linhas = []
    for f in FERRAMENTAS:
        for prog, g in cve.groupby("programa"):
            ref = sd[(sd["a"] == f) & (sd["Target"] == prog)]
            if ref.empty:
                continue
            linhas.append({"ferramenta": f, "programa": prog,
                           "nossas": int(g[f"det_{f}"].sum()), "autores": int(ref["N_Detected_CVEs"].iloc[0]),
                           "n_nosso": len(g), "n_autores": int(ref["N_All_CVEs"].iloc[0])})
    # totais S1-1 por analisador/combinacao publicados x os nossos (robustez da escolha de A e de B)
    tot = sd.groupby("Analyzer_Comb").agg(detectadas=("N_Detected_CVEs", "sum"),
                                          n=("N_All_CVEs", "sum")).sort_values("detectadas", ascending=False)
    print("\n[sca_data_1, S1-1: total de CVEs detectadas por analisador/combinacao (autores)]\n",
          tot.head(12).to_string())
    nossos = {f: int(cve[f"det_{f}"].sum()) for f in FERRAMENTAS}
    nossos["COMBINACAO(6)"] = int(cve["det_combinada"].sum())
    print("[nossos totais S1-1]", nossos)
    aut_ind = {f: int(tot.loc[f, "detectadas"]) for f in FERRAMENTAS if f in tot.index}
    registrar("Ranking individual S1-1 (autores, soma dos programas)",
              sorted(aut_ind, key=lambda f: -aut_ind[f]))
    registrar("Ranking individual S1-1 (nosso)", sorted(nossos, key=lambda f: -nossos[f] if f in FERRAMENTAS else 1)[:7])
    t = pd.DataFrame(linhas)
    if not t.empty:
        t["bate"] = (t["nossas"] == t["autores"]) & (t["n_nosso"] == t["n_autores"])
        t.to_csv(LIMPOS / "conferencia_sca_data_1.csv", index=False)
        registrar("Conferencia com sca_data_1.csv (S1-1, individuais): linhas que batem",
                  f"{int(t['bate'].sum())} de {len(t)}")
        print("\n[sca_data_1: divergencias]\n", t[~t["bate"]].to_string(index=False))
    # ---- custo (VD secundaria): funcoes marcadas por ferramenta/programa x fct_stats_2.csv
    if (BRUTOS / "fct_stats_2.csv").exists():
        f2 = pd.read_csv(BRUTOS / "fct_stats_2.csv")
        f2["Target"] = f2["Target"].str.lower(); f2["a"] = f2["Analyzer_Comb"].str.lower()
        todas = [a for a in f2["a"].unique() if all(f in a for f in FERRAMENTAS)]
        conj = {f: m[f] for f in FERRAMENTAS}
        conj["__combinada__"] = set().union(*[m[f] for f in FERRAMENTAS])
        rot = {f: f for f in FERRAMENTAS}
        if todas:
            rot["__combinada__"] = todas[0]
        linhas2 = []
        for chave, nome_aut in rot.items():
            por_prog = fun["gid"].isin(conj[chave]).groupby(fun["programa"]).sum()
            for prog, v in por_prog.items():
                ref = f2[(f2["a"] == nome_aut) & (f2["Target"] == prog)]
                if not ref.empty:
                    linhas2.append({"analisador": chave, "programa": prog, "nossas": int(v),
                                    "autores": int(ref["N_Marked_Fcts"].iloc[0])})
        t2 = pd.DataFrame(linhas2)
        if not t2.empty:
            t2["bate"] = t2["nossas"] == t2["autores"]
            t2.to_csv(LIMPOS / "conferencia_fct_stats_2.csv", index=False)
            registrar("Conferencia de funcoes marcadas com fct_stats_2.csv: linhas que batem",
                      f"{int(t2['bate'].sum())} de {len(t2)}")
            print("\n[fct_stats_2: funcoes marcadas, divergencias]\n",
                  t2[~t2["bate"]].to_string(index=False))
            tot2 = t2.groupby("analisador")[["nossas", "autores"]].sum()
            print("\n[fct_stats_2: soma sobre programas]\n", tot2.to_string())
    f1 = pd.read_csv(BRUTOS / "fct_stats_1.csv")
    f1["Target"] = f1["Target"].str.lower()
    c = fun.groupby("programa").agg(n_nosso=("gid", "size"), v_nosso=("vulneravel", "sum"))
    r = f1.groupby("Target").agg(n_autores=("Function", "size"), v_autores=("Vulnerable", "sum"))
    cmp_ = c.join(r, how="outer")
    cmp_.to_csv(LIMPOS / "conferencia_fct_stats_1.csv")
    print("\n[fct_stats_1: nosso x autores]\n", cmp_.to_string())
    registrar("Conferencia de funcoes com fct_stats_1.csv: programas que batem (n e vulneraveis)",
              f"{int(((cmp_['n_nosso']==cmp_['n_autores'])&(cmp_['v_nosso']==cmp_['v_autores'])).sum())} de {len(cmp_)}")


def conferir_cwe(cve):
    """Compara contagem de CVEs por (programa, CWE de baixo nivel) com cwe_distr.csv."""
    d = pd.read_csv(BRUTOS / "cwe_distr.csv")
    d["Target"] = d["Target"].str.lower()
    aut = d.groupby(["Target", "LL_CWE_ID"])["N_CVEs"].sum()
    c = cve.copy()
    c["ll"] = pd.to_numeric(c["cwes"].str.split(";").str[0], errors="coerce")
    nos = c.groupby(["programa", "ll"]).size()
    nos.index.names = ["Target", "LL_CWE_ID"]
    t = pd.concat([nos.rename("nosso"), aut.rename("autores")], axis=1).fillna(0).astype(int)
    dif = t[t["nosso"] != t["autores"]]
    dif.to_csv(LIMPOS / "conferencia_cwe_distr_divergencias.csv")
    registrar("Conferencia (programa x CWE) com cwe_distr.csv: combinacoes divergentes", len(dif))
    if len(dif):
        print("\n[divergencias de CWE vs cwe_distr.csv]\n", dif.to_string())


def limpar():
    LIMPOS.mkdir(parents=True, exist_ok=True)
    mapa_cls = mapa_cwe_para_classe()
    bk = achar(BRUTOS / "cwe_mapping", "buckets.json")
    buckets = json.loads(bk[0].read_text()) if bk else {}
    tokens = mapa_tokens()
    registrar("Classe CWE: LL_CWE_ID -> HL_CWE_ID do cwe_distr.csv (plano B: buckets.json)",
              f"{len(mapa_cls)} CWE mapeadas; classes {sorted(set(mapa_cls.values()))}")
    registrar("Tokens de ferramenta (sca_data_1.csv)", tokens)

    pastas = sorted((BRUTOS / "dataset").rglob("sca_results.json"))
    assert pastas, "nenhum sca_results.json em dados/brutos/dataset"
    F, M, C = [], [], []
    for sr in pastas:
        fun, marc, cve, info = carregar_programa(sr.parent, mapa_cls, buckets, tokens)
        marc["programa"] = fun["programa"].iloc[0]
        registrar(f"Programa {sr.parent.name}: {len(fun)} funcoes, {len(cve)} CVEs",
                  {k: v for k, v in info.items() if not k.startswith("_")})
        F.append(fun); M.append(marc); C.append(cve)
    fun = pd.concat(F, ignore_index=True); marc = pd.concat(M, ignore_index=True)
    cve = pd.concat(C, ignore_index=True)

    fun["gid"] = fun["programa"] + ":" + fun["fid"].astype(str)
    marc["gid"] = marc["programa"] + ":" + marc["fid"].astype(str)
    vuln = {(r.programa, f) for r in cve.itertuples() for f in r.afet}
    fun["vulneravel"] = [(p, f) in vuln for p, f in zip(fun["programa"], fun["fid"])]

    # ---- exclusoes por regra DOCUMENTAL (nunca pelo resultado)
    sem_func = cve[cve["n_func_afetadas"] == 0]
    sem_classe = cve[(cve["n_func_afetadas"] > 0) & cve["classes"].str.contains(r"\?|^$", regex=True)]
    multi = cve[cve["classes"].str.contains(";")]
    registrar("CVEs lidas", len(cve))
    cve_todas = cve.copy()
    registrar("CVEs sem funcao afetada mapeada (excluidas)", f"{len(sem_func)}: {sem_func['cve'].tolist()}")
    registrar("CVEs sem classe resolvida (excluidas)",
              f"{len(sem_classe)}: " + str(sem_classe[['programa', 'cve', 'cwes']].values.tolist()))
    registrar("CVEs com mais de uma classe (REGRA A DEFINIR no adendo)", f"{len(multi)}: {multi['cve'].tolist()}")
    cand = cve[cve["refs_nao_casadas"] > 0]
    registrar("CVEs com funcao citada que nao existe em functions.json (candidatas a exclusao dos autores)",
              str(cand[["programa", "cve", "cwes_brutos", "n_func_afetadas"]].values.tolist()))
    cve = cve.drop(sem_func.index.union(sem_classe.index)).copy()
    if EXCLUIR_REF_AUSENTE:
        ex = cve[cve["refs_nao_casadas"] > 0]
        registrar("CVEs excluidas por citar funcao ausente de functions.json (EXCLUIR_REF_AUSENTE)",
                  ex[["programa", "cve"]].values.tolist())
        cve = cve.drop(ex.index).copy()
        vuln = {(r.programa, f) for r in cve.itertuples() for f in r.afet}
        fun["vulneravel"] = [(p, f) in vuln for p, f in zip(fun["programa"], fun["fid"])]
    if EXCLUIR_CVES:
        registrar("CVEs excluidas por reconciliacao com os autores (EXCLUIR_CVES)", EXCLUIR_CVES)
        cve = cve[~cve["cve"].isin(EXCLUIR_CVES)].copy()
    cve["classe"] = np.where(cve["classes"].str.split(";").str[0] == "664", "CWE-664", "Demais")
    registrar("CVE repetida no mesmo programa", int(cve.duplicated(["programa", "cve"], keep=False).sum()))
    dup_global = cve[cve.duplicated("cve", keep=False)]
    registrar("CVE presente em mais de um programa", f"{dup_global['cve'].nunique()}: {sorted(dup_global['cve'].unique())}")

    # ---- deteccao S1-1
    m = marc.groupby("ferramenta")["gid"].apply(set).to_dict()
    fora = sorted(set(m) - set(FERRAMENTAS))
    registrar("Ferramentas nos alertas fora da lista esperada (corrigir tokens!)", fora or "nenhuma")
    for f in FERRAMENTAS:
        m.setdefault(f, set())
        cve[f"det_{f}"] = [bool({f"{r.programa}:{x}" for x in r.afet} & m[f]) for r in cve.itertuples()]
    cve["det_combinada"] = cve[[f"det_{f}" for f in FERRAMENTAS]].any(axis=1)

    taxas = {f: cve[f"det_{f}"].mean() for f in FERRAMENTAS}
    pct_func = {f: len(m[f]) / len(fun) for f in FERRAMENTAS}
    melhor = sorted(FERRAMENTAS, key=lambda f: (-taxas[f], pct_func[f]))[0]
    registrar("Melhor individual = maior taxa de deteccao em S1-1 (empate: menor % de funcoes "
              "sinalizadas; criterio a declarar no adendo ANTES de rodar)", melhor)
    cve["det_melhor_individual"] = cve[f"det_{melhor}"]

    esperado = {"n_cve": len(cve), "n_cwe664": int((cve["classe"] == "CWE-664").sum()),
                "n_demais": int((cve["classe"] == "Demais").sum()),
                "n_funcoes": len(fun), "n_funcoes_vuln": int(fun["vulneravel"].sum())}
    for k, v in esperado.items():
        registrar(f"Conferencia {k} (protocolo)", f"{v} {'OK' if v == ESPERADO[k] else 'DIVERGE: esperado ' + str(ESPERADO[k])}")
    assert not (cve["det_melhor_individual"] & ~cve["det_combinada"]).any(), \
        "combinacao detectou MENOS que o melhor individual: erro de calculo"

    cve.drop(columns=["afet"]).to_csv(LIMPOS / "cve_por_estrategia.csv", index=False)
    ff = fun[["gid", "programa", "vulneravel"]].copy()
    for f in FERRAMENTAS:
        ff[f"marcada_{f}"] = ff["gid"].isin(m[f])
    ff["marcada_combinada"] = ff[[f"marcada_{f}" for f in FERRAMENTAS]].any(axis=1)
    ff["marcada_melhor_individual"] = ff[f"marcada_{melhor}"]
    ff.to_csv(LIMPOS / "funcoes_marcadas.csv", index=False)
    (LIMPOS / "melhor_individual.txt").write_text(melhor + "\n")
    try:
        conferir_cwe(cve_todas)
        conferir_csv(cve, fun, m)
    except Exception as e:           # a conferencia nao pode derrubar a limpeza
        registrar("Conferencia com CSV dos autores NAO executada", repr(e))
    pd.DataFrame(DIARIO).to_csv(LIMPOS / "diario_limpeza.csv", index=False)
    print(f"\nmelhor individual (S1-1): {melhor}")


def diagnosticar():
    """Testa hipoteses sobre POR QUE Cppcheck/CommSCA divergem dos autores (nao altera dados limpos)."""
    mapa_cls = mapa_cwe_para_classe()
    bk = achar(BRUTOS / "cwe_mapping", "buckets.json")
    buckets = json.loads(bk[0].read_text()) if bk else {}
    tokens = mapa_tokens()
    cj_buckets = {so_digitos(k) for k in buckets}
    cj_ll = set(mapa_cls)
    F, M, C = [], [], []
    for sr in sorted((BRUTOS / "dataset").rglob("sca_results.json")):
        fun, marc, cve, _ = carregar_programa(sr.parent, mapa_cls, buckets, tokens)
        marc["programa"] = fun["programa"].iloc[0]
        F.append(fun); M.append(marc); C.append(cve)
    marc = pd.concat(M, ignore_index=True); cve = pd.concat(C, ignore_index=True)
    sd = pd.read_csv(BRUTOS / "sca_data_1.csv")
    sd = sd[sd["Scenario"].str.contains("S.1-1", regex=False)].copy()
    sd["Target"] = sd["Target"].str.lower(); sd["a"] = sd["Analyzer_Comb"].str.lower()

    print("\n[CWE mais comuns nos alertas de cada ferramenta (cada ferramenta: top 8)]")
    for f in FERRAMENTAS:
        print(f, marc[marc["ferramenta"] == f]["cwe"].value_counts().head(8).to_dict())

    variantes = {
        "todas": lambda d: d,
        "cwe_em_buckets": lambda d: d[d["cwe"].isin(cj_buckets)],
        "cwe_em_21_LL": lambda d: d[d["cwe"].isin(cj_ll)],
        "cwe_nao_vazia": lambda d: d[d["cwe"].notna()],
    }
    for nome, filtro in variantes.items():
        m = filtro(marc)
        marc_set = {(p, f): set(g["fid"]) for (p, f), g in m.groupby(["programa", "ferramenta"])}
        linhas = []
        for f in FERRAMENTAS:
            for prog, g in cve.groupby("programa"):
                ref = sd[(sd["a"] == f) & (sd["Target"] == prog)]
                if ref.empty:
                    continue
                ms = marc_set.get((prog, f), set())
                det = sum(bool(a & ms) for a in g["afet"])
                linhas.append({"variante": nome, "ferramenta": f, "programa": prog, "nossas": det,
                               "autores": int(ref["N_Detected_CVEs"].iloc[0]),
                               "n_igual": len(g) == int(ref["N_All_CVEs"].iloc[0])})
        t = pd.DataFrame(linhas); t["bate"] = t["nossas"] == t["autores"]
        eq = t[t["n_igual"]]
        print(f"\n== variante {nome}: batem {int(eq['bate'].sum())} de {len(eq)} (so linhas com n de CVEs igual)")
        print("   por ferramenta:", eq.groupby("ferramenta")["bate"].sum().to_dict())
        t.to_csv(LIMPOS / f"diagnostico_{nome}.csv", index=False)

    # ---- evidencias das divergencias que sobram (variante 'todas')
    fun = pd.concat(F, ignore_index=True)
    cve = cve[cve["refs_nao_casadas"] == 0]
    print("\n[evidencias: CVEs que NOS contamos como detectadas, onde os autores contam menos]")
    for prog, ferr in [("ffmpeg", "infer"), ("ffmpeg", "codechecker"), ("php", "cppcheck"),
                       ("libxml2", "commsca"), ("libtiff", "cppcheck")]:
        mm = marc[(marc["programa"] == prog) & (marc["ferramenta"] == ferr)]
        fp = fun[fun["programa"] == prog].set_index("fid")
        print(f"\n-- {prog} / {ferr}")
        for r in cve[cve["programa"] == prog].itertuples():
            hit = mm[mm["fid"].isin(r.afet)]
            if len(hit):
                h = hit.iloc[0]; f = fp.loc[h["fid"]]
                print(f"  {r.cve}: {len(hit)} alerta(s); ex.: {f['arquivo']}::{f['nome']} "
                      f"[{f['inicio']}-{f['fim']}] alerta na linha {h['linha']} (CWE {h['cwe']})")

    # ---- funcoes vulneraveis: nossa lista x fct_stats_1.csv
    f1 = pd.read_csv(BRUTOS / "fct_stats_1.csv"); f1["Target"] = f1["Target"].str.lower()
    vul = {(r.programa, f) for r in cve.itertuples() for f in r.afet}
    print("\n[funcoes vulneraveis: so nossas (N) / so dos autores (A)]")
    for prog in ["libpng", "libxml2", "php", "poppler"]:
        fp = fun[fun["programa"] == prog]
        nossas = {(x.arquivo.rsplit("/", 1)[-1], x.nome) for x in fp.itertuples() if (prog, x.fid) in vul}
        a = f1[(f1["Target"] == prog) & (f1["Vulnerable"])]
        aut = {(x.File.rsplit("/", 1)[-1], x.Function) for x in a.itertuples()}
        print(f"-- {prog}: N={sorted(nossas - aut)}  A={sorted(aut - nossas)}")

    # ---- as funcoes "a mais": pertencem a CVEs com varias funcoes citadas?
    print("\n[funcoes vulneraveis so nossas: CVE que as cita e n de funcoes dessa CVE]")
    extras = {"libpng": ["png_free_data", "png_safe_execute", "png_read_start_row"],
              "libxml2": ["htmlParseTryOrFinish"], "php": ["exif_offset_info_try_get"]}
    for prog, nomes in extras.items():
        fp = fun[fun["programa"] == prog]
        for nm in nomes:
            fids = set(fp[fp["nome"] == nm]["fid"])
            for r in cve[cve["programa"] == prog].itertuples():
                if r.afet & fids:
                    print(f"  {prog}::{nm} <- {r.cve} (CVE cita {len(r.afet)} funcoes)")

    # ---- intervalos de funcao suspeitos: funcao que contem OUTRAS funcoes do mesmo arquivo
    print("\n[intervalos suspeitos: funcoes cujo line_range contem outra funcao do mesmo arquivo]")
    for prog, g in fun.groupby("programa"):
        suspeitas = []
        for arq, ga in g.groupby("arquivo"):
            ini, fim = ga["inicio"].to_numpy(), ga["fim"].to_numpy()
            for i in range(len(ga)):
                dentro = ((ini >= ini[i]) & (fim <= fim[i])).sum() - 1
                if dentro > 0:
                    suspeitas.append((int(dentro), arq, ga["nome"].iloc[i], int(ini[i]), int(fim[i])))
        suspeitas.sort(reverse=True)
        print(f"-- {prog}: {len(suspeitas)} de {len(g)} funcoes; 3 piores: {suspeitas[:3]}")


def mapeamento():
    """Calibra a regra alerta->funcao contra sca_data_1.csv e fct_stats_2.csv (publicados)."""
    mapa_cls = mapa_cwe_para_classe()
    bk = achar(BRUTOS / "cwe_mapping", "buckets.json")
    buckets = json.loads(bk[0].read_text()) if bk else {}
    tokens = mapa_tokens()
    dados = []
    for sr in sorted((BRUTOS / "dataset").rglob("sca_results.json")):
        fun, _, cve, info = carregar_programa(sr.parent, mapa_cls, buckets, tokens)
        dados.append((fun, info["_al"], cve[cve["refs_nao_casadas"] == 0]))
    sd = pd.read_csv(BRUTOS / "sca_data_1.csv")
    sd = sd[sd["Scenario"].str.contains("S.1-1", regex=False)].copy()
    sd["Target"] = sd["Target"].str.lower(); sd["a"] = sd["Analyzer_Comb"].str.lower()
    f2 = pd.read_csv(BRUTOS / "fct_stats_2.csv")
    f2["Target"] = f2["Target"].str.lower(); f2["a"] = f2["Analyzer_Comb"].str.lower()
    todas = [a for a in f2["a"].unique() if all(f in a for f in FERRAMENTAS)]
    linhas = []
    for borda in ["incl", "ex_ini", "ex_fim", "ex_ambos"]:
        for modo in ["todas", "mais_interna", "maior_inicio"]:
            m1 = t1 = m2 = t2 = 0
            for fun, al, cve in dados:
                prog = fun["programa"].iloc[0]
                marc, _ = mapear(fun, al, borda, modo)
                sets = marc.groupby("ferramenta")["fid"].apply(set).to_dict()
                sets["__comb__"] = set(marc["fid"])
                for f in FERRAMENTAS + ["__comb__"]:
                    ms = sets.get(f, set())
                    nome_f2 = todas[0] if f == "__comb__" and todas else f
                    r2 = f2[(f2["a"] == nome_f2) & (f2["Target"] == prog)]
                    if not r2.empty:
                        t2 += 1; m2 += len(ms) == int(r2["N_Marked_Fcts"].iloc[0])
                    if f != "__comb__":
                        r1 = sd[(sd["a"] == f) & (sd["Target"] == prog)]
                        if not r1.empty:
                            t1 += 1
                            m1 += sum(bool(x & ms) for x in cve["afet"]) == int(r1["N_Detected_CVEs"].iloc[0])
            linhas.append({"borda": borda, "modo": modo, "sca_data_1 (S1-1)": f"{m1}/{t1}",
                           "fct_stats_2 (funcoes marcadas)": f"{m2}/{t2}"})
            print(linhas[-1])
    pd.DataFrame(linhas).to_csv(LIMPOS / "calibracao_mapeamento.csv", index=False)


# ----------------------------------------------------------------------------
# 4) DESCREVER: tabelas + figura (sem teste: o teste e do Marco 3, 17/11)
# ----------------------------------------------------------------------------
def wilson(k, n, z=1.96):
    if n == 0:
        return (np.nan, np.nan)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h, c + h)


def descrever():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    TABS.mkdir(exist_ok=True); FIGS.mkdir(exist_ok=True)
    cve = pd.read_csv(LIMPOS / "cve_por_estrategia.csv")
    fun = pd.read_csv(LIMPOS / "funcoes_marcadas.csv")
    melhor = (LIMPOS / "melhor_individual.txt").read_text().strip()

    # T1: deteccao por ferramenta e estrategias (n = CVEs)
    linhas = []
    for col, nome in [(f"det_{f}", f) for f in FERRAMENTAS] + [("det_combinada", "COMBINACAO (6)")]:
        k, n = int(cve[col].sum()), len(cve)
        lo, hi = wilson(n - k, n)
        linhas.append({"estrategia": nome, "detectadas": k, "n": n,
                       "fn_pct": round(100 * (n - k) / n, 1),
                       "ic95_fn_pct": f"[{100*lo:.1f}; {100*hi:.1f}]",
                       "pct_funcoes_sinalizadas": round(100 * fun[f"marcada_{nome.lower()}"].mean(), 1)
                       if nome in FERRAMENTAS else round(100 * fun["marcada_combinada"].mean(), 1)})
    t1 = pd.DataFrame(linhas); t1.to_csv(TABS / "t1_deteccao_por_estrategia.csv", index=False)
    print("\nT1 (S1-1)\n", t1.to_string(index=False))

    # T2: A x B por classe (descritiva da hipotese principal e da moderadora)
    linhas = []
    for classe, g in [("Todas", cve)] + list(cve.groupby("classe")):
        n = len(g)
        a, b = g["det_melhor_individual"], g["det_combinada"]
        linhas.append({"classe": classe, "n_cve": n,
                       "fn_A_pct": round(100 * (1 - a.mean()), 1),
                       "fn_B_pct": round(100 * (1 - b.mean()), 1),
                       "ganho_pp": round(100 * (b.mean() - a.mean()), 1),
                       "so_B_detecta (b)": int((b & ~a).sum()),
                       "so_A_detecta (c)": int((a & ~b).sum()),
                       "ambas_detectam": int((a & b).sum()),
                       "nenhuma_detecta": int((~a & ~b).sum())})
    t2 = pd.DataFrame(linhas); t2.to_csv(TABS / "t2_A_vs_B_por_classe.csv", index=False)
    print("\nT2\n", t2.to_string(index=False))

    # T3: custo por programa (unidade n = 9 programas)
    t3 = fun.groupby("programa").agg(
        funcoes=("gid", "size"), vulneraveis=("vulneravel", "sum"),
        pct_A=("marcada_melhor_individual", lambda s: round(100 * s.mean(), 1)),
        pct_B=("marcada_combinada", lambda s: round(100 * s.mean(), 1))).reset_index()
    t3["aumento_pp"] = (t3["pct_B"] - t3["pct_A"]).round(1)
    t3.to_csv(TABS / "t3_custo_por_programa.csv", index=False)
    print("\nT3\n", t3.to_string(index=False))

    # Figura 1: barras comecando em zero, n anotado, IC de Wilson; custo por programa
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.2), gridspec_kw={"width_ratios": [1.1, 1]})
    cats = ["Todas", "CWE-664", "Demais"]
    x = np.arange(len(cats)); w = 0.36
    for i, (col, rot, cor) in enumerate([("det_melhor_individual", f"A: {melhor}", "#7f7f7f"),
                                         ("det_combinada", "B: combinação dos 6", "#1f77b4")]):
        vals, err = [], []
        for c in cats:
            g = cve if c == "Todas" else cve[cve["classe"] == c]
            n, k = len(g), int((~g[col]).sum())
            p = 100 * k / n; lo, hi = wilson(k, n)
            vals.append(p); err.append([p - 100 * lo, 100 * hi - p])
        ax[0].bar(x + (i - .5) * w, vals, w, label=rot, color=cor,
                  yerr=np.array(err).T, capsize=3)
    ax[0].set_xticks(x, [f"{c}\n(n={len(cve) if c=='Todas' else int((cve['classe']==c).sum())})" for c in cats])
    ax[0].set_ylabel("Taxa de falsos negativos (% das CVEs)"); ax[0].set_ylim(0, 100)
    ax[0].set_title("Falsos negativos (S1-1), IC 95% de Wilson"); ax[0].legend(frameon=False)
    p = t3.sort_values("pct_B")
    y = np.arange(len(p))
    ax[1].hlines(y, p["pct_A"], p["pct_B"], color="#bbbbbb")
    ax[1].scatter(p["pct_A"], y, color="#7f7f7f", label="A", zorder=3)
    ax[1].scatter(p["pct_B"], y, color="#1f77b4", label="B", zorder=3)
    ax[1].set_yticks(y, p["programa"]); ax[1].set_xlim(left=0)
    ax[1].set_xlabel("Funções sinalizadas (% das funções do programa)")
    ax[1].set_title("Custo: A → B em cada programa"); ax[1].legend(frameon=False)
    fig.tight_layout(); fig.savefig(FIGS / "fig1_fn_e_custo.png", dpi=200)
    print("\nfigura:", FIGS / "fig1_fn_e_custo.png")


if __name__ == "__main__":
    etapas = {"baixar": baixar, "inspecionar": inspecionar, "limpar": limpar,
              "diagnosticar": diagnosticar, "mapeamento": mapeamento,
              "descrever": descrever}
    if len(sys.argv) != 2 or sys.argv[1] not in etapas:
        sys.exit("uso: python src/marco2.py {baixar|inspecionar|limpar|diagnosticar|mapeamento|descrever}")
    etapas[sys.argv[1]]()
