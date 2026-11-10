"""Gera dados SINTETICOS (inventados) no ESQUEMA REAL dos arquivos (conferido com `inspecionar`),
so para testar se o codigo roda ponta a ponta. NUNCA usar a saida no artigo.
Uso (de dentro de Marco-3/):  python testes/gerar_fixture_sintetica.py /tmp/fx
                              MCEQ_FIXTURE=/tmp/fx python src/analise.py limpar   (e descrever)
Formatos ainda nao vistos (itens de cve_data['functions'] e line_range) sao variados de proposito."""
import json, sys
from pathlib import Path
import numpy as np
import pandas as pd
raiz = Path(sys.argv[1]); rng = np.random.default_rng(0)
B = raiz/"dados/brutos"
tok = {"flawfinder":"FLF","cppcheck":"CPP","infer":"INF","codechecker":"CDC","codeql":"CQL","commsca":"CSA"}
(B/"cwe_mapping/cwe_mapping").mkdir(parents=True, exist_ok=True)
(B/"cwe_mapping/cwe_mapping/buckets.json").write_text(json.dumps({"CWE-664":{"child_of":[],"parent_of":["CWE-119"]}}))
pd.DataFrame({"Target":"x","LL_CWE_ID":[119,416,190,476],"HL_CWE_ID":[664,664,682,703],"N_CVEs":0}).to_csv(B/"cwe_distr.csv",index=False)
f1, sd = [], []
for k, prog in enumerate(["binutils","libpng","sqlite3"]):
    d = B/f"dataset/dataset/{prog}"; d.mkdir(parents=True, exist_ok=True)
    funcs = [{"file":f"f{i//5}.c","name":f"fn{i}","line_range":([(i%5)*100+1,(i%5)*100+99] if k else f"{(i%5)*100+1}-{(i%5)*100+99}"),"LOC":9} for i in range(60)]
    cves = {}
    for j in range(10):
        a = funcs[rng.integers(0,60)]
        item = {"file":a["file"],"name":a["name"]} if k else a["name"]
        cves[f"CVE-0-{prog}-{j}"] = {"cwe":f"CWE-{rng.choice([119,416,190,476])}","functions":[item]}
    fb = []
    for t in tok:
        for _ in range(int(rng.integers(5,25))):
            f = funcs[rng.integers(0,60)]
            fb.append({"file":f["file"],"line":int(rng.integers(1,500)),"cwe":"CWE-119","found_by":tok[t]})
    for c in cves.values():
        if rng.random()<0.4:
            t=str(rng.choice(list(tok))); nm=c["functions"][0]["name"] if k else c["functions"][0]
            fn=[f for f in funcs if f["name"]==nm][0]
            fb.append({"file":fn["file"],"line":(((int(nm[2:])%5)*100)+5),"cwe":"CWE-119","found_by":tok[t]})
    (d/"functions.json").write_text(json.dumps({"functions":funcs}))
    (d/"cve_data.json").write_text(json.dumps(cves))
    (d/"sca_results.json").write_text(json.dumps({"findings":fb}))
    for f in funcs: f1.append({"Target":prog,"File":f["file"],"Function":f["name"],"LOC":9,"Vulnerable":False})
    for t,v in tok.items(): sd.append({"Analyzer_Comb":t,"Comb_Token":v,"Target":prog,"Scenario":"Scenario 1 (S.1-1)","N_Detected_CVEs":0,"N_All_CVEs":10})
pd.DataFrame(f1).to_csv(B/"fct_stats_1.csv",index=False); pd.DataFrame(sd).to_csv(B/"sca_data_1.csv",index=False)
