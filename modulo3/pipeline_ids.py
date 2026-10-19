"""
pipeline_ids.py -- Tarefa do orientador (3 tipos de modelo, 5 algoritmos).

Uso (a partir de ~/TCC_FoundationModels_IDS):
    python3 modulo3/montar_base_semana.py          # antes: rotula terca a sexta
    python3 modulo3/pipeline_ids.py preparar      # [--excluir Infiltration --tag sem_infiltration]
    (use o MESMO --tag em todas as etapas seguintes)
    python3 modulo3/pipeline_ids.py binario
    python3 modulo3/pipeline_ids.py multiclasse
    python3 modulo3/pipeline_ids.py por_ataque --modelo RandomForest
    python3 modulo3/pipeline_ids.py relatorio

Dependencias: pip install pandas numpy scikit-learn lightgbm pyarrow matplotlib
"""
import argparse
import json
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler, label_binarize
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore")

SEED = 42
N_JOBS = 4
SPLITS_DIR = Path("modulo3/splits")
RES_DIR = Path("modulo3/resultados")
N_BENIGN = {"treino": 300_000, "validacao": 100_000, "teste": 100_000}
MIN_ATAQUE = 500  # so ataques com mais de 500 observacoes

# Colunas de ENTRADA dos modelos. Ficam de fora de proposito:
#  - src_ip/dst_ip/timestamps: o rotulo foi CRIADO a partir de IP + horario,
#    entao usar essas colunas seria vazamento de rotulo (o modelo so "decora"
#    a regra de rotulagem).
#  - id, expiration_id, MACs, vlan_id/tunnel_id (constantes), src_port (efemera).
BASE_FEATURES = [
    "dst_port", "protocol", "ip_version",
    "bidirectional_duration_ms", "bidirectional_packets", "bidirectional_bytes",
    "src2dst_duration_ms", "src2dst_packets", "src2dst_bytes",
    "dst2src_duration_ms", "dst2src_packets", "dst2src_bytes",
]


def features_de(df):
    X = df[BASE_FEATURES].astype("float64").copy()
    X["bytes_por_pacote"] = X["bidirectional_bytes"] / X["bidirectional_packets"].clip(lower=1)
    X["razao_pacotes_s2d_d2s"] = X["src2dst_packets"] / (X["dst2src_packets"] + 1)
    return X.replace([np.inf, -np.inf], np.nan)


# ----------------------------------------------------------------- preparar
def preparar(csv, excluir=()):
    df = pd.read_csv(csv, usecols=BASE_FEATURES + ["Label"], low_memory=False)
    print("Base:", df.shape)
    if excluir:
        df = df[~df["Label"].isin(excluir)]
        print("Classes excluidas:", list(excluir), "->", df.shape)
    X = features_de(df)
    df = pd.concat([X, df["Label"]], axis=1).dropna().reset_index(drop=True)

    contagem = df["Label"].value_counts()
    print("Contagem por classe:\n", contagem.to_string())
    ataques_ok = [c for c in contagem.index if c != "BENIGN" and contagem[c] > MIN_ATAQUE]
    descartados = [c for c in contagem.index if c != "BENIGN" and c not in ataques_ok]
    print("Ataques mantidos:", ataques_ok)
    print("Ataques descartados (<= %d):" % MIN_ATAQUE, descartados)

    benign = df[df["Label"] == "BENIGN"]
    precisa = sum(N_BENIGN.values())
    if len(benign) < precisa:
        raise SystemExit(f"Benignos insuficientes: {len(benign)} < {precisa}. "
                         "Use a base da semana inteira ou reduza N_BENIGN.")
    benign = benign.sample(n=precisa, random_state=SEED)
    n1, n2 = N_BENIGN["treino"], N_BENIGN["treino"] + N_BENIGN["validacao"]
    partes_b = {"treino": benign.iloc[:n1],
                "validacao": benign.iloc[n1:n2],
                "teste": benign.iloc[n2:]}

    atk = df[df["Label"].isin(ataques_ok)]
    a_tr, a_rest = train_test_split(atk, train_size=0.70, stratify=atk["Label"], random_state=SEED)
    a_va, a_te = train_test_split(a_rest, train_size=2 / 3, stratify=a_rest["Label"], random_state=SEED)
    partes_a = {"treino": a_tr, "validacao": a_va, "teste": a_te}

    SPLITS_DIR.mkdir(parents=True, exist_ok=True)
    meta = {}
    for nome in N_BENIGN:
        s = pd.concat([partes_b[nome], partes_a[nome]]).sample(frac=1, random_state=SEED)
        s["y_bin"] = (s["Label"] != "BENIGN").astype("int8")
        s.reset_index(drop=True).to_parquet(SPLITS_DIR / f"{nome}.parquet")
        meta[nome] = s["Label"].value_counts().to_dict()
        print(f"\n{nome}: {len(s)} linhas\n", s["Label"].value_counts().to_string())
    (SPLITS_DIR / "meta.json").write_text(json.dumps(
        {"ataques": ataques_ok, "descartados": descartados, "contagens": meta}, indent=2))


# ------------------------------------------------------------------ modelos
def fabrica_modelos(multiclasse=False):
    import lightgbm as lgb
    return {
        "LogisticRegression": lambda: LogisticRegression(max_iter=300, class_weight="balanced", n_jobs=N_JOBS),
        "DecisionTree": lambda: DecisionTreeClassifier(max_depth=20, class_weight="balanced", random_state=SEED),
        "RandomForest": lambda: RandomForestClassifier(n_estimators=100, n_jobs=N_JOBS,
                                                       class_weight="balanced", random_state=SEED),
        "LightGBM": lambda: lgb.LGBMClassifier(n_estimators=200, class_weight="balanced",
                                               n_jobs=N_JOBS, random_state=SEED, verbose=-1),
        "MLP": lambda: MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=50, early_stopping=True,
                                     random_state=SEED),
    }


def carregar():
    d = {n: pd.read_parquet(SPLITS_DIR / f"{n}.parquet") for n in N_BENIGN}
    return d


def preparar_X(d):
    """log1p nas colunas nao negativas + padronizacao ajustada SO no treino."""
    X = {}
    for n, df in d.items():
        x = df.drop(columns=["Label", "y_bin"]).copy()
        for c in x.columns:
            if (x[c] >= 0).all():
                x[c] = np.log1p(x[c])
        X[n] = x
    sc = StandardScaler().fit(X["treino"])
    return {n: sc.transform(x) for n, x in X.items()}


def metricas_bin(y, p, limiar=0.5):
    pred = (p >= limiar).astype(int)
    return {"AUC": roc_auc_score(y, p), "AUC_PR": average_precision_score(y, p),
            "F1": f1_score(y, pred, zero_division=0),
            "Precisao": precision_score(y, pred, zero_division=0),
            "Recall": recall_score(y, pred, zero_division=0)}


def metricas_multi(y, proba, k):
    Y = label_binarize(y, classes=range(k))
    pred = proba.argmax(1)
    por_classe = []
    for i in range(k):
        por_classe.append({
            "classe_idx": i,
            "AUC": roc_auc_score(Y[:, i], proba[:, i]) if Y[:, i].any() else np.nan,
            "AUC_PR": average_precision_score(Y[:, i], proba[:, i]) if Y[:, i].any() else np.nan,
            "F1": f1_score(Y[:, i], pred == i, zero_division=0),
            "Precisao": precision_score(Y[:, i], pred == i, zero_division=0),
            "Recall": recall_score(Y[:, i], pred == i, zero_division=0)})
    pc = pd.DataFrame(por_classe)
    macro = {"AUC": pc["AUC"].mean(), "AUC_PR": pc["AUC_PR"].mean(),
             "F1": f1_score(y, pred, average="macro", zero_division=0),
             "Precisao": precision_score(y, pred, average="macro", zero_division=0),
             "Recall": recall_score(y, pred, average="macro", zero_division=0)}
    return macro, pc


# --------------------------------------------------------------- tarefas 1,2
def binario():
    d = carregar()
    X = preparar_X(d)
    linhas = []
    for nome, f in fabrica_modelos().items():
        t = time.time()
        m = f().fit(X["treino"], d["treino"]["y_bin"])
        tempo = time.time() - t
        for s in N_BENIGN:
            p = m.predict_proba(X[s])[:, 1]
            linhas.append({"modelo": nome, "split": s, **metricas_bin(d[s]["y_bin"], p),
                           "tempo_treino_s": tempo})
        print(f"[binario] {nome} ok ({tempo:.0f}s)")
    RES_DIR.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(linhas).to_csv(RES_DIR / "binario.csv", index=False)


def multiclasse():
    d = carregar()
    X = preparar_X(d)
    le = LabelEncoder().fit(d["treino"]["Label"])
    y = {s: le.transform(d[s]["Label"]) for s in N_BENIGN}
    k = len(le.classes_)
    linhas, pcs = [], []
    for nome, f in fabrica_modelos(True).items():
        t = time.time()
        m = f().fit(X["treino"], y["treino"])
        tempo = time.time() - t
        for s in N_BENIGN:
            macro, pc = metricas_multi(y[s], m.predict_proba(X[s]), k)
            linhas.append({"modelo": nome, "split": s, **macro, "tempo_treino_s": tempo})
            pc["classe"] = le.inverse_transform(pc["classe_idx"])
            pc["modelo"], pc["split"] = nome, s
            pcs.append(pc.drop(columns="classe_idx"))
        print(f"[multiclasse] {nome} ok ({tempo:.0f}s)")
    RES_DIR.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(linhas).to_csv(RES_DIR / "multiclasse.csv", index=False)
    pd.concat(pcs).to_csv(RES_DIR / "multiclasse_por_classe.csv", index=False)


# ------------------------------------------------------------------ tarefa 3
def por_ataque(nome_modelo):
    d = carregar()
    X = preparar_X(d)
    f = fabrica_modelos()[nome_modelo]
    ataques = json.loads((SPLITS_DIR / "meta.json").read_text())["ataques"]
    linhas = []
    for atk in ataques:
        mask = {s: (d[s]["Label"].isin(["BENIGN", atk])).to_numpy() for s in N_BENIGN}
        y = {s: (d[s]["Label"][mask[s]] == atk).astype(int).to_numpy() for s in N_BENIGN}
        m = f().fit(X["treino"][mask["treino"]], y["treino"])
        for s in N_BENIGN:
            p = m.predict_proba(X[s][mask[s]])[:, 1]
            linhas.append({"ataque": atk, "modelo": nome_modelo, "split": s,
                           "n_ataque": int(y[s].sum()), **metricas_bin(y[s], p)})
        print(f"[por_ataque] {atk} ok")
    RES_DIR.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(linhas).to_csv(RES_DIR / f"por_ataque_{nome_modelo}.csv", index=False)


# ----------------------------------------------------------------- relatorio
def relatorio():
    RES_DIR.mkdir(parents=True, exist_ok=True)
    partes = ["# Resumo dos resultados (conjunto de TESTE)\n"]
    for nome in ["binario", "multiclasse"]:
        p = RES_DIR / f"{nome}.csv"
        if p.exists():
            r = pd.read_csv(p)
            t = r[r["split"] == "teste"].drop(columns="split").round(4)
            partes.append(f"## {nome}\n\n{t.to_markdown(index=False)}\n")
    for p in sorted(RES_DIR.glob("por_ataque_*.csv")):
        r = pd.read_csv(p)
        t = r[r["split"] == "teste"].drop(columns="split").round(4)
        partes.append(f"## {p.stem}\n\n{t.to_markdown(index=False)}\n")
    (RES_DIR / "resumo.md").write_text("\n".join(partes))
    print("Gerado:", RES_DIR / "resumo.md")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("etapa", choices=["preparar", "binario", "multiclasse", "por_ataque", "relatorio"])
    ap.add_argument("--csv", default="modulo3/base_semana_rotulada.csv")
    ap.add_argument("--excluir", nargs="*", default=[], help="classes a remover, ex.: --excluir Infiltration")
    ap.add_argument("--modelo", default="RandomForest")
    ap.add_argument("--tag", default="", help="sufixo das pastas de saida, ex.: --tag sem_infiltration (evita sobrescrever outra execucao)")
    a = ap.parse_args()
    if a.tag:
        SPLITS_DIR = Path(f"modulo3/splits_{a.tag}")
        RES_DIR = Path(f"modulo3/resultados_{a.tag}")
    if a.etapa == "preparar":
        preparar(a.csv, a.excluir)
    elif a.etapa == "binario":
        binario()
    elif a.etapa == "multiclasse":
        multiclasse()
    elif a.etapa == "por_ataque":
        por_ataque(a.modelo)
    else:
        relatorio()
