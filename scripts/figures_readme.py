"""Génère les figures du README (docs/figures), en version claire et sombre.

    python scripts/figures_readme.py

Sources des données :
  - results/exemple/            une simulation complète (30 Sybils, graine 1)
  - results/balayage_sybils.csv 30 simulations par nombre de Sybils (scripts/simuler.py)
  - RESULTATS_SOUTENANCE        tableau présenté à la soutenance (300 simulations)

Dépendances : matplotlib, numpy.
"""

import csv
import logging
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)

import matplotlib.pyplot as plt
import numpy as np
from matplotlib import font_manager
from matplotlib.patches import PathPatch
from matplotlib.path import Path as MplPath

RACINE = Path(__file__).resolve().parent.parent
EXEMPLE = RACINE / "results" / "exemple"
BALAYAGE = RACINE / "results" / "balayage_sybils.csv"
FIGURES = RACINE / "docs" / "figures"

# Taux de réussite de la défense présentés à la soutenance
# (300 simulations par colonne, proximité 2^144, 5 000 nœuds, 1 h simulée)
RESULTATS_SOUTENANCE = {25: 99.9, 30: 99.6, 50: 99.9, 75: 98.0, 100: 92.0, 200: 49.0, 500: 0.67}

THEMES = {
    "clair": {
        "surface": "#ffffff", "encre": "#0b0b0b", "encre2": "#52514e", "discret": "#898781",
        "grille": "#e1e0d9", "axe": "#c3c2b7",
        "bleu": "#2a78d6", "orange": "#eb6834", "vert": "#1baf7a", "neutre": "#c3c2b7",
    },
    "sombre": {
        "surface": "#0d1117", "encre": "#f0efec", "encre2": "#c3c2b7", "discret": "#898781",
        "grille": "#262b33", "axe": "#3d444d",
        "bleu": "#3987e5", "orange": "#d95926", "vert": "#199e70", "neutre": "#4b525c",
    },
}

for police in font_manager.findSystemFonts():
    if "Inter-" in police:
        font_manager.fontManager.addfont(police)


def fr(valeur, decimales=1):
    """Nombre au format français (virgule décimale)."""
    return f"{valeur:.{decimales}f}".replace(".", ",")


# ---------------------------------------------------------------------------
# Outils matplotlib
# ---------------------------------------------------------------------------


def nouvelle_figure(t, largeur=8.0, hauteur=4.3, **kwargs):
    plt.rcParams.update({
        "font.family": ["Inter", "Segoe UI", "Helvetica Neue", "Arial", "DejaVu Sans"],
        "font.size": 10,
        "text.color": t["encre"],
        "axes.edgecolor": t["axe"],
        "axes.labelcolor": t["encre2"],
        "xtick.color": t["discret"],
        "ytick.color": t["discret"],
        "xtick.labelcolor": t["encre2"],
        "ytick.labelcolor": t["encre2"],
        "figure.facecolor": t["surface"],
        "axes.facecolor": t["surface"],
        "savefig.facecolor": t["surface"],
        "legend.frameon": False,
    })
    return plt.subplots(figsize=(largeur, hauteur), **kwargs)


def habiller(ax, t, grille_y=True):
    for cote in ("top", "right", "left"):
        ax.spines[cote].set_visible(False)
    ax.spines["bottom"].set_color(t["axe"])
    ax.tick_params(length=0)
    if grille_y:
        ax.grid(axis="y", color=t["grille"], linewidth=0.8)
    ax.set_axisbelow(True)


def titrer(fig, t, titre, sous_titre, gauche=0.075):
    fig.text(gauche, 0.955, titre, fontsize=13.5, fontweight="semibold", color=t["encre"], va="top")
    fig.text(gauche, 0.885, sous_titre, fontsize=9.5, color=t["encre2"], va="top")


def colonnes(ax, xs, valeurs, couleur, largeur_px=52, rayon_px=8):
    """Colonnes fines à sommet arrondi, base carrée sur l'axe."""
    fig = ax.figure
    fig.canvas.draw()
    origine = ax.transData.transform((0, 0))
    unite = ax.transData.transform((1, 1)) - origine
    demi = largeur_px / 2 / unite[0]
    for x, v in zip(xs, valeurs):
        if v <= 0:
            continue
        ry = min(rayon_px / unite[1], v)
        rx = rayon_px / unite[0]
        g, d = x - demi, x + demi
        sommets = [
            (g, 0), (g, v - ry), (g, v), (g + rx, v),
            (d - rx, v), (d, v), (d, v - ry), (d, 0), (g, 0),
        ]
        codes = [
            MplPath.MOVETO, MplPath.LINETO, MplPath.CURVE3, MplPath.CURVE3,
            MplPath.LINETO, MplPath.CURVE3, MplPath.CURVE3, MplPath.LINETO, MplPath.CLOSEPOLY,
        ]
        ax.add_patch(PathPatch(MplPath(sommets, codes), facecolor=couleur, edgecolor="none", zorder=2))


def enregistrer(fig, nom, theme):
    FIGURES.mkdir(parents=True, exist_ok=True)
    chemin = FIGURES / f"{nom}-{theme}.png"
    fig.savefig(chemin, dpi=200)
    plt.close(fig)
    print("  ", chemin.relative_to(RACINE))


# ---------------------------------------------------------------------------
# Lecture des données
# ---------------------------------------------------------------------------


def lire_csv(chemin):
    with open(chemin, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def wilson(succes, n, z=1.96):
    """Intervalle de confiance à 95 % d'une proportion (méthode de Wilson)."""
    p = succes / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    demi = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return 100 * max(0.0, centre - demi), 100 * min(1.0, centre + demi)


def lire_balayage():
    """Regroupe le balayage par nombre de Sybils."""
    groupes = {}
    for ligne in lire_csv(BALAYAGE):
        groupes.setdefault(int(ligne["sybils"]), []).append(ligne)
    resume = {}
    for sybils, lignes in sorted(groupes.items()):
        n = len(lignes)
        succes = sum(int(l["defense_reussie"]) for l in lignes)
        delais = [int(l["premiere_defense_ms"]) / 60000 for l in lignes if l["premiere_defense_ms"]]
        resume[sybils] = {
            "n": n,
            "succes": succes,
            "taux": 100 * succes / n,
            "ic": wilson(succes, n),
            "delai_median": float(np.median(delais)) if delais else None,
            "delais": delais,
        }
    return resume


# ---------------------------------------------------------------------------
# Figure 1 : taux de réussite selon le nombre de Sybils
# ---------------------------------------------------------------------------


def figure_taux_reussite(t, theme):
    balayage = lire_balayage() if BALAYAGE.exists() else {}
    sybils = list(RESULTATS_SOUTENANCE)
    xs = np.arange(len(sybils))

    fig, ax = nouvelle_figure(t)
    fig.subplots_adjust(left=0.075, right=0.975, top=0.74, bottom=0.2)
    ax.set_xlim(-0.6, len(sybils) - 0.4)
    ax.set_ylim(0, 108)
    habiller(ax, t)

    colonnes(ax, xs, [RESULTATS_SOUTENANCE[s] for s in sybils], t["bleu"])
    for x, s in zip(xs, sybils):
        v = RESULTATS_SOUTENANCE[s]
        ax.text(x, v + 2.5, f"{fr(v, 2 if v < 1 else 1)} %", ha="center", va="bottom",
                fontsize=9.5, fontweight="medium", color=t["encre"])

    if balayage:
        for x, s in zip(xs, sybils):
            if s not in balayage:
                continue
            b = balayage[s]
            ax.plot([x + 0.31, x + 0.31], b["ic"], color=t["encre2"], linewidth=1.4,
                    solid_capstyle="round", zorder=3)
            ax.plot(x + 0.31, b["taux"], "o", markersize=7.5, color=t["encre"],
                    markeredgecolor=t["surface"], markeredgewidth=1.6, zorder=4, clip_on=False)

    ax.set_xticks(xs, [str(s) for s in sybils])
    ax.set_yticks([0, 25, 50, 75, 100], ["0", "25", "50", "75", "100 %"])
    ax.set_xlabel("Nombre de nœuds Sybils injectés autour de la cible (réseau de 5 000 nœuds)")

    from matplotlib.lines import Line2D
    from matplotlib.patches import Patch

    legende = [Patch(facecolor=t["bleu"], label="Soutenance : 300 simulations par colonne")]
    if balayage:
        n = next(iter(balayage.values()))["n"]
        legende.append(Line2D([], [], marker="o", color=t["encre2"], markerfacecolor=t["encre"],
                              markeredgecolor=t["surface"], markersize=7.5, linewidth=1.4,
                              label=f"Reproduction avec ce dépôt : {n} simulations, intervalle à 95 %"))
    fig.legend(handles=legende, loc="upper left", bbox_to_anchor=(0.065, 0.845), ncols=2,
               fontsize=9, labelcolor=t["encre2"], handlelength=1.4, columnspacing=1.8)

    titrer(fig, t,
           "La défense lève la censure dans au moins 98 % des cas jusqu'à 75 Sybils",
           "Part des simulations où la donnée ciblée redevient accessible  ·  proximité des Sybils : 2^144, 1 h simulée")
    enregistrer(fig, "taux-reussite", theme)


# ---------------------------------------------------------------------------
# Figure 2 : délai de réaction selon le nombre de Sybils
# ---------------------------------------------------------------------------


def figure_delai_reaction(t, theme):
    if not BALAYAGE.exists():
        return
    balayage = {s: b for s, b in lire_balayage().items() if b["delai_median"] is not None}
    sybils = list(balayage)
    xs = np.arange(len(sybils))
    medianes = [balayage[s]["delai_median"] for s in sybils]

    fig, ax = nouvelle_figure(t, hauteur=3.9)
    fig.subplots_adjust(left=0.075, right=0.975, top=0.76, bottom=0.21)
    ax.set_xlim(-0.6, len(sybils) - 0.4)
    ax.set_ylim(0, max(medianes) * 1.22)
    habiller(ax, t)

    colonnes(ax, xs, medianes, t["bleu"])
    for x, s, m in zip(xs, sybils, medianes):
        ax.text(x, m + max(medianes) * 0.03, f"{fr(m)} min", ha="center", va="bottom",
                fontsize=9.5, fontweight="medium", color=t["encre"])
        ax.text(x, -max(medianes) * 0.2, f"{len(balayage[s]['delais'])}/{balayage[s]['n']}",
                ha="center", va="top", fontsize=8.5, color=t["discret"])

    ax.set_xticks(xs, [str(s) for s in sybils])
    ax.set_xlabel("Nombre de nœuds Sybils  ·  en gris : simulations où la défense a réagi", labelpad=22)
    ax.yaxis.set_major_formatter(lambda v, _: f"{v:.0f} min" if v else "0")

    titrer(fig, t,
           "Les attaques les plus discrètes sont les plus longues à repérer",
           "Délai médian entre le début de l'attaque et la première recherche non censurée (pas de mesure : 100 s)")
    enregistrer(fig, "delai-reaction", theme)


# ---------------------------------------------------------------------------
# Figure 3 : une simulation, de la censure totale à la neutralisation
# ---------------------------------------------------------------------------


def figure_exemple_censure(t, theme):
    lignes = lire_csv(EXEMPLE / "simulation_stats.csv")
    minutes, cumul, fenetre = [], [], []
    total_precedent = censure_precedente = 0
    for ligne in lignes[1:]:
        taux = float(ligne["CensorshipRate"])
        censurees = int(ligne["CensoredSearches"])
        total = round(censurees / taux) if taux > 0 else total_precedent
        minutes.append(int(ligne["Timestamp"]) / 60000)
        cumul.append(100 * taux)
        nouvelles = total - total_precedent
        fenetre.append(100 * (censurees - censure_precedente) / nouvelles if nouvelles else 0)
        total_precedent, censure_precedente = total, censurees

    reaction = next(m for m, c in zip(minutes, cumul) if c < 100)

    fig, ax = nouvelle_figure(t, hauteur=4.1)
    fig.subplots_adjust(left=0.075, right=0.975, top=0.75, bottom=0.15)
    ax.set_xlim(0, 60)
    ax.set_ylim(0, 108)
    habiller(ax, t)

    # Taux par fenêtre de 100 s : chaque valeur couvre l'intervalle qui se termine à l'instant mesuré
    xs = [0] + minutes
    ys = [fenetre[0]] + fenetre
    ax.fill_between(xs, ys, step="pre", color=t["orange"], alpha=0.12, linewidth=0)
    ax.step(xs, ys, where="pre", color=t["orange"], linewidth=2, solid_joinstyle="round",
            label="Sur les 100 dernières secondes")
    ax.plot(minutes, cumul, color=t["bleu"], linewidth=2, solid_capstyle="round",
            label="Cumulé depuis le début (indicateur suivi par la simulation)")
    ax.plot(minutes[-1], cumul[-1], "o", markersize=7.5, color=t["bleu"],
            markeredgecolor=t["surface"], markeredgewidth=1.6, clip_on=False, zorder=5)
    ax.text(59.2, cumul[-1] + 4, f"{fr(cumul[-1])} %", ha="right", va="bottom", fontsize=9.5,
            fontweight="medium", color=t["encre"])

    ax.plot([reaction + 0.3, reaction + 1.3], [20, 20], color=t["discret"], linewidth=1)
    ax.text(reaction + 1.7, 20, "Attaque détectée :\nle voisinage de la cible est élargi",
            fontsize=9.5, color=t["encre"], va="center", linespacing=1.4)

    ax.set_xticks([0, 10, 20, 30, 40, 50, 60])
    ax.set_yticks([0, 25, 50, 75, 100], ["0", "25", "50", "75", "100 %"])
    ax.set_xlabel("Temps simulé (minutes)")
    fig.legend(loc="upper left", bbox_to_anchor=(0.065, 0.85), ncols=2, fontsize=9,
               labelcolor=t["encre2"], handlelength=1.4, columnspacing=1.8)

    titrer(fig, t,
           "Une fois l'attaque détectée, plus aucune recherche n'est censurée",
           "Part des recherches de la donnée ciblée qui sont censurées  ·  simulation à 30 Sybils (results/exemple)")
    enregistrer(fig, "exemple-censure", theme)


# ---------------------------------------------------------------------------
# Figure 4 : le principe de la détection par densité
# ---------------------------------------------------------------------------


def figure_detection_densite(t, theme):
    reference = {int(l["bitLength"]): int(l["count"]) for l in lire_csv(EXEMPLE / "baseline_distribution.csv")}
    total = sum(reference.values())
    moyenne = sum(b * c for b, c in reference.items()) / total
    ecart = math.sqrt(sum(c * (b - moyenne) ** 2 for b, c in reference.items()) / total)
    seuil = moyenne - 2 * ecart
    # Un nœud est « anormalement proche » si bitLength < seuil, soit log2(distance) < plancher
    plancher = math.ceil(seuil) - 1

    noeuds = lire_csv(EXEMPLE / "nodes_distribution.csv")
    distances = sorted((math.log2(int(l["Distance"])), l["Type"]) for l in noeuds if int(l["Distance"]) > 0)
    sans_attaque = [d for d, type_ in distances if type_ == "Normal"][:20]
    avec_attaque = distances[:20]

    fig, (haut, bas) = nouvelle_figure(
        t, hauteur=5.0, nrows=2, sharex=True, gridspec_kw={"height_ratios": [2.3, 1], "hspace": 0.08})
    fig.subplots_adjust(left=0.075, right=0.975, top=0.775, bottom=0.12)

    # Référence : la longueur en bits b correspond à log2(distance) dans [b - 1, b[
    habiller(haut, t)
    for b, c in reference.items():
        haut.bar(b - 0.5, 100 * c / total, width=0.86, color=t["neutre"], linewidth=0, zorder=2)
    haut.set_ylim(0, 46)
    haut.set_yticks([0, 10, 20, 30, 40], ["0", "10", "20", "30", "40 %"])
    haut.text(130.7, 43, f"Référence mesurée au départ :\n{total:,} distances entre un nœud\net ses 20 plus proches voisins".replace(",", " "),
              ha="left", va="top", fontsize=9, color=t["encre2"], linespacing=1.45,
              bbox={"facecolor": t["surface"], "edgecolor": "none", "pad": 3})
    haut.text(plancher - 0.3, 20, f"Zone anormalement proche\n(sous μ − 2σ = 2^{fr(seuil)})",
              ha="right", va="center", fontsize=9, color=t["encre2"], linespacing=1.45,
              bbox={"facecolor": t["surface"], "edgecolor": "none", "pad": 3})

    # Voisinage de la cible : les 20 nœuds les plus proches, sans puis avec Sybils
    habiller(bas, t, grille_y=False)
    for y, serie in ((1, [(d, "Normal") for d in sans_attaque]), (0, avec_attaque)):
        for i, (d, type_) in enumerate(serie):
            bas.plot(d, y + (i % 3 - 1) * 0.16, "o", markersize=7,
                     color=t["orange"] if type_ == "Sybil" else t["bleu"],
                     markeredgecolor=t["surface"], markeredgewidth=1.2, zorder=3)
    bas.set_ylim(-0.6, 1.6)
    bas.set_yticks([])
    sous_seuil = sum(d < plancher for d, _ in avec_attaque)
    bas.text(130.7, 1, "Sans attaque", ha="left", va="center", fontsize=9.5, color=t["encre"])
    bas.text(130.7, 0, "Avec 30 Sybils", ha="left", va="center", fontsize=9.5, color=t["encre"])
    bas.text(plancher + 0.4, 0, f"{sous_seuil} sur 20 sous le seuil : alerte", ha="left", va="center",
             fontsize=9.5, fontweight="medium", color=t["encre"])
    bas.set_xlabel("Distance XOR, en puissance de 2 (plus à gauche = plus proche)")
    bas.set_xlim(130.5, 153.4)
    bas.set_xticks(range(136, 154, 2), [f"2^{b}" for b in range(136, 154, 2)])

    for ax in (haut, bas):
        ax.axvline(plancher, color=t["encre2"], linewidth=1, zorder=1)

    from matplotlib.lines import Line2D

    legende = [
        Line2D([], [], marker="o", linestyle="", color=t["bleu"], markersize=7, label="Nœuds honnêtes"),
        Line2D([], [], marker="o", linestyle="", color=t["orange"], markersize=7, label="Nœuds Sybils"),
    ]
    fig.legend(handles=legende, loc="upper left", bbox_to_anchor=(0.065, 0.868), ncols=2, fontsize=9,
               labelcolor=t["encre2"], handletextpad=0.3, columnspacing=1.8)

    titrer(fig, t,
           "Les Sybils se trahissent : ils sont anormalement proches de la cible",
           "En bas, les 20 nœuds les plus proches de la donnée ciblée dans la même simulation (results/exemple)")
    enregistrer(fig, "detection-densite", theme)
    return moyenne, ecart, seuil


# ---------------------------------------------------------------------------
# Schéma : réseau sain, attaque, neutralisation
# ---------------------------------------------------------------------------


def schema_attaque_defense(t, theme):
    largeur, hauteur_bloc = 880, 168
    honnetes = [78, 160, 248, 318, 378, 502, 562, 640, 722, 802]
    sybils = [410, 425, 455, 470]
    cible = 440

    police = 'font-family="system-ui, -apple-system, Segoe UI, Helvetica, Arial, sans-serif"'
    classes = {
        "titre": f'{police} font-size="16" font-weight="600" fill="{t["encre"]}"',
        "texte": f'{police} font-size="13.5" fill="{t["encre"]}"',
        "petit": f'{police} font-size="12.5" fill="{t["encre2"]}"',
    }

    def ligne_noeuds(y, proches=(), ajoutes=(), avec_sybils=False, etiquette="donnée ciblée"):
        s = [f'<line x1="40" y1="{y}" x2="840" y2="{y}" stroke="{t["axe"]}" stroke-width="2" stroke-linecap="round"/>']
        for x in honnetes:
            if x in ajoutes:
                couleur = t["vert"]
            elif x in proches:
                couleur = t["bleu"]
            else:
                couleur = t["neutre"]
            s.append(f'<circle cx="{x}" cy="{y}" r="11" fill="{couleur}" stroke="{t["surface"]}" stroke-width="2"/>')
        if avec_sybils:
            for x in sybils:
                s.append(f'<circle cx="{x}" cy="{y}" r="8.5" fill="{t["orange"]}" stroke="{t["surface"]}" stroke-width="2"/>')
        s.append(f'<path d="M{cible} {y - 9} L{cible + 7} {y} L{cible} {y + 9} L{cible - 7} {y} Z" fill="{t["encre"]}" stroke="{t["surface"]}" stroke-width="1.5"/>')
        s.append(f'<text x="{cible}" y="{y - 21}" text-anchor="middle" class="petit">{etiquette}</text>')
        return "\n".join(s)

    def accolade(x1, x2, y, texte):
        m = (x1 + x2) / 2
        return (
            f'<path d="M{x1} {y} v6 q0 6 6 6 H{m - 7} q5 0 7 7 q2 -7 7 -7 H{x2 - 6} q6 0 6 -6 v-6" '
            f'fill="none" stroke="{t["encre2"]}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>'
            f'<text x="{m}" y="{y + 37}" text-anchor="middle" class="texte">{texte}</text>'
        )

    def bloc(index, titre, corps):
        y0 = index * hauteur_bloc
        separateur = "" if index == 0 else (
            f'<line x1="24" y1="{y0}" x2="{largeur - 24}" y2="{y0}" stroke="{t["grille"]}" stroke-width="1"/>')
        return f'{separateur}<text x="40" y="{y0 + 34}" class="titre">{titre}</text>\n{corps}'

    y1, y2, y3 = 84, hauteur_bloc + 84, 2 * hauteur_bloc + 84
    blocs = [
        bloc(0, "1 · Réseau sain",
             ligne_noeuds(y1, proches=(318, 378, 502, 562))
             + accolade(302, 578, y1 + 20, "Les K plus proches voisins savent où trouver la donnée : la recherche aboutit")),
        bloc(1, "2 · Attaque Sybil",
             ligne_noeuds(y2, avec_sybils=True)
             + accolade(398, 482, y2 + 20, "Les K plus proches voisins sont tous des Sybils, qui ne répondent pas : la donnée est censurée")),
        bloc(2, "3 · Détection puis neutralisation",
             f'<line x1="395" y1="{y3 - 16}" x2="395" y2="{y3 + 16}" stroke="{t["encre2"]}" stroke-width="1.5"/>'
             f'<line x1="485" y1="{y3 - 16}" x2="485" y2="{y3 + 16}" stroke="{t["encre2"]}" stroke-width="1.5"/>'
             + ligne_noeuds(y3, ajoutes=(318, 378, 502, 562), avec_sybils=True, etiquette="seuil d’anomalie")
             + accolade(302, 578, y3 + 20, "Voisinage élargi à des nœuds fiables au-delà du seuil : la recherche aboutit de nouveau")),
    ]

    legende_y = 3 * hauteur_bloc + 26
    legende = (
        f'<line x1="24" y1="{3 * hauteur_bloc}" x2="{largeur - 24}" y2="{3 * hauteur_bloc}" stroke="{t["grille"]}" stroke-width="1"/>'
        f'<circle cx="48" cy="{legende_y}" r="7" fill="{t["neutre"]}"/><text x="62" y="{legende_y + 4.5}" class="petit">nœud honnête</text>'
        f'<circle cx="188" cy="{legende_y}" r="7" fill="{t["bleu"]}"/><text x="202" y="{legende_y + 4.5}" class="petit">détient l’adresse du fournisseur</text>'
        f'<circle cx="426" cy="{legende_y}" r="7" fill="{t["orange"]}"/><text x="440" y="{legende_y + 4.5}" class="petit">nœud Sybil</text>'
        f'<circle cx="546" cy="{legende_y}" r="7" fill="{t["vert"]}"/><text x="560" y="{legende_y + 4.5}" class="petit">nœud fiable ajouté par la défense</text>'
    )

    hauteur = 3 * hauteur_bloc + 52
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {largeur} {hauteur}" width="{largeur}" height="{hauteur}" role="img" aria-label="Schéma : réseau sain, attaque Sybil, puis détection et neutralisation">
<rect width="{largeur}" height="{hauteur}" rx="10" fill="{t["surface"]}"/>
{chr(10).join(blocs)}
{legende}
</svg>
'''
    for nom, attributs in classes.items():
        svg = svg.replace(f'class="{nom}"', attributs)
    FIGURES.mkdir(parents=True, exist_ok=True)
    chemin = FIGURES / f"schema-attaque-defense-{theme}.svg"
    chemin.write_text(svg, encoding="utf-8")
    print("  ", chemin.relative_to(RACINE))


# ---------------------------------------------------------------------------
# Aperçu pour les réseaux sociaux (Settings > Social preview sur GitHub)
# ---------------------------------------------------------------------------


def apercu_social():
    from matplotlib.patches import Circle

    t = THEMES["sombre"]
    fig = plt.figure(figsize=(12.8, 6.4), facecolor=t["surface"])
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1280)
    ax.set_ylim(640, 0)
    ax.axis("off")
    police = {"family": ["Inter", "Segoe UI", "Arial", "DejaVu Sans"]}

    ax.text(80, 92, "TIPE  ·  SIMULATION PEERSIM  ·  JAVA / PYTHON", fontsize=15, color=t["discret"],
            fontweight="medium", **police)
    ax.text(80, 172, "Défendre un réseau Kademlia", fontsize=44, fontweight="bold", color=t["encre"], **police)
    ax.text(80, 242, "contre une attaque Sybil", fontsize=44, fontweight="bold", color=t["encre"], **police)

    # Ligne des identifiants : nœuds honnêtes, Sybils autour de la cible, nœuds fiables ajoutés
    y = 356
    ax.plot([80, 1200], [y, y], color=t["axe"], linewidth=2.5, solid_capstyle="round", zorder=1)
    for x in (130, 250, 370, 910, 1030, 1150):
        ax.add_patch(Circle((x, y), 17, facecolor=t["neutre"], edgecolor=t["surface"], linewidth=3, zorder=2))
    for x in (460, 536, 744, 820):
        ax.add_patch(Circle((x, y), 17, facecolor=t["vert"], edgecolor=t["surface"], linewidth=3, zorder=2))
    for x in (588, 614, 666, 692):
        ax.add_patch(Circle((x, y), 13, facecolor=t["orange"], edgecolor=t["surface"], linewidth=3, zorder=3))
    ax.plot([640], [y], marker="D", markersize=11, color=t["encre"], markeredgecolor=t["surface"],
            markeredgewidth=2, zorder=4)
    for x in (564, 716):
        ax.plot([x, x], [y - 26, y + 26], color=t["encre2"], linewidth=2, zorder=1)

    ax.text(80, 540, "99,6 %", fontsize=64, fontweight="bold", color=t["encre"], **police)
    ax.text(400, 502, "des censures levées face à 30 nœuds Sybils", fontsize=19, color=t["encre"], **police)
    ax.text(400, 540, "300 simulations d'un réseau de 5 000 nœuds", fontsize=19, color=t["encre2"], **police)
    ax.text(1200, 592, "github.com/paulin-guillet", fontsize=15, color=t["discret"], ha="right", **police)

    chemin = FIGURES / "apercu-social.png"
    fig.savefig(chemin, dpi=100, facecolor=t["surface"])
    plt.close(fig)
    print("  ", chemin.relative_to(RACINE))


# ---------------------------------------------------------------------------


def main():
    for theme, t in THEMES.items():
        print(f"Thème {theme} :")
        schema_attaque_defense(t, theme)
        figure_taux_reussite(t, theme)
        figure_delai_reaction(t, theme)
        figure_exemple_censure(t, theme)
        stats = figure_detection_densite(t, theme)
    apercu_social()
    print(f"\nRéférence de l'exemple : moyenne 2^{stats[0]:.2f}, écart-type {stats[1]:.2f} bit, seuil 2^{stats[2]:.2f}")


if __name__ == "__main__":
    main()
