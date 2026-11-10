"""Lance des séries de simulations PeerSim et mesure l'efficacité de la défense.

Une simulation = 1 h simulée d'un réseau Kademlia de 5 000 nœuds attaqué par
des Sybils (voir kademlia/example.cfg). La défense est comptée comme réussie
si la censure finale est strictement inférieure à 100 % : au moins une
recherche de la donnée ciblée a abouti.

Exemples :

    python scripts/simuler.py                       # 300 simulations, config par défaut
    python scripts/simuler.py --runs 1 --sortie results/exemple
    python scripts/simuler.py --runs 30 --sybils 25 30 50 75 100 200 500 --jobs 2 --csv results/balayage_sybils.csv

Le code Java est compilé automatiquement dans build/classes si nécessaire.
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from statistics import mean

# =========================
# CHEMINS
# =========================

RACINE = Path(__file__).resolve().parent.parent
SOURCES = RACINE / "kademlia" / "src"
CLASSES = RACINE / "build" / "classes"
JARS = [
    RACINE / "peersim" / "peersim-1.0.5.jar",
    RACINE / "peersim" / "jep-2.3.0.jar",
    RACINE / "peersim" / "djep-1.0.0.jar",
]
CONFIG_DEFAUT = RACINE / "kademlia" / "example.cfg"

# Fichiers écrits par KademliaObserver à la fin d'une simulation
EXPORTS = [
    "simulation_stats.csv",
    "detection_results.csv",
    "baseline_distribution.csv",
    "nodes_distribution.csv",
]

# =========================
# REGEX
# =========================

# Le séparateur décimal dépend de la langue du système (« 67,60 » ou « 67.60 »)
SYBIL_REGEX = re.compile(
    r"Target searches:\s+(\d+).*?Censored:\s+(\d+)\s+\(([0-9]+[.,][0-9]+)%\)"
)

TIME_REGEX = re.compile(r"\[time=(\d+)\]")

DETECTION_REGEX = re.compile(
    r"Periodic detections:\s+(\d+)\s+positive\s+\|\s+(\d+)\s+negative"
)

MITIGATION_APPLY_REGEX = re.compile(r"Extended closestKNodes to (\d+) nodes")

# =========================
# COMPILATION
# =========================


def classpath(*elements):
    return os.pathsep.join(str(e) for e in elements)


def compiler(force=False):
    """Compile kademlia/src vers build/classes (seulement si les sources ont changé)."""

    fichiers = sorted(SOURCES.rglob("*.java"))
    temoin = CLASSES / ".compile"

    a_jour = (
        temoin.exists()
        and temoin.stat().st_mtime >= max(f.stat().st_mtime for f in fichiers)
    )
    if a_jour and not force:
        return

    if shutil.which("javac") is None:
        sys.exit("javac introuvable : installer un JDK (8 ou plus).")

    CLASSES.mkdir(parents=True, exist_ok=True)

    print(f"Compilation de {len(fichiers)} fichiers Java -> {CLASSES}")

    subprocess.run(
        [
            "javac", "-nowarn", "-encoding", "UTF-8",
            "-classpath", classpath(*JARS),
            "-d", str(CLASSES),
            *[str(f) for f in fichiers],
        ],
        check=True,
    )
    temoin.touch()


# =========================
# FONCTION DE SIMULATION
# =========================


def lancer_simulation(simulation_id, config, sybils=None, proximite=None,
                      graine=None, sortie=None):
    """Lance une simulation et extrait ses indicateurs depuis la sortie de PeerSim."""

    commande = [
        "java",
        "-classpath", classpath(CLASSES, *JARS),
        "peersim.Simulator",
        str(config),
    ]

    # PeerSim accepte des paramètres supplémentaires qui écrasent ceux du fichier
    if sybils is not None:
        commande.append(f"init.1uniqueNodeID.sybil_count={sybils}")
    if proximite is not None:
        commande.append(f"init.1uniqueNodeID.proximity_bits={proximite}")
    if graine is not None:
        commande.append(f"random.seed={graine}")

    # Chaque simulation tourne dans son propre dossier : les exports CSV
    # de deux simulations parallèles ne s'écrasent pas.
    with tempfile.TemporaryDirectory(prefix="kademlia_") as dossier:

        process = subprocess.run(
            commande, cwd=dossier, capture_output=True, text=True, errors="replace"
        )

        if sortie is not None:
            sortie = Path(sortie)
            sortie.mkdir(parents=True, exist_ok=True)
            for nom in EXPORTS:
                if (Path(dossier) / nom).exists():
                    shutil.copy(Path(dossier) / nom, sortie / nom)

    if process.returncode != 0:
        print(process.stderr[-2000:], file=sys.stderr)
        sys.exit(f"La simulation {simulation_id} a échoué.")

    dernier_time = None
    premiere_defense_time = None
    censure_finale = None
    recherches_cible = 0
    recherches_censurees = 0
    detections_positives = 0
    detections_totales = 0
    taille_finale_closest = None

    # Les lignes [time=...] et [SYBIL STATS] sont écrites sur stderr,
    # dans l'ordre chronologique.
    for ligne in process.stderr.splitlines():

        time_match = TIME_REGEX.search(ligne)
        if time_match:
            dernier_time = int(time_match.group(1))

        if "[SYBIL STATS]" in ligne:
            match = SYBIL_REGEX.search(ligne)
            if match:
                recherches_cible = int(match.group(1))
                recherches_censurees = int(match.group(2))
                censure_finale = float(match.group(3).replace(",", "."))

                # Premier moment où la défense agit réellement
                if (
                    recherches_cible > 0
                    and censure_finale < 100.0
                    and premiere_defense_time is None
                ):
                    premiere_defense_time = dernier_time

        if "[DETECTION STATS]" in ligne:
            detection_match = DETECTION_REGEX.search(ligne)
            if detection_match:
                detections_positives = int(detection_match.group(1))
                detections_totales = detections_positives + int(
                    detection_match.group(2)
                )

    for ligne in process.stdout.splitlines():
        mitigation_match = MITIGATION_APPLY_REGEX.search(ligne)
        if mitigation_match:
            taille_finale_closest = int(mitigation_match.group(1))

    return {
        "simulation": simulation_id,
        "sybils": sybils,
        "proximite_bits": proximite,
        "graine": graine,
        "recherches_cible": recherches_cible,
        "recherches_censurees": recherches_censurees,
        "censure_finale": censure_finale,
        "defense_reussie": int(censure_finale is not None and censure_finale < 100.0),
        "premiere_defense_ms": premiere_defense_time,
        "detections_positives": detections_positives,
        "detections_totales": detections_totales,
        "taille_finale_closest": taille_finale_closest,
    }


def afficher_simulation(r):

    statut = "Défense réussie" if r["defense_reussie"] else "Attaque réussie"

    if r["premiere_defense_ms"] is not None:
        reaction = f"{r['premiere_defense_ms'] / 60000:.1f} min"
    else:
        reaction = "jamais"

    print(
        f"Simulation {r['simulation']:>4} | "
        f"Sybils : {r['sybils'] if r['sybils'] is not None else 'config'} | "
        f"Censure finale : {r['censure_finale']:6.2f}% | {statut} | "
        f"Première réaction : {reaction} | "
        f"Détections : {r['detections_positives']}/{r['detections_totales']} | "
        f"closestKNodes : {r['taille_finale_closest'] or 20}",
        flush=True,
    )


# =========================
# STATISTIQUES GLOBALES
# =========================


def afficher_resume(resultats, titre):

    print("\n===================================")
    print(titre)
    print("===================================")

    defenses_reussies = sum(r["defense_reussie"] for r in resultats)

    print(
        f"Taux de réussite de la défense : "
        f"{100 * defenses_reussies / len(resultats):.2f}% "
        f"({defenses_reussies}/{len(resultats)})"
    )
    print(
        f"Censure finale moyenne : "
        f"{mean(r['censure_finale'] for r in resultats):.2f}%"
    )

    temps_valides = [
        r["premiere_defense_ms"]
        for r in resultats
        if r["premiere_defense_ms"] is not None
    ]
    if temps_valides:
        temps_moyen = mean(temps_valides)
        print(
            f"Temps moyen de réaction de la défense : "
            f"{temps_moyen:.0f} ms ({temps_moyen / 60000:.2f} min)"
        )

    print(
        f"Détections positives moyennes : "
        f"{mean(r['detections_positives'] for r in resultats):.2f}"
    )
    print(
        f"Détections totales moyennes : "
        f"{mean(r['detections_totales'] for r in resultats):.2f}"
    )

    tailles_valides = [
        r["taille_finale_closest"]
        for r in resultats
        if r["taille_finale_closest"] is not None
    ]
    if tailles_valides:
        print(f"Taille moyenne de closestKNodes : {mean(tailles_valides):.2f}")

    print("===================================")


# =========================
# PROGRAMME PRINCIPAL
# =========================


def main():

    parser = argparse.ArgumentParser(
        description="Séries de simulations de l'attaque Sybil et de sa défense."
    )
    parser.add_argument("--runs", type=int, default=300,
                        help="nombre de simulations par valeur de --sybils (défaut : 300)")
    parser.add_argument("--sybils", type=int, nargs="+", default=[None],
                        help="nombre(s) de Sybils à tester (défaut : valeur du fichier de config)")
    parser.add_argument("--proximite", type=int, default=None,
                        help="proximity_bits des Sybils (défaut : valeur du fichier de config)")
    parser.add_argument("--config", type=Path, default=CONFIG_DEFAUT,
                        help="fichier de configuration PeerSim")
    parser.add_argument("--graine", type=int, default=None,
                        help="graine de la première simulation (les suivantes : +1, +2...) ; "
                             "défaut : graines aléatoires")
    parser.add_argument("--jobs", type=int, default=1,
                        help="nombre de simulations lancées en parallèle")
    parser.add_argument("--csv", type=Path, default=None,
                        help="enregistre une ligne par simulation dans ce fichier CSV")
    parser.add_argument("--sortie", type=Path, default=None,
                        help="copie dans ce dossier les CSV exportés par la simulation "
                             "(à réserver à --runs 1)")
    args = parser.parse_args()

    compiler()

    config = args.config.resolve()

    taches = []
    for sybils in args.sybils:
        for i in range(args.runs):
            numero = len(taches) + 1
            graine = None if args.graine is None else args.graine + numero - 1
            taches.append((numero, sybils, graine))

    def executer(tache):
        numero, sybils, graine = tache
        return lancer_simulation(
            numero, config, sybils=sybils, proximite=args.proximite,
            graine=graine, sortie=args.sortie,
        )

    fichier_csv = writer = None
    if args.csv is not None:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        fichier_csv = open(args.csv, "w", newline="", encoding="utf-8")

    resultats = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        # pool.map rend les résultats dans l'ordre des tâches, au fur et à mesure
        for resultat in pool.map(executer, taches):
            afficher_simulation(resultat)
            resultats.append(resultat)
            if fichier_csv is not None:
                if writer is None:
                    writer = csv.DictWriter(fichier_csv, fieldnames=list(resultat.keys()))
                    writer.writeheader()
                writer.writerow(resultat)
                fichier_csv.flush()

    if fichier_csv is not None:
        fichier_csv.close()
        print(f"\nRésultats enregistrés dans {args.csv}")

    for sybils in args.sybils:
        groupe = [r for r in resultats if r["sybils"] == sybils]
        titre = "RÉSUMÉ GLOBAL"
        if sybils is not None:
            titre += f" - {sybils} SYBILS"
        afficher_resume(groupe, titre)


if __name__ == "__main__":
    main()
