import re
import csv
import matplotlib.pyplot as plt
import numpy as np
import sys

class SybilAnalyzer:
    def __init__(self, log_file):
        """Initialiser l'analyseur (log_file : dossier des CSV, conserve pour information)"""
        self.log_file = log_file
        
        # ===== DONNEES TEMPORELLES =====
        self.timestamps = []
        
        # ===== ETAT DU RESEAU =====
        self.normal_counts = []          # Nombre de noeuds normaux
        self.sybil_counts = []           # Nombre de noeuds Sybils
        self.hop_counts = []             # Nombre moyen de hops
        self.latencies = []              # Latence moyenne (ms)
        
        # ===== IMPACT DE L'ATTAQUE SYBIL =====
        self.censored_searches = []      # Nombre de recherches censurees
        self.censorship_rates = []       # Pourcentage de censure
        
        # ===== DETECTION D'ANOMALIES (depuis logs) =====
        self.detection_timestamps = []   # Timestamps des tests de détection
        self.detection_positives = []    # Detections positives cumulees
        self.detection_negatives = []    # Detections negatives cumulees
        self.baseline_mean = None        # Reference baseline (2^X bits)
        
        # ===== DISTRIBUTION DES NOEUDS =====
        self.nodes_data_witness = []     # Sans Sybils (reference)
        self.nodes_data_current = []     # Avec Sybils
        
        # ===== DONNEES CSV DETAILLEES =====
        self.k_density_data = []         # k_density_analysis.csv
        self.detection_results_data = [] # detection_results.csv
        
        # ===== BASELINE DISTRIBUTION =====
        self.baseline_distribution = {}  # bitLength -> count mapping
    
    # ============================================================================
    #                       1. PARSING - LOGS ET CSV
    # ============================================================================
    
    def parse_logs(self):
        """Parse data from exported CSV files (no longer reading log file)"""
        try:
            print("[PARSER] Reading exported CSV files (no longer using resultats.txt)\n")
            
            # Parser les donnees CSV exportees par l'Observer
            self._parse_simulation_stats()
            self._parse_baseline_distribution_csv()
            self._parse_nodes_distribution()
            self._parse_k_density_analysis()
            self._parse_detection_results()
            
            return self._validate_data()
        
        except FileNotFoundError as e:
            print(f"[ERROR] Required CSV file not found: {e}")
            return False
        except Exception as e:
            print(f"[ERROR] Error parsing CSV files: {e}")
            return False
    
    def _validate_data(self):
        """Valider les donnees chargees"""
        if len(self.timestamps) == 0:
            print("[ERROR] Aucune donnee trouvee")
            return False
        
        print(f"[OK] {len(self.timestamps)} snapshots charges")
        if self.normal_counts:
            print(f"   - Reseau: {len(self.normal_counts)} snapshots")
        if self.censored_searches:
            print(f"   - Attaque: {len(self.censored_searches)} snapshots")
        if self.k_density_data:
            print(f"   - K-density CSV: {len(self.k_density_data)} entrees")
        if self.detection_results_data:
            print(f"   - Detection CSV: {len(self.detection_results_data)} entrees")
        print()
        return True
    

    
    def _parse_simulation_stats(self):
        """Parse simulation_stats.csv - exported by KademliaObserver"""
        try:
            with open('simulation_stats.csv', 'r', encoding='utf-8') as f:
                reader = csv.reader(f, delimiter=',')
                header = next(reader)  # Skip header
                
                for row in reader:
                    if len(row) < 7:
                        continue
                    try:
                        self.timestamps.append(int(row[0]))
                        self.normal_counts.append(int(row[1]))
                        self.sybil_counts.append(int(row[2]))
                        self.hop_counts.append(float(row[3]))
                        self.latencies.append(float(row[4]))
                        self.censored_searches.append(int(row[5]))
                        # CensorshipRate est exporte comme une fraction (0-1) : conversion en %
                        self.censorship_rates.append(100 * float(row[6]))
                    except (ValueError, IndexError):
                        pass
                
                if self.timestamps:
                    print(f"[OK] Simulation Stats: {len(self.timestamps)} timesteps")
        except FileNotFoundError:
            print("[WARN] simulation_stats.csv not found - network data will be empty\n")
        except Exception as e:
            print(f"[WARN] Error reading simulation_stats.csv: {e}\n")
    
    def _parse_baseline_distribution_csv(self):
        """Parse baseline_distribution.csv - exported by KademliaObserver"""
        try:
            with open('baseline_distribution.csv', 'r', encoding='utf-8') as f:
                reader = csv.reader(f, delimiter=',')
                header = next(reader)  # Skip header
                
                for row in reader:
                    if len(row) < 2:
                        continue
                    try:
                        bit_length = int(row[0])
                        count = int(row[1])
                        self.baseline_distribution[bit_length] = count
                    except ValueError:
                        pass
                
                if self.baseline_distribution:
                    print(f"[OK] Baseline Distribution: {len(self.baseline_distribution)} bitLengths")
                    # Calculate baseline mean from distribution
                    total_samples = sum(self.baseline_distribution.values())
                    weighted_sum = sum(bl * count for bl, count in self.baseline_distribution.items())
                    self.baseline_mean = weighted_sum / total_samples if total_samples > 0 else 0
                    print(f"     Calculated baseline mean: 2^{self.baseline_mean:.2f}\n")
        except FileNotFoundError:
            print("[WARN] baseline_distribution.csv not found - baseline plot will be empty\n")
        except Exception as e:
            print(f"[WARN] Error reading baseline_distribution.csv: {e}\n")
    
    def _parse_nodes_distribution(self):
        """Parser fichiers CSV de distribution: witness et current"""
        # Fichier reference (sans Sybils)
        try:
            with open('nodes_distribution_witness.csv', 'r', encoding='utf-8') as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split(',')
                    if len(parts) >= 3:
                        try:
                            self.nodes_data_witness.append(int(parts[2]))
                        except ValueError:
                            pass
            print(f"[OK] Witness: {len(self.nodes_data_witness)} noeuds")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[WARN] Witness CSV: {e}")
        
        # Fichier avec Sybils
        try:
            with open('nodes_distribution.csv', 'r', encoding='utf-8') as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split(',')
                    if len(parts) >= 3:
                        try:
                            self.nodes_data_current.append(int(parts[2]))
                        except ValueError:
                            pass
            print(f"[OK] Current: {len(self.nodes_data_current)} noeuds\n")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[WARN] Current CSV: {e}\n")
    
    def _parse_k_density_analysis(self):
        """Parser k_density_analysis.csv avec gestion des virgules décimales"""
        try:
            with open('k_density_analysis.csv', 'r', encoding='utf-8') as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split(',')
                    if len(parts) >= 4:
                        try:
                            record = {
                                'query_id': parts[0],
                                'distance': int(parts[1]),
                                'bit_length': int(parts[2]),
                                'is_sybil': int(parts[3]) == 1
                            }
                            self.k_density_data.append(record)
                        except (ValueError, IndexError):
                            pass
            
            if self.k_density_data:
                print(f"[OK] K-Density: {len(self.k_density_data)} entrees\n")
        except FileNotFoundError:
            print(f"[WARN] k_density_analysis.csv not found - will use simplified detection plot\n")
        except Exception as e:
            print(f"[WARN] K-Density CSV: {e}\n")
    
    def _parse_detection_results(self):
        """Parser detection_results.csv - Anomaly Detection Results"""
        import csv
        try:
            with open('detection_results.csv', 'r', encoding='utf-8') as f:
                reader = csv.reader(f, delimiter=',')
                header = next(reader)  # Lire l'en-tête
                
                print(f"[PARSER] CSV Header: {header}")
                
                for row_idx, row in enumerate(reader):
                    try:
                        if len(row) < 8:
                            continue
                        
                        # Colonnes du CSV pour Anomaly Detector:
                        # 0=SampleIndex, 1=AnomalyScore, 2=Threshold, 3=AttackDetected, 
                        # 4=SamplesAnalyzed, 5=MeanBitLength, 6=OutlierPercentage, 7=Diagnostics
                        
                        try:
                            anomaly_score = float(row[1])
                            threshold = float(row[2])
                            attack_detected_int = int(row[3])
                            samples_analyzed = int(row[4])
                            mean_bit_length = float(row[5])
                            outlier_percentage = float(row[6])
                            diagnostics = row[7] if len(row) > 7 else ""
                        except (ValueError, IndexError) as e:
                            continue
                        
                        attack_detected = (attack_detected_int == 1)
                        
                        record = {
                            'index': row_idx,
                            'anomaly_score': anomaly_score,
                            'threshold': threshold,
                            'attack_detected': attack_detected,
                            'samples_analyzed': samples_analyzed,
                            'mean_bit_length': mean_bit_length,
                            'outlier_percentage': outlier_percentage,
                            'diagnostics': diagnostics
                        }
                        self.detection_results_data.append(record)
                        
                        if row_idx == 0:
                            print(f"[PARSER] OK First row: Outliers={outlier_percentage:.1f}%, Mean={mean_bit_length:.2f} bits, Score={anomaly_score:.4f}, Detected={attack_detected}")
                        
                    except Exception as e:
                        pass
            
            if self.detection_results_data:
                last_record = self.detection_results_data[-1]
                positives = sum(1 for d in self.detection_results_data if d['attack_detected'])
                print(f"[OK] Detection Results: {len(self.detection_results_data)} entrees")
                print(f"     Detections positives: {positives}")
                print(f"     Last: Outliers={last_record['outlier_percentage']:.1f}%, Mean={last_record['mean_bit_length']:.2f} bits\n")
        except FileNotFoundError:
            print(f"[WARN] detection_results.csv not found\n")
        except Exception as e:
            print(f"[ERROR] Detection results CSV parsing: {e}\n")
    
    # ============================================================================
    #              2. VISUALISATION - ETAT DU RESEAU (Network Status)
    # ============================================================================
    
    def plot_network_composition(self):
        """Composition du reseau (Normal vs Sybil)"""
        if not self.normal_counts:
            return False
        
        time_subset = self.timestamps[:len(self.normal_counts)]
        
        plt.figure(figsize=(12, 6))
        ax = plt.gca()
        ax.stackplot(time_subset, self.normal_counts, self.sybil_counts,
                    labels=['Noeuds normaux', 'Noeuds Sybils'],
                    colors=['#4dabf7', '#ff6b6b'], alpha=0.8)
        
        ax.set_xlabel('Temps (ms)', fontsize=14, fontweight='bold')
        ax.set_ylabel('Nombre de noeuds', fontsize=14, fontweight='bold')
        ax.set_title('Composition du reseau', fontsize=16, fontweight='bold')
        ax.legend(loc='upper left', fontsize=13)
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('network_composition.png', dpi=300, bbox_inches='tight')
        print("[OK] network_composition.png")
        plt.close()
        return True
    
    def plot_performance_metrics(self):
        """Performance du reseau (hops et latence)"""
        if not self.hop_counts:
            return False
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        time_subset = self.timestamps[:len(self.hop_counts)]
        
        ax1.plot(time_subset, self.hop_counts, marker='o', linewidth=2, 
                markersize=4, color='#4dabf7')
        ax1.set_xlabel('Temps (ms)', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Hops moyen', fontsize=14, fontweight='bold')
        ax1.set_title('Evolution des hops', fontsize=15, fontweight='bold')
        ax1.grid(True, alpha=0.3)
        
        time_subset_lat = self.timestamps[:len(self.latencies)]
        ax2.plot(time_subset_lat, self.latencies, marker='s', linewidth=2, 
                markersize=4, color='#ffa500')
        ax2.set_xlabel('Temps (ms)', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Latence (ms)', fontsize=14, fontweight='bold')
        ax2.set_title('Evolution de la latence', fontsize=15, fontweight='bold')
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('performance_metrics.png', dpi=300, bbox_inches='tight')
        print("[OK] performance_metrics.png")
        plt.close()
        return True
    
    def plot_nodes_distribution(self):
        """Distribution des nœuds proches (Witness vs Avec Sybils)"""
        if not self.nodes_data_witness and not self.nodes_data_current:
            return False
        
        witness_closest_20 = sorted(self.nodes_data_witness)[:20] if self.nodes_data_witness else []
        current_closest_20 = sorted(self.nodes_data_current)[:20] if self.nodes_data_current else []
        
        fig, ax = plt.subplots(figsize=(14, 8))
        
        def to_log2(dist):
            return np.log2(float(dist)) if dist > 0 else 0
        
        witness_log = [to_log2(d) for d in witness_closest_20]
        current_log = [to_log2(d) for d in current_closest_20]
        
        all_log_dist = witness_log + current_log
        if all_log_dist:
            min_log = min([d for d in all_log_dist if d > 0]) if any(d > 0 for d in all_log_dist) else 0
            max_log = max(all_log_dist)
            
            log_bins = np.linspace(min_log, max_log, 50)
            bin_centers = (log_bins[:-1] + log_bins[1:]) / 2
            
            witness_counts, _ = np.histogram(witness_log, bins=log_bins)
            current_counts, _ = np.histogram(current_log, bins=log_bins)
            
            ax.plot(bin_centers, witness_counts, linestyle='-', linewidth=2, 
                    label='TEMOIN (sans Sybil)', color='#4dabf7', 
                   markeredgecolor='black', markeredgewidth=1.2)
            ax.plot(bin_centers, current_counts, linestyle='-', linewidth=2, 
                    label='AVEC SYBIL', color='#ff6b6b', markeredgewidth=1.5)
        
        ax.set_xlabel('Distance log2 avec la cible', fontsize=16, fontweight='bold')
        ax.set_ylabel('Nombre de noeuds (20 proches)', fontsize=16, fontweight='bold')
        ax.set_title('Distribution des noeuds les plus proches', fontsize=18, fontweight='bold')
        ax.legend(fontsize=18)
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('nodes_distribution.png', dpi=300, bbox_inches='tight')
        print("[OK] nodes_distribution.png")
        plt.close()
        return True
    
    # ============================================================================
    #           3. VISUALISATION - IMPACT ATTAQUE SYBIL (Attack Impact)
    # ============================================================================
    
    def plot_censorship_rate(self):
        """Taux de censure au fil du temps"""
        if not self.censorship_rates:
            return False
        
        time_subset = self.timestamps[:len(self.censorship_rates)]
        
        plt.figure(figsize=(12, 6))
        plt.plot(time_subset, self.censorship_rates, marker='o', linewidth=2.5, 
                markersize=5, color='#ff4444')
        plt.xlabel('Temps (ms)', fontsize=15, fontweight='bold')
        plt.ylabel('Taux de censure (%)', fontsize=15, fontweight='bold')
        plt.title('Taux de censure des recherches ciblees', fontsize=16, fontweight='bold')
        plt.grid(True, alpha=0.4)
        plt.ylim([0, 100])
        plt.tight_layout()
        plt.savefig('censorship_rate.png', dpi=300, bbox_inches='tight')
        print("[OK] censorship_rate.png")
        plt.close()
        return True
    
    def plot_search_results(self):
        """Nombres de recherches censurees"""
        if not self.censored_searches:
            return False
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        time_subset = self.timestamps[:len(self.censored_searches)]
        
        final_censored = self.censored_searches[-1]
        
        ax1.bar(['Censurees'], [final_censored], 
               color=['#ff6b6b'], edgecolor='black', linewidth=2, width=0.6)
        ax1.set_ylabel('Nombre', fontsize=14, fontweight='bold')
        ax1.set_title('Resultats finaux', fontsize=15, fontweight='bold')
        ax1.grid(True, alpha=0.3, axis='y')
        ax1.text(0, final_censored + 30, str(final_censored), ha='center', fontweight='bold', fontsize=13)
        
        ax2.plot(time_subset, self.censored_searches, marker='o', linewidth=2, 
                markersize=4, color='#ff6b6b', label='Censurees')
        ax2.set_xlabel('Temps (ms)', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Nombre', fontsize=14, fontweight='bold')
        ax2.set_title('Evolution des recherches censurees', fontsize=15, fontweight='bold')
        ax2.legend(fontsize=13)
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('search_results.png', dpi=300, bbox_inches='tight')
        print("[OK] search_results.png")
        plt.close()
        return True
    
    # ============================================================================
    #        4. VISUALISATION - DETECTION D'ANOMALIES (Anomaly Detection)
    # ============================================================================
    

    

    

    
    # ============================================================================
    #        5. VISUALISATION - DISTRIBUTION DES NOEUDS REFERENCE (Node Distribution)
    # ============================================================================
    
    def plot_k_density_distribution(self):
        """K-distance distribution: Normal vs Sybil nodes"""
        if not self.k_density_data:
            return False
        
        normal_bits = [d['bit_length'] for d in self.k_density_data if not d['is_sybil']]
        sybil_bits = [d['bit_length'] for d in self.k_density_data if d['is_sybil']]
        
        fig, ax = plt.subplots(figsize=(14, 8))
        
        if normal_bits:
            ax.hist(normal_bits, bins=20, alpha=0.6, label=f'Normal (n={len(normal_bits)})', 
                   color='#4dabf7', edgecolor='black')
        if sybil_bits:
            ax.hist(sybil_bits, bins=20, alpha=0.6, label=f'Sybil (n={len(sybil_bits)})', 
                   color='#ff6b6b', edgecolor='black')
        
        ax.set_xlabel('K-distance (bits)', fontsize=14, fontweight='bold')
        ax.set_ylabel('Nombre de noeuds', fontsize=14, fontweight='bold')
        ax.set_title('Distribution K-distance (Normal vs Sybil)', fontsize=16, fontweight='bold')
        ax.legend(fontsize=12)
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        plt.savefig('k_density_distribution.png', dpi=300, bbox_inches='tight')
        print("[OK] k_density_distribution.png")
        plt.close()
        return True
    

    
    def plot_outlier_percentage_evolution(self):
        """Outlier Percentage evolution - Key metric for anomaly detection"""
        if not self.detection_results_data:
            return False
        
        indices = [d['index'] for d in self.detection_results_data]
        outlier_percentages = [d['outlier_percentage'] for d in self.detection_results_data]
        detections = [d['attack_detected'] for d in self.detection_results_data]
        
        fig, ax = plt.subplots(figsize=(14, 8))
        
        # Highlighting attack detections
        colors = ['#ff6b6b' if det else '#4dabf7' for det in detections]
        
        ax.scatter(indices, outlier_percentages, c=colors, s=100, alpha=0.7, edgecolors='black', linewidth=1.5)
        ax.axhline(y=15, color='#27ae60', linestyle='--', linewidth=2.5, label='Detection Threshold (15%)')
        
        ax.set_xlabel('Sample Index', fontsize=14, fontweight='bold')
        ax.set_ylabel('Outlier Percentage (%)', fontsize=14, fontweight='bold')
        ax.set_title('Evolution du pourcentage d\'outliers', fontsize=16, fontweight='bold')
        ax.grid(True, alpha=0.3)
        
        # Legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#ff6b6b', edgecolor='black', label='Attack Detected'),
            Patch(facecolor='#4dabf7', edgecolor='black', label='No Attack'),
            plt.Line2D([0], [0], color='#27ae60', linewidth=2.5, linestyle='--', label='Threshold (15%)')
        ]
        ax.legend(handles=legend_elements, fontsize=12, loc='upper left')
        
        plt.tight_layout()
        plt.savefig('outlier_percentage_evolution.png', dpi=300, bbox_inches='tight')
        print("[OK] outlier_percentage_evolution.png")
        plt.close()
        return True
    
    def plot_detection_accuracy(self):
        """Detection accuracy: cumulative detection rate"""
        if not self.detection_results_data:
            return False
        
        indices = [d['index'] for d in self.detection_results_data]
        detections = [d['attack_detected'] for d in self.detection_results_data]
        
        cumulative_correct = [sum(detections[:i+1]) for i in range(len(detections))]
        detection_rate = [100 * c / (i + 1) for i, c in enumerate(cumulative_correct)]
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        
        ax1.plot(indices, detection_rate, marker='o', linewidth=2.5, markersize=6, 
                color='#2ecc71', label='Detection Rate')
        ax1.axhline(y=100, color='red', linestyle='--', linewidth=2, label='Parfait (100%)')
        ax1.fill_between(indices, 0, detection_rate, alpha=0.3, color='#2ecc71')
        ax1.set_xlabel('Sample Index', fontsize=13, fontweight='bold')
        ax1.set_ylabel('Detection Rate (%)', fontsize=13, fontweight='bold')
        ax1.set_title('Precision cumulee de detection', fontsize=14, fontweight='bold')
        ax1.legend(fontsize=11)
        ax1.grid(True, alpha=0.3)
        ax1.set_ylim([0, 105])
        
        positive_count = sum(detections)
        negative_count = len(detections) - positive_count
        
        ax2.bar(['Detected', 'Missed'], [positive_count, negative_count], 
               color=['#2ecc71', '#e74c3c'], edgecolor='black', linewidth=2, alpha=0.8)
        
        for i, v in enumerate([positive_count, negative_count]):
            ax2.text(i, v + 0.5, str(v), ha='center', fontweight='bold', fontsize=14)
        
        ax2.set_ylabel('Count', fontsize=13, fontweight='bold')
        ax2.set_title('Resultats de detection (resume)', fontsize=14, fontweight='bold')
        ax2.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        plt.savefig('detection_accuracy.png', dpi=300, bbox_inches='tight')
        print("[OK] detection_accuracy.png")
        plt.close()
        return True
    
    def plot_mean_bitlength_vs_baseline(self):
        """Observed K-distance mean vs baseline reference"""
        if not self.detection_results_data or not self.baseline_mean:
            return False
        
        indices = [d['index'] for d in self.detection_results_data]
        means = [d['mean_bit_length'] for d in self.detection_results_data]
        
        fig, ax = plt.subplots(figsize=(14, 8))
        
        ax.plot(indices, means, marker='o', linewidth=2, markersize=5, 
               color='#e74c3c', label='Observed Mean K-distance')
        
        ax.axhline(y=self.baseline_mean, color='#4dabf7', linestyle='--', linewidth=3,
                  label=f'Baseline = 2^{self.baseline_mean:.2f}')
        
        ax.axhspan(self.baseline_mean - 2, self.baseline_mean + 2, 
                  alpha=0.15, color='#4dabf7', label='±2 bits (Normal Range)')
        
        ax.set_xlabel('Test Sample Index', fontsize=14, fontweight='bold')
        ax.set_ylabel('Mean K-distance (bits)', fontsize=14, fontweight='bold')
        ax.set_title('Observations vs Baseline Reference', fontsize=16, fontweight='bold')
        ax.legend(fontsize=12)
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('mean_bitlength_vs_baseline.png', dpi=300, bbox_inches='tight')
        print("[OK] mean_bitlength_vs_baseline.png")
        plt.close()
        return True
    

    
    def _plot_sample_composition_simplified(self):
        """Version simplifiée de composition basée sur detection_results_data"""
        if not self.detection_results_data or not self.baseline_mean:
            return False
        
        # Extraire le seuil d'outlier
        outlier_threshold = self.baseline_mean - 2
        
        # Créer une distribution estimée des samples à partir des moyennes
        means = [d['mean_bit_length'] for d in self.detection_results_data]
        outlier_pcts = [d['outlier_percentage'] for d in self.detection_results_data]
        detections = [d['attack_detected'] for d in self.detection_results_data]
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # ============ Graphe 1: Distribution des moyennes ==============
        colors_detected = ['#ff6b6b' if d else '#4dabf7' for d in detections]
        ax1.scatter(range(len(means)), means, c=colors_detected, s=100, alpha=0.7, 
                   edgecolors='black', linewidth=1.5)
        ax1.axhline(y=self.baseline_mean, color='#2ecc71', linestyle='--', linewidth=2.5,
                   label=f'Baseline (2^{self.baseline_mean:.2f})')
        ax1.axhspan(self.baseline_mean - 2, self.baseline_mean + 2, alpha=0.15, 
                   color='#2ecc71', label='Normal Range (±2sigma)')
        ax1.axhspan(0, outlier_threshold, alpha=0.2, color='#ff6b6b', 
                   label=f'Outlier Zone (< 2^{outlier_threshold:.2f})')
        ax1.set_xlabel('Sample Index', fontsize=12, fontweight='bold')
        ax1.set_ylabel('Mean K-distance (bits)', fontsize=12, fontweight='bold')
        ax1.set_title('1. Moyennes K-distances par test (détection rare)', 
                     fontsize=13, fontweight='bold')
        ax1.grid(True, alpha=0.3)
        
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#ff6b6b', edgecolor='black', label='Attack Detected'),
            Patch(facecolor='#4dabf7', edgecolor='black', label='No Attack'),
            plt.Line2D([0], [0], color='#2ecc71', linewidth=2.5, linestyle='--', label='Baseline'),
            Patch(facecolor='#2ecc71', alpha=0.15, label='Normal Range'),
        ]
        ax1.legend(handles=legend_elements, fontsize=10)
        
        # ============ Graphe 2: Histogramme des outlier percentages ==============
        bins = np.arange(0, 105, 5)
        
        # Séparer par type de détection
        pcts_detected = [p for p, d in zip(outlier_pcts, detections) if d]
        pcts_normal = [p for p, d in zip(outlier_pcts, detections) if not d]
        
        ax2.hist(pcts_detected, bins=bins, alpha=0.6, color='#ff6b6b',
                label=f'Attacks ({len(pcts_detected)})', edgecolor='black', linewidth=1.5)
        ax2.hist(pcts_normal, bins=bins, alpha=0.6, color='#4dabf7',
                label=f'Normal ({len(pcts_normal)})', edgecolor='black', linewidth=1.5)
        ax2.axvline(x=15, color='#27ae60', linestyle='--', linewidth=2.5, label='Threshold (15%)')
        ax2.axvspan(15, 100, alpha=0.15, color='#ff6b6b', label='Attack Zone')
        ax2.set_xlabel('Outlier Percentage (%)', fontsize=12, fontweight='bold')
        ax2.set_ylabel('Nombre tests', fontsize=12, fontweight='bold')
        ax2.set_title('2. Distribution du % d\'outliers (métrique de détection)', 
                     fontsize=13, fontweight='bold')
        ax2.legend(fontsize=10)
        ax2.grid(True, alpha=0.3, axis='y')
        
        # ============ Graphe 3: Corrélation moyennes vs outlier% ==============
        scatter_colors = ['#ff6b6b' if d else '#4dabf7' for d in detections]
        ax3.scatter(means, outlier_pcts, c=scatter_colors, s=100, alpha=0.7, 
                   edgecolors='black', linewidth=1.5)
        ax3.axvline(x=self.baseline_mean, color='#2ecc71', linestyle='--', linewidth=2, alpha=0.7)
        ax3.axhline(y=15, color='#27ae60', linestyle='--', linewidth=2, alpha=0.7)
        ax3.set_xlabel('Mean K-distance (bits)', fontsize=12, fontweight='bold')
        ax3.set_ylabel('Outlier Percentage (%)', fontsize=12, fontweight='bold')
        ax3.set_title('3. Corrélation: Mean vs % outliers', fontsize=13, fontweight='bold')
        ax3.grid(True, alpha=0.3)
        
        # ============ Graphe 4: Résumé ==============
        ax4.axis('off')
        
        detected_count = sum(detections)
        total_tests = len(detections)
        detection_rate = (detected_count / total_tests * 100) if total_tests > 0 else 0
        avg_mean_detected = np.mean([m for m, d in zip(means, detections) if d]) if any(detections) else 0
        avg_mean_normal = np.mean([m for m, d in zip(means, detections) if not d]) if any(not d for d in detections) else 0
        
        summary_text = f"""
+======================================+
|   ANALYSE ECHANTILLONS (SIMPLIFIEE)  |
+======================================╝

TOTAL TESTS DETECTION:
  Tests executés:     {total_tests:>6d}
  Attaques détectées: {detected_count:>6d}
  Taux détection:     {detection_rate:>6.1f}%

MOYENNES K-DISTANCES:
  Quand attack:       {avg_mean_detected:>6.2f} bits
  Quand normal:       {avg_mean_normal:>6.2f} bits
  Baseline ref:       {self.baseline_mean:>6.2f} bits
  Écart attack:       {self.baseline_mean - avg_mean_detected:>6.2f} bits OK

SEUIL D'OUTLIER:
  Zone < {outlier_threshold:.2f} bits
  = Mean - 2sigma

NOTE: Graphe simplifié car
k_density_analysis.csv non trouvé.
Ce graphe utilise les moyennes par
test de détection pour estimer la
distribution des samples."""
        
        ax4.text(0.05, 0.5, summary_text, fontsize=10, family='monospace',
                verticalalignment='center', bbox=dict(boxstyle='round', 
                facecolor='lightyellow', alpha=0.5))
        
        plt.tight_layout()
        plt.savefig('sample_composition.png', dpi=300, bbox_inches='tight')
        print("[OK] sample_composition.png (simplified)")
        plt.close()
        return True
    

    def plot_baseline_distribution(self):
        """Distribution de bitLength - depuis BASELINE-DEBUG"""
        if not self.baseline_distribution or not self.baseline_mean:
            return False
        
        # Extraire et trier les bitLengths
        bit_lengths = sorted(self.baseline_distribution.keys())
        counts = [self.baseline_distribution[bl] for bl in bit_lengths]
        
        # Calculer les zones
        outlier_threshold = self.baseline_mean - 2
        normal_min = self.baseline_mean - 2
        normal_max = self.baseline_mean + 2
        
        # Colorier les barres selon la zone
        colors = []
        for bl in bit_lengths:
            if bl < normal_min:
                colors.append('#ff6b6b')  # Outlier zone (Sybil)
            elif bl > normal_max:
                colors.append('#ffc107')  # High outliers
            else:
                colors.append('#4dabf7')  # Normal range
        
        fig, ax = plt.subplots(figsize=(16, 9))
        
        ax.bar(bit_lengths, counts, color=colors, edgecolor='black', linewidth=1.5, alpha=0.8, width=0.8)
        
        # Ajouter les lignes de référence
        ax.axvline(x=self.baseline_mean, color='#2ecc71', linestyle='--', linewidth=3,
                  label=f'Moyenne = 2^{self.baseline_mean:.2f}')
        ax.axvline(x=outlier_threshold, color='#e74c3c', linestyle=':', linewidth=3,
                  label=f'Seuil d\'Anomalie = 2^{outlier_threshold:.2f} (Moyenne - 2sigma)')
        ax.axvline(x=normal_max, color='#f0ad4e', linestyle=':', linewidth=2, alpha=0.7)
        
        # Ajouter des zones (centrer sur la plage des données)
        min_bl = min(bit_lengths)
        max_bl = max(bit_lengths)
        margin = 1
        
        ax.axvspan(min_bl - margin, outlier_threshold, alpha=0.1, color='#ff6b6b', label='Zone Sybil')
        ax.axvspan(normal_min, normal_max, alpha=0.1, color='#2ecc71', label='Zone Normale')
        
        # Centrer l'axe X sur la plage réelle des bitLengths avec un peu de marge
        ax.set_xlim(min_bl - 1.5, max_bl + 1.5)
        
        # Optimiser l'espace Y
        max_count = max(counts)
        ax.set_ylim(0, max_count * 1.1)
        
        ax.set_xlabel('distance en bits', fontsize=16, fontweight='bold')
        ax.set_ylabel('Nombre d\'echantillons', fontsize=16, fontweight='bold')
        ax.set_title('Distribution des échantillons - (10,000)', 
                    fontsize=20, fontweight='bold')
        ax.legend(
            fontsize=20,
            loc='upper left',
            bbox_to_anchor=(0.01, 0.99)
        )
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        plt.savefig('baseline_distribution.png', dpi=300, bbox_inches='tight')
        print("[OK] baseline_distribution.png")
        plt.close()
        return True
    
    def plot_sample_composition(self):
        """Composition des échantillons: normal vs sybil vs outliers"""
        # Si k_density_data n'existe pas, créer une version simplifiée
        if not self.detection_results_data or not self.baseline_mean:
            return False
        
        if not self.k_density_data:
            # Fallback: créer une composition estimée depuis detection_results
            return self._plot_sample_composition_simplified()
        
        # Extraire le seuil d'outlier
        outlier_threshold = self.baseline_mean - 2
        
        # Classer les K-distances
        normal_bits = []
        sybil_bits = []
        outlier_bits = []
        
        for d in self.k_density_data:
            bit_len = d['bit_length']
            if d['is_sybil']:
                sybil_bits.append(bit_len)
                if bit_len < outlier_threshold:
                    outlier_bits.append(bit_len)
            else:
                normal_bits.append(bit_len)
                if bit_len < outlier_threshold:
                    outlier_bits.append(bit_len)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # ============ Graphe 1: Distribution complète ==============
        ax1.hist(normal_bits, bins=30, alpha=0.6, label=f'Normal (n={len(normal_bits)})',
                color='#4dabf7', edgecolor='black')
        ax1.hist(sybil_bits, bins=30, alpha=0.6, label=f'Sybil (n={len(sybil_bits)})',
                color='#ff6b6b', edgecolor='black')
        ax1.axvline(x=self.baseline_mean, color='#2ecc71', linestyle='--', linewidth=2.5,
                   label=f'Baseline (2^{self.baseline_mean:.2f})')
        ax1.axvline(x=outlier_threshold, color='#e74c3c', linestyle=':', linewidth=2.5,
                   label=f'Outlier Threshold (< 2^{outlier_threshold:.2f})')
        ax1.set_xlabel('K-distance (bits)', fontsize=12, fontweight='bold')
        ax1.set_ylabel('Fréquence', fontsize=12, fontweight='bold')
        ax1.set_title('1. Distribution complète des K-distances (Normal vs Sybil)', 
                     fontsize=13, fontweight='bold')
        ax1.legend(fontsize=10)
        ax1.grid(True, alpha=0.3, axis='y')
        
        # ============ Graphe 2: Log scale pour visualiser les outliers ==============
        ax2.hist(normal_bits, bins=30, alpha=0.6, label=f'Normal',
                color='#4dabf7', edgecolor='black')
        ax2.hist(sybil_bits, bins=30, alpha=0.6, label=f'Sybil',
                color='#ff6b6b', edgecolor='black')
        ax2.axvline(x=self.baseline_mean, color='#2ecc71', linestyle='--', linewidth=2.5)
        ax2.axvline(x=outlier_threshold, color='#e74c3c', linestyle=':', linewidth=2.5)
        ax2.set_yscale('log')
        ax2.set_xlabel('K-distance (bits)', fontsize=12, fontweight='bold')
        ax2.set_ylabel('Fréquence (log)', fontsize=12, fontweight='bold')
        ax2.set_title('2. Distribution en échelle log (mieux voir anomalies)', 
                     fontsize=13, fontweight='bold')
        ax2.grid(True, alpha=0.3, axis='y')
        
        # ============ Graphe 3: Zoom sur outliers ==============
        if outlier_bits:
            for bit_len in outlier_bits:
                is_sybil = any(d['bit_length'] == bit_len and d['is_sybil'] 
                             for d in self.k_density_data)
                color = '#ff6b6b' if is_sybil else '#ffc107'
                ax3.axvline(x=bit_len, color=color, alpha=0.3, linewidth=1)
        
        ax3.hist(outlier_bits, bins=20, alpha=0.8, color='#e74c3c', edgecolor='black', linewidth=1.5)
        ax3.axvline(x=outlier_threshold, color='#2ecc71', linestyle='--', linewidth=2.5,
                   label=f'Seuil outlier (< {outlier_threshold:.1f})')
        ax3.set_xlabel('K-distance (bits)', fontsize=12, fontweight='bold')
        ax3.set_ylabel('Fréquence', fontsize=12, fontweight='bold')
        ax3.set_title(f'3. Zoom: Outliers détectés (n={len(outlier_bits)})', 
                     fontsize=13, fontweight='bold')
        ax3.legend(fontsize=10)
        ax3.grid(True, alpha=0.3, axis='y')
        
        # ============ Graphe 4: Résumé statistiques ==============
        ax4.axis('off')
        
        normal_low_outliers = sum(1 for bit in normal_bits if bit < outlier_threshold)
        sybil_low_outliers = sum(1 for bit in sybil_bits if bit < outlier_threshold)
        sybil_pct_detected = (sybil_low_outliers / len(sybil_bits) * 100) if sybil_bits else 0
        normal_pct_fp = (normal_low_outliers / len(normal_bits) * 100) if normal_bits else 0
        
        summary_text = f"""
+======================================+
|   COMPOSITION DES ECHANTILLONS       |
+======================================+
|                                      |
| TOTAL K-distances:                   |
|   Normal:           {len(normal_bits):>6d}           |
|   Sybil:            {len(sybil_bits):>6d}           |
|   Total:            {len(normal_bits) + len(sybil_bits):>6d}           |
|                                      |
| OUTLIERS (< {outlier_threshold:.1f}):                  |
|   Normal outliers:  {normal_low_outliers:>6d} ({normal_pct_fp:>5.1f}%)       |
|   Sybil outliers:   {sybil_low_outliers:>6d} ({sybil_pct_detected:>5.1f}%)       |
|   Total outliers:   {len(outlier_bits):>6d}           |
|                                      |
| STATISTIQUES:                        |
|   Mean Normal:      {np.mean(normal_bits):>6.2f} bits        |
|   Mean Sybil:       {np.mean(sybil_bits):>6.2f} bits        |
|   Baseline ref:     {self.baseline_mean:>6.2f} bits        |
|                                      |
| SÉPARATION:                          |
|   Sybils plus proches: {self.baseline_mean - np.mean(sybil_bits):>4.2f} bits OK      |
|                                      |
+======================================╝
"""
        
        ax4.text(0.1, 0.5, summary_text, fontsize=11, family='monospace',
                verticalalignment='center', bbox=dict(boxstyle='round', 
                facecolor='wheat', alpha=0.3))
        
        plt.tight_layout()
        plt.savefig('sample_composition.png', dpi=300, bbox_inches='tight')
        print("[OK] sample_composition.png")
        plt.close()
        return True
    
    # ============================================================================
    #                      6. RAPPORT FINAL
    # ============================================================================
    
    def generate_summary(self):
        """Generer resume final"""
        censored = self.censored_searches[-1] if self.censored_searches else 0
        censorship_rate = self.censorship_rates[-1] if self.censorship_rates else 0
        normal_nodes = self.normal_counts[-1] if self.normal_counts else 0
        sybil_nodes = self.sybil_counts[-1] if self.sybil_counts else 0
        
        # Detection stats: preferer les CSV plutot que les logs
        total_tests = len(self.detection_results_data)
        positives = sum(1 for d in self.detection_results_data if d['attack_detected'])
        
        # Baseline reference
        baseline_str = "N/A"
        if self.baseline_mean:
            baseline_str = f"2^{self.baseline_mean:.2f} (from log)"
        
        # DEBUG: Show data collection stats
        print(f"\n[DEBUG] Data collection statistics:")
        print(f"   - Censorship snapshots: {len(self.censorship_rates)}")
        print(f"   - Last censorship rate: {censorship_rate:.2f}% (value: {self.censorship_rates[-1] if self.censorship_rates else 'N/A'})")
        print(f"   - All censorship rates: {self.censorship_rates[-5:] if len(self.censorship_rates) > 5 else self.censorship_rates}")
        print()
        
        summary = f"""
===========================================================
        RESUME - ATTAQUE SYBIL + DETECTION D'ANOMALIES
===========================================================

ETAT DU RESEAU (FINAL):
   Noeuds normaux: {normal_nodes}
   Noeuds Sybils: {sybil_nodes}

IMPACT DE L'ATTAQUE:
   Recherches censurees: {censored}
   Taux de censure: {censorship_rate:.2f}%

PERFORMANCE:
   Hops moyen: {self.hop_counts[-1] if self.hop_counts else 'N/A'}
   Latence: {self.latencies[-1] if self.latencies else 'N/A'} ms

DETECTION D'ANOMALIES:
   Total tests: {total_tests}
   Detections positives: {positives}
   Taux accuracy: {(positives/total_tests*100):.1f}%
   Baseline reference: {baseline_str}
   Detection method: Outlier-based anomaly detection (count low outliers)

===========================================================
"""
        print(summary)
        with open('sybil_summary.txt', 'w', encoding='utf-8') as f:
            f.write(summary)
        print("Fichier: sybil_summary.txt\n")
    
    def generate_all_plots(self):
        """
        Generer TOUS les graphes, organises par categories
        """
        print("\n" + "="*60)
        print("GENERATION DES GRAPHIQUES")
        print("="*60 + "\n")
        
        # 1. ETAT DU RESEAU
        print("[1] ETAT DU RESEAU")
        print("-" * 40)
        self.plot_network_composition()
        self.plot_performance_metrics()
        self.plot_nodes_distribution()
        print()
        
        # 2. IMPACT ATTAQUE SYBIL
        print("[2] IMPACT DE L'ATTAQUE SYBIL")
        print("-" * 40)
        self.plot_censorship_rate()
        self.plot_search_results()
        print()
        
        # 3. BASELINE DISTRIBUTION
        print("[3] BASELINE DISTRIBUTION (BASELINE-DEBUG)")
        print("-" * 40)
        if self.baseline_distribution and self.baseline_mean:
            self.plot_baseline_distribution()
        print()
        
        # 4. DETECTION (FROM CSV)
        print("[4] DETECTION D'ANOMALIES (depuis CSV)")
        print("-" * 40)
        if self.k_density_data:
            self.plot_k_density_distribution()
        
        if self.detection_results_data:
            self.plot_outlier_percentage_evolution()
            self.plot_detection_accuracy()
            
            if self.baseline_mean:
                self.plot_mean_bitlength_vs_baseline()
        
        # 5. COMPOSITION DES ECHANTILLONS
        print("[5] ECHANTILLONS UTILISES POUR LA DETECTION")
        print("-" * 40)
        if self.detection_results_data and self.baseline_mean:
            self.plot_sample_composition()
        print()
        
        # RESUME
        print("[6] RESUME FINAL")
        print("-" * 40)
        self.generate_summary()
        
        print("="*60)
        print("TOUS LES GRAPHIQUES GENERES")
        print("="*60 + "\n")


if __name__ == "__main__":
    # Usage : python scripts/graphe.py [dossier]
    # Le dossier contient les CSV exportes par une simulation (simulation_stats.csv,
    # baseline_distribution.csv, detection_results.csv, nodes_distribution.csv, et
    # eventuellement nodes_distribution_witness.csv pour le temoin sans Sybil).
    # Par defaut : results/exemple. Les figures sont ecrites dans ce meme dossier.
    import os
    from pathlib import Path

    dossier = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "results" / "exemple"
    os.chdir(dossier)

    analyzer = SybilAnalyzer(str(dossier))
    if analyzer.parse_logs():
        analyzer.generate_all_plots()
    else:
        sys.exit(1)
