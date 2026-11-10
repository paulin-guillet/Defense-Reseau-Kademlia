package peersim.kademlia;

/**
 * A Kademlia implementation for PeerSim extending the EDProtocol class.<br>
 * See the Kademlia bibliografy for more information about the protocol.
 *
 */

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.TreeMap;
import java.util.HashMap;

import peersim.config.Configuration;
import peersim.core.CommonState;
import peersim.core.Network;
import peersim.core.Node;
import peersim.edsim.EDProtocol;
import peersim.edsim.EDSimulator;
import peersim.transport.UnreliableTransport;

//__________________________________________________________________________________________________
public class KademliaProtocol implements Cloneable, EDProtocol {

	// VARIABLE PARAMETERS
	final String PAR_K = "K";
	final String PAR_ALPHA = "ALPHA";
	final String PAR_BITS = "BITS";

	private static final String PAR_TRANSPORT = "transport";
	private static String prefix = null;
	private UnreliableTransport transport;
	private int tid;
	private int kademliaid;


	/**
	 * allow to call the service initializer only once
	 */
	private static boolean _ALREADY_INSTALLED = false;

	/**
	 * Flag indicating if this node is a Sybil attacker node
	 */
	public boolean isSybil = false;

	/**
	 * nodeId of this pastry node
	 */
	public BigInteger nodeId;

	/**
	 * routing table of this pastry node
	 */
	public RoutingTable routingTable;

	/**
	 * trace message sent for timeout purpose
	 */
	private TreeMap<Long, Long> sentMsg;

	/**
	 * find operations set
	 */
	private LinkedHashMap<Long, FindOperation> findOp;

	/**
	 * ===== PARALLEL DETECTION SEARCHES =====
	 * Number of parallel periodic detection searches pending
	 */
	private int pendingDetectionSearches = 0;

	/**
	 * Pool collecting all nodes found from parallel detection searches
	 */
	private java.util.HashMap<BigInteger, Integer> detectionNodePool = new java.util.HashMap<>();

	/**
	 * Replicate this object by returning an identical copy.<br>
	 * It is called by the initializer and do not fill any particular field.
	 * 
	 * @return Object
	 */
	public Object clone() {
		KademliaProtocol dolly = new KademliaProtocol(KademliaProtocol.prefix);
		return dolly;
	}

	/**
	 * Used only by the initializer when creating the prototype. Every other instance call CLONE to create the new object.
	 * 
	 * @param prefix
	 *            String
	 */
	public KademliaProtocol(String prefix) {
		this.nodeId = null; // empty nodeId
		KademliaProtocol.prefix = prefix;

		_init();

		routingTable = new RoutingTable();

		sentMsg = new TreeMap<Long, Long>();

		findOp = new LinkedHashMap<Long, FindOperation>();

		tid = Configuration.getPid(prefix + "." + PAR_TRANSPORT);
	}

	/**
	 * This procedure is called only once and allow to inizialize the internal state of KademliaProtocol. Every node shares the
	 * same configuration, so it is sufficient to call this routine once.
	 */
	private void _init() {
		// execute once
		if (_ALREADY_INSTALLED)
			return;

		// read paramaters
		KademliaCommonConfig.K = Configuration.getInt(prefix + "." + PAR_K, KademliaCommonConfig.K);
		KademliaCommonConfig.ALPHA = Configuration.getInt(prefix + "." + PAR_ALPHA, KademliaCommonConfig.ALPHA);
		KademliaCommonConfig.BITS = Configuration.getInt(prefix + "." + PAR_BITS, KademliaCommonConfig.BITS);

		_ALREADY_INSTALLED = true;
	}

	/**
	 * Search through the network the Node having a specific node Id, by performing binary serach (we concern about the ordering
	 * of the network).
	 * 
	 * @param searchNodeId
	 *            BigInteger
	 * @return Node
	 */
	private Node nodeIdtoNode(BigInteger searchNodeId) {
		if (searchNodeId == null)
			return null;

		int inf = 0;
		int sup = Network.size() - 1;
		int m;

		while (inf <= sup) {
			m = (inf + sup) / 2;

			BigInteger mId = ((KademliaProtocol) Network.get(m).getProtocol(kademliaid)).nodeId;

			if (mId.equals(searchNodeId))
				return Network.get(m);

			if (mId.compareTo(searchNodeId) < 0)
				inf = m + 1;
			else
				sup = m - 1;
		}

		// perform a traditional search for more reliability (maybe the network is not ordered)
		BigInteger mId;
		for (int i = Network.size() - 1; i >= 0; i--) {
			mId = ((KademliaProtocol) Network.get(i).getProtocol(kademliaid)).nodeId;
			if (mId.equals(searchNodeId))
				return Network.get(i);
		}

		return null;
	}

	/**
	 * Perform the required operation upon receiving a message in response to a ROUTE message.<br>
	 * Update the find operation record with the closest set of neighbour received. Than, send as many ROUTE request I can
	 * (according to the ALPHA parameter).<br>
	 * If no closest neighbour available and no outstanding messages stop the find operation.
	 * 
	 * @param m
	 *            Message
	 * @param myPid
	 *            the sender Pid
	 */
	private void route(Message m, int myPid) {
		// add message source to my routing table
		if (m.src != null) {
			routingTable.addNeighbour(m.src);
		}

		// get corresponding find operation (using the message field operationId)
		FindOperation fop = this.findOp.get(m.operationId);

		if (fop != null) {
			// save received neighbour in the closest Set of fin operation
			try {
				fop.elaborateResponse((BigInteger[]) m.body);
			} catch (Exception ex) {
				fop.available_requests++;
			}

			while (fop.available_requests > 0) { // I can send a new find request

				// get an available neighbour
				BigInteger neighbour = fop.getNeighbour();

				if (neighbour != null) {
					// create a new request to send to neighbour
					Message request = new Message(Message.MSG_ROUTE);
					request.operationId = m.operationId;
					request.src = this.nodeId;
					request.dest = m.dest;

					// increment hop count
					fop.nrHops++;

					// send find request
					sendMessage(request, neighbour, myPid);
				} else if (fop.available_requests == KademliaCommonConfig.ALPHA) { // no new neighbour and no outstanding requests
					// search operation finished
					findOp.remove(fop.operationId);

					if (fop.body.equals("Automatically Generated Traffic") && fop.closestSet.containsKey(fop.destNode)) {
						// update statistics
						long timeInterval = (CommonState.getTime()) - (fop.timestamp);
						KademliaObserver.timeStore.add(timeInterval);
						KademliaObserver.hopStore.add(fop.nrHops);
						KademliaObserver.msg_deliv.add(1);
					}

					// Vérifier si c'est une recherche ciblée (Target Search Traffic)
					if (fop.body.equals("Target Search")) {
						if (fop.closestSet.size() > 0) {
							// Incrémenter seulement quand la recherche est TERMINÉE
							KademliaObserver.targetSearchCount++;
					
							if (CheckClosest(fop.getAllNeighbors(), KademliaObserver.closestKNodes)) {
								// CENSURE RÉUSSIE
								KademliaObserver.censoredSearchCount++;
							} else {
								// CENSURE ÉCHOUÉE (au moins 1 nœud non-Sybil parmi les K théoriques)
								KademliaObserver.successfulSearchCount++;
							}
						} else {
							// RECHERCHE ÉCHOUÉE (aucun résultat)
							KademliaObserver.failedSearchCount++;
						}
					}
					
					// PARALLEL DETECTION SEARCHES: Collect nodes from all M parallel searches
					// Instead of detecting immediately on each search, accumulate all findings
					if (fop.body != null && fop.body.equals("Periodic Detection Search")) {
						if (KademliaObserver.referenceBaseline != null && KademliaObserver.referenceBaseline.isReady) {
							// PHASE 1: Discovery - collect candidates if not complete yet
							if (!TrafficGenerator.discoveryComplete) {
								for (BigInteger nodeId : fop.getAllNeighbors().keySet()) {
									if (nodeId != null) {
										TrafficGenerator.explorationCandidates.add(nodeId);
									}
								}
								// Collect Phase 1 discovery results into detection pool
								collectDetectionResults(fop);
								this.pendingDetectionSearches = 0;  // Count Phase 1 discovery search
								
								TrafficGenerator.discoveryComplete = true;
							}
							// PHASE 2: Exploration - collect nodes for analysis
							else {
								// Collect nodes from this detection search into pool
								collectDetectionResults(fop);
								
								this.pendingDetectionSearches++;
								
								// After collecting 3 searches (or could use timeout), perform full analysis
								// This ensures we have enough data from multiple parallel searches
								if (this.pendingDetectionSearches >= 3) {
									performAnalysis();
									this.pendingDetectionSearches = 0;
								}
							}
						}
					}
					
					// MITIGATION: Use nodes already found during detection (no more Additional Mitigation Search)
					// The nodes are already in detectionNodePool and have been filtered
				

				return;

			} else { // no neighbour available but exists oustanding request to wait
				return;
			}
		}
	} else {
		System.err.println("There has been some error in the protocol");
	}
	}



	/**
	 * Response to a route request.<br>
	 * Find the ALPHA closest node consulting the k-buckets and return them to the sender.
	 * 
	 * @param m
	 *            Message
	 * @param myPid
	 *            the sender Pid
	 */
	private void routeResponse(Message m, int myPid) {
		// get the ALPHA closest node to destNode
		BigInteger[] neighbours = this.routingTable.getNeighbours(m.dest, m.src);

		// create a response message containing the neighbours (with the same id of the request)
		Message response = new Message(Message.MSG_RESPONSE, neighbours);
		response.operationId = m.operationId;
		response.dest = m.dest;
		response.src = this.nodeId;
		response.ackId = m.id; // set ACK number

		// send back the neighbours to the source of the message
		sendMessage(response, m.src, myPid);
	}


	/**
	 * Start a find node operation.<br>
	 * Find the ALPHA closest node and send find request to them.
	 * 
	 * @param m
	 *            Message received (contains the node to find)
	 * @param myPid
	 *            the sender Pid
	 */
	private void find(Message m, int myPid) {
		find(m, myPid, null);  // Sans detectionresult car FIND operation normale
	}

	private void find(Message m, int myPid, SybilAnomalyDetector.DetectionResult detectionResult) {

		KademliaObserver.find_op.add(1);

		// create find operation and add to operations array
		FindOperation fop = new FindOperation(m.dest, m.timestamp);
		fop.body = m.body;
		findOp.put(fop.operationId, fop);

		// MITIGATION: Link the DetectionResult if provided (passed from launchMitigationSearch)
		if (detectionResult != null) {
			fop.detectionResult = detectionResult;
		}

		// get the ALPHA closest node to srcNode and add to find operation
		BigInteger[] neighbours = this.routingTable.getNeighbours(m.dest, this.nodeId);
		fop.elaborateResponse(neighbours);
		fop.available_requests = KademliaCommonConfig.ALPHA;

		// set message operation id
		m.operationId = fop.operationId;
		m.type = Message.MSG_ROUTE;
		m.src = this.nodeId;

		// send ALPHA messages
		for (int i = 0; i < KademliaCommonConfig.ALPHA; i++) {
			BigInteger nextNode = fop.getNeighbour();
			if (nextNode != null) {
				sendMessage(m.copy(), nextNode, myPid);
				fop.nrHops++;
			}
		}

	}

	/**
	 * send a message with current transport layer and starting the timeout timer (wich is an event) if the message is a request
	 * 
	 * @param m
	 *            the message to send
	 * @param destId
	 *            the Id of the destination node
	 * @param myPid
	 *            the sender Pid
	 */
	public void sendMessage(Message m, BigInteger destId, int myPid) {
		// add destination to routing table
		this.routingTable.addNeighbour(destId);

		Node src = nodeIdtoNode(this.nodeId);
		Node dest = nodeIdtoNode(destId);

		transport = (UnreliableTransport) (Network.prototype).getProtocol(tid);
		transport.send(src, dest, m, kademliaid);

		if (m.getType() == Message.MSG_ROUTE) { // is a request
			Timeout t = new Timeout(destId, m.id, m.operationId);
			long latency = transport.getLatency(src, dest);

			// add to sent msg
			this.sentMsg.put(m.id, m.timestamp);
			EDSimulator.add(4 * latency, t, src, myPid); // set delay = 2*RTT
		}
	}

	/**
	 * manage the peersim receiving of the events
	 * 
	 * @param myNode
	 *            Node
	 * @param myPid
	 *            int
	 * @param event
	 *            Object
	 */
	public void processEvent(Node myNode, int myPid, Object event) {

		// Parse message content Activate the correct event manager fot the particular event
		this.kademliaid = myPid;

		Message m;

		switch (((SimpleEvent) event).getType()) {

			case Message.MSG_RESPONSE:
				m = (Message) event;
				sentMsg.remove(m.ackId);
				route(m, myPid);
				break;

			case Message.MSG_FINDNODE:
				m = (Message) event;
				find(m, myPid);
				break;

			case Message.MSG_ROUTE:
				m = (Message) event;
				routeResponse(m, myPid);
				break;

			case Message.MSG_EMPTY:
				// TO DO
				break;

			case Message.MSG_STORE: 
				// TO DO
				break;

			case Timeout.TIMEOUT: // timeout
				Timeout t = (Timeout) event;
				if (sentMsg.containsKey(t.msgID)) { // the response msg isn't arrived
					// remove form sentMsg
					sentMsg.remove(t.msgID);
					// remove node from my routing table
					this.routingTable.removeNeighbour(t.node);
					// remove from closestSet of find operation
					this.findOp.get(t.opID).closestSet.remove(t.node);
					// try another node
					Message m1 = new Message();
					m1.operationId = t.opID;
					m1.src = nodeId;
					m1.dest = this.findOp.get(t.opID).destNode;
					this.route(m1, myPid);
				}
				break;

		}

	}

	/**
	 * set the current NodeId
	 * 
	 * @param tmp
	 *            BigInteger
	 */
	public void setNodeId(BigInteger tmp) {
		this.nodeId = tmp;
		this.routingTable.nodeId = tmp;
	}


	/**
	 * Set this node as a Sybil node
	 */
	public void setSybil() {
		this.isSybil = true;
	}

	/**
	 * Check if this node is a Sybil
	 */
	public boolean isSybil() {
		return this.isSybil;
	}

	/**
	 * Vérifie si tous les K plus proches nœuds trouvées sont des Sybils.
	 * Compare contre la liste closestKNodes calculée par l'Observer.
	 * 
	 * Censure réussie = tous les K plus proches trouvées sont des Sybils
	 * Censure échouée = au moins un des K plus proches trouvées n'est pas un Sybil
	 * 
	 * @param closestSet HashMap des nœuds trouvés par la recherche
	 * @param closestKNodes Set des K plus proches nœuds théoriques
	 * @return true si tous les K plus proches trouvées sont des Sybils
	 */
	public boolean CheckClosest(HashMap<BigInteger, Boolean> closestSet, java.util.HashSet<BigInteger> closestKNodes) {
		// Vérifier que la liste théorique n'est pas vide
		if (closestKNodes.isEmpty()) {
			return false;
		}
		
		// Vérifier que chaque nœud des K plus proches théoriques est un Sybil
		for (BigInteger nodeId : closestKNodes) {
			if (nodeId != null) {
				// Récupérer le nœud correspondant
				Node node = nodeIdtoNode(nodeId);
				
				if (node == null) {
					return false; // Nœud non trouvé
				}
				
				// Vérifier le flag isSybil
				KademliaProtocol proto = (KademliaProtocol) node.getProtocol(kademliaid);
				if (!proto.isSybil) {
					return false; // Au moins un des K plus proches théoriques n'est pas un Sybil
				}
			}
		}
		
		// Tous les K plus proches théoriques sont des Sybils = censure réussie
		return true;
	}



/*______________________________________

  PHASE DE DETECTION DE L'ATTAQUE SYBIL
  ______________________________________
*/

	/**
	 * Collect nodes from a single "Periodic Detection Search" result into the detection pool.
	 * Accumulates bitLengths for each found node.
	 * 
	 * @param fop FindOperation that just completed
	 */
	private void collectDetectionResults(FindOperation fop) {
		// Extract all K neighbors found
		for (BigInteger nodeId : fop.getAllNeighbors().keySet()) {
			if (nodeId != null) {
				// XOR distance to target node to get bitLength for anomaly detection
				BigInteger distance = Util.distance(nodeId, KademliaObserver.targetNodeId);
				int bitLength = distance.bitLength();
				
				// Add to detection pool (accumulate across all M parallel searches)
				this.detectionNodePool.put(nodeId, bitLength);
			}
		}
	}

	/**
	 * Perform full analysis on accumulated detection nodes from all parallel searches.
	 * Analyzes top closestKNodes.size() nodes instead of just K. (This prevent consecutive positive detections)
	 * If attack detected, applies filtering and adds defensive nodes directly.
	 */
	private void performAnalysis() {
		if (KademliaObserver.referenceBaseline == null || !KademliaObserver.referenceBaseline.isReady) {
			return;
		}

		// Get the pool size to analyze: MAX(K, closestKNodes.size())
		double K = KademliaCommonConfig.K;
		int poolSize = Math.max((int) K, KademliaObserver.closestKNodes.size());

		// Extract top closestKNodes.size() nodes by bitLength (closest ones)
		HashMap<BigInteger, Boolean> topClosestNodes = getTopClosestNodes(poolSize);
		if (topClosestNodes.isEmpty()) {
			this.detectionNodePool.clear();
			return;
		}

		// Perform anomaly detection on the expanded pool
		SybilAnomalyDetector.DetectionResult anomalyResult = 
			SybilAnomalyDetector.performAnomalyDetection(
				topClosestNodes,
				KademliaObserver.targetNodeId,
				KademliaObserver.referenceBaseline,
				0.50,  // Outlier threshold: 50%
				KademliaObserver.closestKNodes.size() // Analyze at least as many nodes as closestKNodes for better accuracy
			);

		// Record detection statistics
		KademliaObserver.detectionResults.add(anomalyResult);

		if (anomalyResult.isAttackDetected) {
			System.out.println("[ALERT-DETECTION-BATCH] Sybil attack DETECTED after analyzing " + 
				topClosestNodes.size() + " nodes | Outliers=" + 
				String.format("%.1f%%", anomalyResult.outlierPercentage) + 
				" | Mean=" + String.format("%.2f", anomalyResult.meanBitLength) + " bits");
			KademliaObserver.detectionPositives++;

			// Apply mitigation directly using nodes already found (no additional searches needed)
			applyMitigation(anomalyResult);
		} else {
			System.out.println("[DETECTION-NEGATIVE] No attack detected in batch of " + 
				topClosestNodes.size() + " nodes | Outliers=" + 
				String.format("%.1f%%", anomalyResult.outlierPercentage) + 
				" | Mean=" + String.format("%.2f", anomalyResult.meanBitLength) + " bits");
			KademliaObserver.detectionNegatives++;
		}

		// Clear pool for next batch
		this.detectionNodePool.clear();
		
		// Reset exploration phase for next detection cycle
		TrafficGenerator.explorationCandidates.clear();
		TrafficGenerator.discoveryComplete = false;
	}

	/**
	 * Extract top N nodes by smallest bitLength (closest nodes) from detection pool.
	 * Returns a HashMap suitable for performAnomalyDetection.
	 * 
	 * @param topN Number of top closest nodes to extract
	 * @return HashMap of top nodes (node ID -> true)
	 */
	private HashMap<BigInteger, Boolean> getTopClosestNodes(int topN) {
		// Sort detection pool by bitLength (ascending - closest first)
		java.util.List<java.util.Map.Entry<BigInteger, Integer>> sortedList = 
			new java.util.ArrayList<>(this.detectionNodePool.entrySet());
		
		java.util.Collections.sort(sortedList, new java.util.Comparator<java.util.Map.Entry<BigInteger, Integer>>() {
			public int compare(java.util.Map.Entry<BigInteger, Integer> a, java.util.Map.Entry<BigInteger, Integer> b) {
				return Integer.compare(a.getValue(), b.getValue()); // Sort by bitLength ascending
			}
		});
		// Take top N
		HashMap<BigInteger, Boolean> topNodes = new HashMap<>();
		for (int i = 0; i < Math.min(topN, sortedList.size()); i++) {
			topNodes.put(sortedList.get(i).getKey(), true);
		}

		return topNodes;
	}



/*__________________________________________

  PHASE DE NEUTRALISATION DE L'ATTAQUE SYBIL
  __________________________________________
*/

	/**
	 * Apply mitigation by filtering detected nodes and adding them to closestKNodes.
	 * Uses the same filtering logic as before but without needing additional searches.
	 * 
	 * @param detectionResult The positive detection result
	 */
	private void applyMitigation(SybilAnomalyDetector.DetectionResult detectionResult) {
		// Apply filtering using existing method directly on detection pool
		if (!this.detectionNodePool.isEmpty() && KademliaObserver.targetNodeId != null) {
			addMitigationNodes(
				this.detectionNodePool,
				KademliaObserver.referenceBaseline,
				detectionResult
			);
			System.out.println("[MITIGATION-APPLY] Extended closestKNodes to " + 
				KademliaObserver.closestKNodes.size() + " nodes using detected pool");
		}
	}



	/**
	 * Filtre et ajoute les nœuds trouvés lors des recherches additionnelles pour la mitigation
	 * 
	 * Filtre A: Ajoute tous les nœuds PROCHES (< mean - 2σ) - zone proche Sybil
	 * Filtre B: Ajoute seulement quelques nœuds FIABLES les plus proches (zone [mean-2σ, mean+2σ])
	 * 
	 * @param foundNodes HashMap des nœuds trouvés avec leur bitLength
	 * @param baseline Statistiques de baseline pour les seuils
	 * @param detectionResult Résultat de détection pour calculer le nombre de nœuds fiables
	 */
	private void addMitigationNodes(
	        java.util.HashMap<BigInteger, Integer> foundNodes,
	        KademliaObserver.ReferenceBaseline baseline,
	        SybilAnomalyDetector.DetectionResult detectionResult) {
	    
	    
	    if (baseline != null && baseline.isReady && !foundNodes.isEmpty()) {

			
			double mean = baseline.meanKDistance;
			double stdDev = baseline.stdDevKDistance;
			double lowerBound = mean - (2.0 * stdDev);  // Seuil d'anomalie
			

			// FILTRE A: Nœuds PROCHES (< mean - 2σ)

			int addedFromFilterA = 0;
			for (BigInteger nodeId : foundNodes.keySet()) {
				int bitLength = foundNodes.get(nodeId);
				if (bitLength < lowerBound && !KademliaObserver.closestKNodes.contains(nodeId)) {
					KademliaObserver.closestKNodes.add(nodeId);
					addedFromFilterA++;
				}
			}
			
	
			// FILTRE B: Quelques nœuds FIABLES les plus proches du seuil d'anomalie

			// Nombre = CEIL(K × outlierPercentage / 100)
			int reliableNodesToAdd = (int) Math.ceil(
				KademliaCommonConfig.K * (detectionResult.outlierPercentage / 100.0)
			);
			reliableNodesToAdd = Math.max(5, Math.min(reliableNodesToAdd, 10)); // Entre 5 et 10 nœuds fiables à ajouter, selon l'excès d'anomalie détecté
			
			java.util.List<java.util.AbstractMap.SimpleEntry<BigInteger, Integer>> reliableNodes = 
				new java.util.ArrayList<>();
			
			for (BigInteger nodeId : foundNodes.keySet()) {
				int bitLength = foundNodes.get(nodeId);
				if (bitLength >= lowerBound) {
					reliableNodes.add(
						new java.util.AbstractMap.SimpleEntry<>(nodeId, bitLength)
					);
				}
			}
			
			// Trier par bitLength: les plus proches du seuil d'anomalie en premier
			reliableNodes.sort((a, b) -> Integer.compare(a.getValue(), b.getValue()));
			
			// Ajouter seulement les N plus proches fiables
			int addedFromFilterB = 0;
			int cpt = 0;
			while (cpt < reliableNodes.size() && addedFromFilterB < reliableNodesToAdd) {
				BigInteger nodeId = reliableNodes.get(cpt).getKey();
				if (!KademliaObserver.closestKNodes.contains(nodeId)) {
					KademliaObserver.closestKNodes.add(nodeId);
					addedFromFilterB++;
				}
				cpt++;
			}
			
			System.err.println("[MITIGATION] Filtered nodes: " + addedFromFilterA + 
				" close (Filtre A) + " + addedFromFilterB + 
				" reliable (Filtre B) = " + (addedFromFilterA + addedFromFilterB) + " total");
			
		} else {
			System.err.println("[MITIGATION] Cannot apply mitigation: Baseline not ready or no nodes found");
		}
	}
}
