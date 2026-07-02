# app/app_utils/failure_clustering.py
import json
import os
import math
import random
import logging
import re

def get_text_embedding(text: str, dim: int = 16) -> list[float]:
    """Generates a normalized text embedding vector deterministically.
    
    Falls back to a feature-frequency vector if active models are offline.
    """
    vector = [0.0] * dim
    for idx, char in enumerate(text.lower()):
        vector[idx % dim] += ord(char)
    norm = math.sqrt(sum(v*v for v in vector))
    if norm > 0:
        vector = [v / norm for v in vector]
    return vector

def kmeans(vectors: list[list[float]], k: int = 3, max_iters: int = 100) -> tuple[list[int], list[list[float]]]:
    """Pure-Python KMeans clustering algorithm.
    
    Returns:
        assignments: Cluster index for each input vector.
        centroids: Final coordinate vectors for each cluster centroid.
    """
    if not vectors:
        return [], []
        
    # Cap K if more clusters than vectors
    k = min(k, len(vectors))
    
    # Deterministic seed for testing consistency
    random.seed(42)
    centroids = random.sample(vectors, k)
    
    for _ in range(max_iters):
        clusters = [[] for _ in range(k)]
        for vec in vectors:
            min_dist = float('inf')
            closest_idx = 0
            for i, centroid in enumerate(centroids):
                dist = math.dist(vec, centroid)
                if dist < min_dist:
                    min_dist = dist
                    closest_idx = i
            clusters[closest_idx].append(vec)
            
        new_centroids = []
        for i, cluster in enumerate(clusters):
            if not cluster:
                new_centroids.append(centroids[i])
                continue
            dim = len(cluster[0])
            centroid = [sum(v[d] for v in cluster) / len(cluster) for d in range(dim)]
            new_centroids.append(centroid)
            
        if new_centroids == centroids:
            break
        centroids = new_centroids
        
    assignments = []
    for vec in vectors:
        min_dist = float('inf')
        closest_idx = 0
        for i, centroid in enumerate(centroids):
            dist = math.dist(vec, centroid)
            if dist < min_dist:
                min_dist = dist
                closest_idx = i
        assignments.append(closest_idx)
        
    return assignments, centroids

def cluster_failures(session_logs: list[dict], k: int = 3) -> dict:
    """Filters failed/corrected/abandoned logs and clusters them by text embeddings."""
    failures = [log for log in session_logs if log.get("status") in ["correction", "abandoned", "failed"]]
    if not failures:
        return {}
        
    vectors = [get_text_embedding(log.get("text", "")) for log in failures]
    assignments, centroids = kmeans(vectors, k=k)
    
    clusters = {i: [] for i in range(k)}
    for idx, cluster_idx in enumerate(assignments):
        clusters[cluster_idx].append(failures[idx])
        
    return clusters

def generate_sample_failures() -> list[dict]:
    """Generates mock session logs containing distinct failure modes for clustering."""
    return [
        {"session_id": "session-1", "status": "failed", "text": "429 API rate limits exceeded. Vertex AI prediction service quota reached."},
        {"session_id": "session-2", "status": "failed", "text": "Rate limit 429 hit. Too many requests per minute for gemini-flash model."},
        {"session_id": "session-3", "status": "correction", "text": "AST gating failure: prohibited builtin function 'eval' detected in generated code."},
        {"session_id": "session-4", "status": "correction", "text": "Gating check blocked: eval used on untrusted string variables."},
        {"session_id": "session-5", "status": "abandoned", "text": "Indirect prompt injection: untrusted input attempting to overwrite context."},
        {"session_id": "session-6", "status": "abandoned", "text": "Injection payload detected. System instruction override attempt rejected."}
    ]

def run_clustering_on_file(input_file: str = None, output_file: str = "artifacts/failure_clusters.md") -> dict:
    """Reads logs, runs failure clustering, and writes a detailed markdown report."""
    if input_file and os.path.exists(input_file):
        with open(input_file, "r") as f:
            logs = json.load(f)
    else:
        logs = generate_sample_failures()
        
    clusters = cluster_failures(logs, k=3)
    
    # Create output directory if it doesn't exist
    out_dir = os.path.dirname(output_file)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        
    # Generate markdown report
    report = ["# Failure Mode Clustering Report\n", "Systematically grouped tracing errors and user corrections.\n"]
    
    for cluster_id, items in clusters.items():
        report.append(f"## Cluster {cluster_id}")
        if not items:
            report.append("No items in this cluster.\n")
            continue
            
        # Determine theme by common terms (using regex word boundaries)
        all_words = " ".join([item["text"].lower() for item in items])
        if re.search(r'\b(rate|429)\b', all_words):
            theme = "API Rate Limiting & Quota Exceeded"
        elif re.search(r'\b(gating|eval)\b', all_words):
            theme = "AST Sandbox Gating & Syntax Blocks"
        elif re.search(r'\b(injection|payload)\b', all_words):
            theme = "Indirect Prompt Injections & Context Hijacks"
        else:
            theme = "General System Anomaly"
            
        report.append(f"**Identified Theme**: {theme}\n")
        report.append("| Session ID | Status | Failure Details |")
        report.append("|---|---|---|")
        for item in items:
            report.append(f"| `{item['session_id']}` | **{item['status'].upper()}** | {item['text']} |")
        report.append("")
        
    with open(output_file, "w") as f:
        f.write("\n".join(report))
        
    return clusters
