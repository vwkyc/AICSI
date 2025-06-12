#!/usr/bin/env python3
"""
Debug script to test the RAG system for lateral movement techniques
"""

import json
import pickle
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss

# Load techniques data
print("Loading techniques data...")
with open('techniques.json', 'r') as f:
    techniques_data = json.load(f)

print(f"Loaded {len(techniques_data)} techniques")

# Find lateral movement techniques
lateral_techniques = []
for i, technique in enumerate(techniques_data):
    tactics = technique.get('tactics', [])
    if 'lateral-movement' in tactics:
        lateral_techniques.append({
            'index': i,
            'id': technique.get('attack_id'),
            'name': technique.get('name'),
            'description': technique.get('description', '')[:200] + '...'
        })

print(f"\nFound {len(lateral_techniques)} lateral movement techniques:")
for t in lateral_techniques[:5]:  # Show first 5
    print(f"  {t['id']}: {t['name']}")

# Load RAG system components
print("\nLoading RAG system...")
try:
    # Load embedding model
    embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
    print("✓ Embedding model loaded")
    
    # Load embeddings
    with open('technique_embeddings.pkl', 'rb') as f:
        technique_embeddings = pickle.load(f)
    print(f"✓ Embeddings loaded: {technique_embeddings.shape}")
    
    # Load FAISS index
    faiss_index = faiss.read_index('technique_index.faiss')
    print(f"✓ FAISS index loaded: {faiss_index.ntotal} vectors")
    
except Exception as e:
    print(f"✗ Failed to load RAG system: {e}")
    exit(1)

# Test the lateral movement query
offense_data = {
    'offense_name': 'Lateral Movement Detected',
    'magnitude': 9,
    'rule_triggered': 'Multiple SMB Auth Attempts Across Hosts',
    'event_category': 'Lateral Movement',
    'source_host': 'HR-LT-12'
}

# Create query like the app does
parts = []
if offense_data.get('offense_name'):
    parts.append(offense_data['offense_name'])
if offense_data.get('rule_triggered'):
    parts.append(offense_data['rule_triggered'])
if offense_data.get('event_category'):
    parts.append(offense_data['event_category'])

magnitude = offense_data.get('magnitude', 0)
if magnitude >= 8:
    parts.append('critical security incident high priority threat')

query = ' '.join(parts)
print(f"\nRAG Query: '{query}'")

# Get embeddings for the query
query_embedding = embedding_model.encode([query])
print(f"Query embedding shape: {query_embedding.shape}")

# Search for similar techniques using FAISS
TOP_K = 20  # Get more results to see similarities
distances, indices = faiss_index.search(query_embedding.astype('float32'), TOP_K)

print(f"\nTop {TOP_K} similar techniques:")
print("Rank | Similarity | ID      | Name")
print("-" * 60)

for i, (distance, idx) in enumerate(zip(distances[0], indices[0])):
    if idx != -1:  # Valid index
        similarity = 1 - distance  # Convert distance to similarity
        technique = techniques_data[idx]
        attack_id = technique.get('attack_id', 'Unknown')
        name = technique.get('name', 'Unknown')[:30]
        tactics = technique.get('tactics', [])
        is_lateral = 'lateral-movement' in tactics
        marker = " ← LATERAL" if is_lateral else ""
        
        print(f"{i+1:4d} | {similarity:8.3f} | {attack_id:7s} | {name}{marker}")

# Test with different similarity thresholds
thresholds = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4]
print(f"\nResults at different similarity thresholds:")
for threshold in thresholds:
    count = sum(1 for d in distances[0] if (1 - d) >= threshold and d != float('inf'))
    lateral_count = 0
    for distance, idx in zip(distances[0], indices[0]):
        if idx != -1 and (1 - distance) >= threshold:
            if 'lateral-movement' in techniques_data[idx].get('tactics', []):
                lateral_count += 1
    print(f"  Threshold {threshold}: {count} total, {lateral_count} lateral movement")
