#!/usr/bin/env python3
import yaml
from app import find_candidate_techniques, format_offense_for_ai, load_techniques_data, ensure_rag_system

# Load data
print("Loading techniques data...")
load_techniques_data()
print("Ensuring RAG system...")
ensure_rag_system()

# Load the offense
with open('qradar_samples.yaml', 'r') as f:
    data = yaml.safe_load(f)
    offenses = data.get('qradar_offenses', [])

# Find PowerShell offense
powershell_offense = None
for offense in offenses:
    if 'PowerShell' in offense.get('offense_name', ''):
        powershell_offense = offense
        break

if powershell_offense:
    print('=== OFFENSE DATA ===')
    print(powershell_offense)
    print()
    
    print('=== RAG CANDIDATES ===')
    candidates = find_candidate_techniques(powershell_offense)
    print(f'Found {len(candidates)} candidates')
    for i, c in enumerate(candidates):
        attack_id = c.get('attack_id', 'N/A')
        name = c.get('name', 'N/A')
        score = c.get('similarity_score', 0)
        print(f'{i+1}. {attack_id}: {name} (score: {score:.2f})')
    print()
    
    print('=== PROMPT LENGTH CHECK ===')
    prompt = format_offense_for_ai(powershell_offense)
    print(f'Total prompt length: {len(prompt)} characters')
    print(f'Word count: {len(prompt.split())} words')
    print()
    
    # Check if prompt is too long
    if len(prompt) > 8000:
        print('WARNING: Prompt may be too long!')
    
    print('=== PROMPT PREVIEW (first 1000 chars) ===')
    print(prompt[:1000])
    print('...')
    print()
    
    print('=== PROMPT END (last 1000 chars) ===')
    print('...')
    print(prompt[-1000:])
else:
    print('PowerShell offense not found')
