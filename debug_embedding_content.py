#!/usr/bin/env python3
import json

# Load techniques
with open('techniques.json', 'r') as f:
    techniques = json.load(f)

# Find a few lateral movement techniques and see what text is being embedded
lateral_techniques = []
for i, technique in enumerate(techniques):
    if 'lateral-movement' in technique.get('tactics', []):
        lateral_techniques.append((i, technique))

print('Sample lateral movement techniques and their embedded text:')
print('=' * 80)

for i, (idx, technique) in enumerate(lateral_techniques[:5]):
    print(f'Index {idx}: {technique.get("attack_id")} - {technique.get("name")}')
    
    # Recreate the text that gets embedded (from create_technique_embeddings)
    text_parts = []
    
    if technique.get('name'):
        text_parts.append(technique['name'])
    if technique.get('attack_id'):
        text_parts.append(technique['attack_id'])
    if technique.get('description'):
        desc = technique['description'][:500]  # Limit to 500 chars
        text_parts.append(desc)
    if technique.get('tactics'):
        text_parts.extend(technique['tactics'])
    if technique.get('platforms'):
        text_parts.extend(technique['platforms'])
    
    technique_text = ' '.join(text_parts)
    print(f'Embedded text: {technique_text[:300]}...')
    print('-' * 40)

print("\nNow let's check what our query looks like:")
query = 'Lateral Movement Detected Multiple SMB Auth Attempts Across Hosts Lateral Movement critical security incident high priority threat'
print(f'Query: {query}')
print(f'Query length: {len(query)}')
