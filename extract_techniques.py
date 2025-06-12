#!/usr/bin/env python3
"""
Preprocess MITRE ATT&CK STIX JSON to extract only techniques (attack-patterns).
Produces a smaller JSON file (techniques.json) containing a list of simplified technique entries.
"""

import json
import os

# Path to the full STIX JSON you downloaded. E.g., "enterprise-attack.json"
STIX_FILE = "enterprise-attack.json"

# Output file
OUTPUT_FILE = "techniques.json"

def extract_techniques(stix_path, output_path):
    with open(stix_path, 'r', encoding='utf-8') as f:
        stix_data = json.load(f)
    
    # The STIX bundle typically has a top-level "objects" list
    objects = stix_data.get("objects", [])
    print(f"Total STIX objects: {len(objects)}")

    techniques = []
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            technique = {}
            # STIX ID
            technique["stix_id"] = obj.get("id")
            # Name
            technique["name"] = obj.get("name")
            # Description
            # Some use "description"; sometimes MITRE includes "x_mitre_short_description"
            technique["description"] = obj.get("description", "")
            # Platforms (if available)
            if "x_mitre_platforms" in obj:
                technique["platforms"] = obj["x_mitre_platforms"]
            # Data sources (for detection guidance)
            if "x_mitre_data_sources" in obj:
                technique["data_sources"] = obj["x_mitre_data_sources"]
            # Kill chain phases (tactics)
            kc = []
            for phase in obj.get("kill_chain_phases", []):
                # Only include MITRE ATT&CK kill chain
                if phase.get("kill_chain_name", "").lower() == "mitre-attack":
                    kc.append(phase.get("phase_name"))
            if kc:
                technique["tactics"] = kc
            # ATT&CK ID from external_references
            atk_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                    atk_id = ref["external_id"]
                    break
            if atk_id:
                technique["attack_id"] = atk_id
            else:
                # Fallback: sometimes use "x_mitre_id"
                if "x_mitre_id" in obj:
                    technique["attack_id"] = obj["x_mitre_id"]
            # Optional: Add URL to MITRE ATT&CK page if you want for UI links
            if "attack_id" in technique:
                # Convert T1550.004 format to T1550/004/ format for correct MITRE URLs
                attack_id = technique['attack_id']
                if '.' in attack_id:
                    # Split on dot and join with forward slash
                    parts = attack_id.split('.')
                    formatted_id = '/'.join(parts)
                else:
                    formatted_id = attack_id
                technique["url"] = f"https://attack.mitre.org/techniques/{formatted_id}/"
            # Append to list
            techniques.append(technique)
    
    print(f"Extracted {len(techniques)} techniques")

    # Sort by ATT&CK ID (e.g., T1001 before T1002)
    def sort_key(t):
        # Remove 'T' and split if sub-technique (e.g., 'T1059.001')
        aid = t.get("attack_id", "")
        # Convert to numeric sort: split at '.', convert parts to ints
        try:
            parts = aid.lstrip("T").split(".")
            parts = [int(p) for p in parts]
            return parts
        except:
            return [float('inf')]
    techniques.sort(key=sort_key)

    # Write out
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(techniques, f, indent=2)
    print(f"Wrote simplified techniques to {output_path}")

if __name__ == "__main__":
    if not os.path.exists(STIX_FILE):
        print(f"ERROR: STIX file {STIX_FILE} not found. Please download enterprise-attack.json from MITRE ATT&CK GitHub.")
    else:
        extract_techniques(STIX_FILE, OUTPUT_FILE)
