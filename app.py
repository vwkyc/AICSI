#!/usr/bin/env python3
"""
CyberSec Intelligence Web Application
AI-powered security analysis dashboard with RAG-based technique retrieval
"""

import os
import json
import yaml
import logging
import threading
import pickle
import numpy as np
from datetime import datetime
from zoneinfo import ZoneInfo

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from openai import OpenAI
from sentence_transformers import SentenceTransformer
import faiss

# Configuration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = "anthropic/claude-sonnet-4"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
SITE_URL = "http://localhost:5000"  # Your site URL for OpenRouter rankings
SITE_NAME = "CyberSec Intelligence App"  # Your site name for OpenRouter rankings

SAMPLES_FILE = "qradar_samples.yaml"
OUTPUT_DIR = "analysis_results"
TECHNIQUES_FILE = "techniques.json"  # MITRE ATT&CK techniques
EMBEDDINGS_FILE = "technique_embeddings.pkl"  # Pre-computed embeddings
FAISS_INDEX_FILE = "technique_index.faiss"  # FAISS vector index
UAE_TZ = ZoneInfo("Asia/Dubai")

# RAG Configuration
EMBEDDING_MODEL = "all-MiniLM-L6-v2"  # Lightweight, fast sentence transformer
TOP_K_TECHNIQUES = 8  # Number of techniques to retrieve
SIMILARITY_THRESHOLD = 0.5  # Minimum similarity score (lowered to capture relevant techniques)

# Logging setup - Force everything to stdout with immediate flush
import sys
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True
)
logger = logging.getLogger(__name__)

# Disable Flask's default request logging to avoid spam
import logging as flask_logging
flask_logging.getLogger('werkzeug').setLevel(logging.WARNING)

# Create a custom handler that flushes immediately
class FlushingHandler(logging.StreamHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()

# Replace the handler with our flushing one
for handler in logger.handlers:
    logger.removeHandler(handler)
logger.addHandler(FlushingHandler(sys.stdout))

# Flask app
app = Flask(__name__)
CORS(app)

# Global state
openai_client = None
client_loading = False
analysis_progress = {}
techniques_data = []  # MITRE ATT&CK techniques

# RAG-related global variables
embedding_model = None
faiss_index = None
technique_embeddings = None
embedding_model_loading = False

# ==================== REQUEST LOGGING ====================

@app.before_request
def log_request():
    # Only log POST requests to avoid spam
    if request.method == 'POST':
        print(f"{request.method} {request.path}", flush=True)

@app.after_request
def log_response(response):
    # Only log POST responses to avoid spam
    if request.method == 'POST':
        emoji = "OK" if response.status_code < 400 else "ERROR"
        print(f"{emoji} {response.status_code} - {request.method} {request.path}", flush=True)
    return response

# ==================== DATA FUNCTIONS ====================

def load_techniques_data():
    """Load MITRE ATT&CK techniques from preprocessed JSON"""
    global techniques_data
    try:
        with open(TECHNIQUES_FILE, "r", encoding="utf-8") as f:
            techniques_data = json.load(f)
            logger.info(f"Loaded {len(techniques_data)} ATT&CK techniques")
    except Exception as e:
        logger.error(f"Failed to load techniques data: {e}")
        techniques_data = []

def load_qradar_samples():
    """Load offense samples from YAML"""
    try:
        with open(SAMPLES_FILE, 'r') as f:
            data = yaml.safe_load(f)
            offenses = data.get('qradar_offenses', [])
            print(f"Loaded {len(offenses)} offense samples", flush=True)
            return offenses
    except Exception as e:
        print(f"Error loading samples: {e}", flush=True)
        return []

def format_offense_for_ai(offense):
    """Format offense data for AI analysis"""
    text = f"Security Offense Analysis Request:\n\n"
    text += f"Offense: {offense.get('offense_name', 'Unknown')}\n"
    text += f"Rule: {offense.get('rule_triggered', 'Unknown')}\n"
    text += f"Category: {offense.get('event_category', 'Unknown')}\n"
    text += f"Magnitude: {offense.get('magnitude', 'N/A')}\n"
    
    if offense.get('source_ip'):
        text += f"Source IP: {offense['source_ip']}\n"
    if offense.get('destination_ip'):
        text += f"Destination IP: {offense['destination_ip']}\n"
    if offense.get('user'):
        text += f"User: {offense['user']}\n"
    
    # Add relevant MITRE ATT&CK techniques from RAG
    candidates = find_candidate_techniques(offense)
    if candidates:
        text += "\nCandidate MITRE ATT&CK Techniques (RAG-retrieved):\n"
        text += "Review these techniques and select ONLY those that are truly relevant to this specific incident:\n\n"
        for t in candidates:
            tactics_str = ", ".join(t.get("tactics", []))
            similarity = t.get('similarity_score', 0)
            description = t.get('description', 'No description available')
            platforms = ", ".join(t.get('platforms', []))
            data_sources = ", ".join(t.get('data_sources', []))
            url = t.get('url', '')
            
            text += f"- {t.get('attack_id')}: {t.get('name')}\n"
            text += f"  Description: {description}\n"
            text += f"  Tactics: {tactics_str}\n"
            text += f"  Platforms: {platforms}\n"
            if data_sources:
                text += f"  Data Sources: {data_sources}\n"
            text += f"  Reference: {url}\n"
    
    text += "\nProvide a concise security analysis in the following order:\n"
    text += "1. Risk Assessment\n"
    text += "2. Attack Type and Tactics\n"
    text += "3. Immediate Response Actions\n"
    text += "4. Prevention Recommendations\n"
    if candidates:
        text += "5. Relevant MITRE ATT&CK Techniques Analysis\n"
        text += "   - First, determine which of the above candidate techniques are actually relevant to this specific incident\n"
        text += "   - Exclude any techniques that don't directly apply to the observed behavior\n"
        text += "   - For each relevant technique you select, explain how it specifically applies to this incident\n"
        text += "   - Use only the provided descriptions - do not add information beyond what is given\n"
        text += "   - If none of the candidate techniques are relevant, state that clearly\n"
    text += "\nIMPORTANT: You have the authority to filter out irrelevant techniques. The RAG system provides candidates, but you decide which ones actually apply to this specific incident based on the evidence presented.\n"
    text += "\nFormat your response with clear section headers and keep it concise."
    
    return text

def find_candidate_techniques(offense):
    """
    Find candidate MITRE ATT&CK techniques using RAG-based semantic search.
    """
    # Initialize RAG system if not already done
    if not ensure_rag_system():
        logger.warning("RAG system not available, falling back to basic selection")
        return get_fallback_techniques(offense)
    
    try:
        # Create query text from offense data
        query_text = create_offense_query(offense)
        
        # Get embeddings for the query
        query_embedding = embedding_model.encode([query_text])
        
        # Search for similar techniques using FAISS
        distances, indices = faiss_index.search(query_embedding.astype('float32'), TOP_K_TECHNIQUES)
        
        # Filter results by similarity threshold and return techniques
        candidates = []
        for i, (distance, idx) in enumerate(zip(distances[0], indices[0])):
            if idx != -1:  # Valid index
                similarity = 1 - distance  # Convert distance to similarity
                if similarity >= SIMILARITY_THRESHOLD:
                    technique = techniques_data[idx].copy()
                    technique['similarity_score'] = float(similarity)
                    candidates.append(technique)
        
        logger.info(f"RAG retrieved {len(candidates)} candidate techniques for offense: {offense.get('offense_name', 'Unknown')}")
        return candidates
        
    except Exception as e:
        logger.error(f"RAG search failed: {e}")
        return get_fallback_techniques(offense)

def create_offense_query(offense):
    """Create a clean query from offense data for RAG search, letting embeddings handle semantics."""
    parts = []
    
    # Include offense name (cleaned of noise words)
    offense_name = offense.get('offense_name', '')
    if offense_name:
        # Remove only the most generic noise words
        meaningful_words = []
        for word in offense_name.split():
            word_lower = word.lower()
            if word_lower not in ['detected', 'alert', 'event', 'activity']:
                meaningful_words.append(word)
        if meaningful_words:
            parts.extend(meaningful_words)
    
    # Include rule triggered (the most descriptive field)
    rule = offense.get('rule_triggered', '')
    if rule:
        parts.append(rule)
    
    # Include event category if meaningful
    category = offense.get('event_category', '')
    if category and category.lower() not in ['security', 'alert', 'event']:
        parts.append(category)

    return " ".join(parts)

def get_fallback_techniques(offense):
    """Fallback technique selection when RAG is not available."""
    # Simple heuristic-based fallback
    magnitude = offense.get('magnitude', 0)
    if magnitude >= 5:
        # Return some common high-priority techniques
        fallback_ids = ["T1059", "T1055", "T1003", "T1071", "T1105", "T1566", "T1190", "T1078"]
        return [t for t in techniques_data if t.get('attack_id') in fallback_ids][:TOP_K_TECHNIQUES]
    return []

# ==================== RAG SYSTEM FUNCTIONS ====================

def initialize_embedding_model():
    """Initialize the sentence transformer model for creating embeddings."""
    global embedding_model, embedding_model_loading
    
    if embedding_model is not None:
        return True
        
    embedding_model_loading = True
    try:
        logger.info(f"Loading embedding model: {EMBEDDING_MODEL}")
        embedding_model = SentenceTransformer(EMBEDDING_MODEL)
        logger.info("Embedding model loaded successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to load embedding model: {e}")
        return False
    finally:
        embedding_model_loading = False

def create_technique_embeddings():
    """Create embeddings for all MITRE ATT&CK techniques."""
    if not techniques_data:
        logger.error("No techniques data available")
        return False
    
    try:
        logger.info("Creating embeddings for MITRE ATT&CK techniques...")
        
        # Create text representations of techniques for embedding
        technique_texts = []
        for technique in techniques_data:
            text_parts = []
            
            # Include technique name and ID
            if technique.get('name'):
                text_parts.append(technique['name'])
            if technique.get('attack_id'):
                text_parts.append(technique['attack_id'])
            
            # Include description (truncated to avoid very long texts)
            if technique.get('description'):
                desc = technique['description'][:500]  # Limit to 500 chars
                text_parts.append(desc)
            
            # Include tactics
            if technique.get('tactics'):
                text_parts.extend(technique['tactics'])
            
            # Include platforms
            if technique.get('platforms'):
                text_parts.extend(technique['platforms'])
            
            technique_text = " ".join(text_parts)
            technique_texts.append(technique_text)
        
        # Generate embeddings
        logger.info(f"Generating embeddings for {len(technique_texts)} techniques...")
        embeddings = embedding_model.encode(technique_texts, show_progress_bar=True)
        
        # Save embeddings
        logger.info(f"Saving embeddings to {EMBEDDINGS_FILE}")
        with open(EMBEDDINGS_FILE, 'wb') as f:
            pickle.dump(embeddings, f)
        
        return embeddings
        
    except Exception as e:
        logger.error(f"Failed to create technique embeddings: {e}")
        return None

def create_faiss_index(embeddings):
    """Create and save FAISS index for fast similarity search."""
    try:
        logger.info("Creating FAISS index...")
        
        # Create FAISS index (using cosine similarity)
        dimension = embeddings.shape[1]
        index = faiss.IndexFlatIP(dimension)  # Inner product for cosine similarity
        
        # Normalize embeddings for cosine similarity
        faiss.normalize_L2(embeddings)
        
        # Add embeddings to index
        index.add(embeddings.astype('float32'))
        
        # Save index
        logger.info(f"Saving FAISS index to {FAISS_INDEX_FILE}")
        faiss.write_index(index, FAISS_INDEX_FILE)
        
        return index
        
    except Exception as e:
        logger.error(f"Failed to create FAISS index: {e}")
        return None

def load_or_create_rag_system():
    """Load existing RAG system or create it if it doesn't exist."""
    global faiss_index, technique_embeddings
    
    # Try to load existing embeddings and index
    if os.path.exists(EMBEDDINGS_FILE) and os.path.exists(FAISS_INDEX_FILE):
        try:
            logger.info("Loading existing RAG system...")
            
            # Load embeddings
            with open(EMBEDDINGS_FILE, 'rb') as f:
                technique_embeddings = pickle.load(f)
            
            # Load FAISS index
            faiss_index = faiss.read_index(FAISS_INDEX_FILE)
            
            logger.info("RAG system loaded successfully")
            return True
            
        except Exception as e:
            logger.warning(f"Failed to load existing RAG system: {e}")
    
    # Create new RAG system
    logger.info("Creating new RAG system...")
    
    # Create embeddings
    technique_embeddings = create_technique_embeddings()
    if technique_embeddings is None:
        return False
    
    # Create FAISS index
    faiss_index = create_faiss_index(technique_embeddings)
    if faiss_index is None:
        return False
    
    logger.info("RAG system created successfully")
    return True

def ensure_rag_system():
    """Ensure RAG system is initialized and ready."""
    global embedding_model, faiss_index, technique_embeddings
    
    # Check if everything is ready
    if (embedding_model is not None and 
        faiss_index is not None and 
        technique_embeddings is not None):
        return True
    
    # Initialize embedding model
    if not initialize_embedding_model():
        return False
    
    # Load or create RAG system
    return load_or_create_rag_system()

def initialize_rag_background():
    """Initialize RAG system in background thread."""
    try:
        logger.info("Starting RAG system initialization...")
        if ensure_rag_system():
            logger.info("✅ RAG system ready")
        else:
            logger.error("❌ RAG system initialization failed")
    except Exception as e:
        logger.error(f"❌ RAG initialization error: {e}")

# ==================== AI FUNCTIONS ====================

def initialize_ai():
    """Initialize the OpenAI client"""
    print("Initializing OpenAI client...", flush=True)
    try:
        if not OPENROUTER_API_KEY:
            raise ValueError("OPENROUTER_API_KEY environment variable not set")
        
        client = OpenAI(
            base_url=OPENROUTER_BASE_URL,
            api_key=OPENROUTER_API_KEY,
        )
        
        print("OpenAI client initialized successfully", flush=True)
        return client
    except Exception as e:
        print(f"Failed to initialize OpenAI client: {e}", flush=True)
        raise

def analyze_offense(client, offense):
    """Analyze a security offense using OpenAI API"""
    print(f"Analyzing: {offense.get('offense_name', 'Unknown')}", flush=True)
    
    prompt = format_offense_for_ai(offense)
    print(f"Prompt length: {len(prompt)} characters", flush=True)
    print(f"Full prompt:\n{prompt}", flush=True)
    try:
        completion = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": SITE_URL,
                "X-Title": SITE_NAME,
            },
            model=OPENROUTER_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=1024,
            temperature=0.6,
            top_p=0.9,
        )
        
        # Extract the analysis content
        analysis_text = completion.choices[0].message.content or ""
        analysis_text = analysis_text.strip()
        print(f"Analysis text length: {len(analysis_text)}", flush=True)
        
        result = {
            'timestamp': datetime.now(UAE_TZ).isoformat(),
            'offense_data': offense,
            'analysis': analysis_text,
            'model_info': {
                'model': OPENROUTER_MODEL,
                'tokens_generated': len(analysis_text.split()) if analysis_text else 0,
                'api_provider': 'OpenRouter'
            }
        }
        return result
        
    except Exception as e:
        print(f"Analysis failed: {e}", flush=True)
        raise

def load_client_background():
    """Load OpenAI client in background thread"""
    global openai_client, client_loading
    client_loading = True
    try:
        openai_client = initialize_ai()
    except Exception as e:
        print(f"❌ Background client initialization failed: {e}", flush=True)
    finally:
        client_loading = False

# ==================== WEB ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    # Extract model name from the configuration
    model_name = None
    if openai_client and OPENROUTER_MODEL:
        # Format the model name nicely
        model_name = OPENROUTER_MODEL.replace('/', ' - ').replace('-', ' ').title()
    
    return jsonify({
        'model_loaded': openai_client is not None,
        'loading': client_loading,
        'model_name': model_name,
        'model': OPENROUTER_MODEL if openai_client else None,
        'api_provider': 'OpenRouter' if openai_client else None,
        'rag_ready': (embedding_model is not None and faiss_index is not None),
        'rag_loading': embedding_model_loading,
        'embedding_model': EMBEDDING_MODEL
    })

@app.route('/api/offenses')
def api_offenses():
    return jsonify(load_qradar_samples())

@app.route('/api/techniques')
def api_techniques():
    """
    Return the full list or filtered list of techniques.
    Query parameters:
      - search: substring to match in name or ID (case-insensitive)
      - tactic: filter by tactic name (e.g., Execution)
      - platform: filter by platform (e.g., Windows)
    """
    q = request.args.get('search', '').lower()
    tactic = request.args.get('tactic', '').lower()
    platform = request.args.get('platform', '').lower()

    results = techniques_data

    if q:
        results = [
            t for t in results
            if q in t.get("name", "").lower() or q in t.get("attack_id", "").lower()
        ]
    if tactic:
        results = [
            t for t in results
            if any(tactic == tac.lower().replace(" ", "-") for tac in t.get("tactics", []))
        ]
    if platform:
        results = [
            t for t in results
            if any(platform == pf.lower() for pf in t.get("platforms", []))
        ]

    # Add pagination for large result sets
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    total = len(results)
    results = results[offset:offset + limit]
    
    return jsonify({
        'techniques': results,
        'total': total,
        'limit': limit,
        'offset': offset
    })

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    print("Received analysis request", flush=True)
    
    if openai_client is None:
        print("OpenAI client not initialized", flush=True)
        return jsonify({'error': 'OpenAI client not initialized'}), 503
    
    data = request.get_json()
    offense_index = data.get('offense_index')
    
    print(f"Analyzing offense index: {offense_index}", flush=True)
    
    if offense_index is None:
        print("No offense index provided", flush=True)
        return jsonify({'error': 'No offense index provided'}), 400
    
    offenses = load_qradar_samples()
    if offense_index >= len(offenses):
        return jsonify({'error': 'Invalid offense index'}), 400
    
    selected_offense = offenses[offense_index]
    analysis_id = f"analysis_{int(datetime.now(UAE_TZ).timestamp())}"
    
    analysis_progress[analysis_id] = {'status': 'processing'}
    
    def run_analysis():
        try:
            print(f"Starting AI analysis for: {selected_offense.get('offense_name', 'Unknown')}", flush=True)
            
            result = analyze_offense(openai_client, selected_offense)
            
            print(f"AI analysis completed for: {selected_offense.get('offense_name', 'Unknown')}", flush=True)
            
            # Save result
            filename = f"analysis_{selected_offense.get('offense_name', 'unknown').replace(' ', '_').lower()}.json"
            filepath = os.path.join(OUTPUT_DIR, filename)
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            
            analysis_progress[analysis_id] = {
                'status': 'completed',
                'result': result,
                'filepath': filepath
            }
            print(f"Saved analysis to: {filepath}", flush=True)
            
        except Exception as e:
            print(f"Analysis failed for {selected_offense.get('offense_name', 'Unknown')}: {e}", flush=True)
            analysis_progress[analysis_id] = {
                'status': 'error',
                'error': str(e)
            }
    
    thread = threading.Thread(target=run_analysis)
    thread.daemon = True
    thread.start()
    
    print(f"Started analysis thread for ID: {analysis_id}", flush=True)
    
    return jsonify({'analysis_id': analysis_id})

@app.route('/api/progress/<analysis_id>')
@app.route('/api/analysis/<analysis_id>')  # Add alternative endpoint
def api_progress(analysis_id):
    """Check the progress of an analysis"""
    if analysis_id not in analysis_progress:
        return jsonify({'error': 'Analysis not found'}), 404
    
    progress_data = analysis_progress[analysis_id]
    # Only log once when checking status, not every poll
    
    return jsonify(progress_data)

@app.route('/api/results')
def api_results():
    results = []
    if os.path.exists(OUTPUT_DIR):
        for filename in os.listdir(OUTPUT_DIR):
            if filename.endswith('.json'):
                filepath = os.path.join(OUTPUT_DIR, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        results.append({
                            'filename': filename,
                            'offense_name': data.get('offense_data', {}).get('offense_name', 'Unknown'),
                            'timestamp': data.get('timestamp', 'Unknown')
                        })
                except Exception as e:
                    print(f"Error reading {filename}: {e}", flush=True)
    
    results.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify(results)

@app.route('/api/result/<filename>')
def api_get_result(filename):
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'Result not found'}), 404
    
    try:
        with open(filepath, 'r') as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== MAIN ====================

def main():
    print("CyberSec Intelligence Web App with RAG & OpenAI API")
    print("http://localhost:5000")
    print("=" * 40)
    
    # Load MITRE ATT&CK techniques data
    load_techniques_data()
    
    # Start loading OpenAI client in background
    loading_thread = threading.Thread(target=load_client_background)
    loading_thread.daemon = True
    loading_thread.start()
    
    # Start loading RAG system in background
    rag_thread = threading.Thread(target=initialize_rag_background)
    rag_thread.daemon = True
    rag_thread.start()
    
    # Start web server (disable debug to prevent threading issues)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)

if __name__ == '__main__':
    main()
