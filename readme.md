# CyberSec Intelligence Web Application

a demo for an AI-powered cybersecurity analysis dashboard that provides intelligent security offense analysis using RAG (Retrieval-Augmented Generation) and MITRE ATT&CK framework integration.

## Features

- **AI-Powered Analysis**: Leverages Mistral's Magistral Medium model via OpenRouter API
- **RAG-Enhanced Intelligence**: Semantic search to retrieve relevant MITRE ATT&CK techniques
- **MITRE ATT&CK Integration**: Comprehensive database of attack techniques with intelligent matching
- **QRadar Integration**: Analyzes QRadar offense samples with structured threat intelligence
- **Real-time Dashboard**: Modern web interface for interactive security analysis
- **Background Processing**: Asynchronous analysis with progress tracking

## Technology Stack

- **Backend**: Flask (Python)
- **AI/ML**: OpenAI API via OpenRouter, Sentence Transformers, FAISS
- **Frontend**: HTML5, CSS3, JavaScript
- **Data Processing**: PyYAML, NumPy, Pickle
- **Vector Search**: FAISS (Facebook AI Similarity Search)
- **Embeddings**: all-MiniLM-L6-v2 model for semantic matching

## Prerequisites

- Python 3.8+
- OpenRouter API key
- 4GB+ RAM
- Modern web browser

## Installation

1. **Clone the repository**
   
   **PowerShell:**
   ```powershell
   git clone <repository-url>
   cd AICSI
   ```
   
   **Bash:**
   ```bash
   git clone <repository-url>
   cd AICSI
   ```

2. **Create and activate virtual environment**
   
   **PowerShell:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
   
   **Bash:**
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   
   **PowerShell/Bash:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   Create a `.env` file or set environment variable:
   
   **PowerShell:**
   ```powershell
   $env:OPENROUTER_API_KEY="your_openrouter_api_key_here"
   ```
   
   **Bash:**
   ```bash
   export OPENROUTER_API_KEY="your_openrouter_api_key_here"
   ```

4. **Prepare data files**
   Ensure these files are present:
   - `qradar_samples.yaml` - Sample security offenses
   - `techniques.json` - MITRE ATT&CK techniques database
   - `enterprise-attack.json` - Full MITRE ATT&CK dataset

## Quick Start

1. **Start the application**
   
   **PowerShell/Bash:**
   ```bash
   python app.py
   ```

2. **Access the dashboard**
   Open your browser and navigate to: `http://localhost:5000`

3. **Initialize the system**
   - RAG system will automatically initialize embeddings and vector index
   - Wait for "RAG system ready" in console

4. **Analyze security offenses**
   - Select a QRadar offense from the dashboard
   - Click "Analyze" to start analysis
   - View real-time progress and results

## How It Works

### RAG (Retrieval-Augmented Generation) Pipeline

1. **Embedding Creation**: MITRE ATT&CK techniques are converted to vector embeddings
2. **Semantic Search**: For each offense, relevant techniques are retrieved using FAISS
3. **Context Enhancement**: Retrieved techniques are added to the AI prompt
4. **Intelligent Analysis**: Mistral AI analyzes the offense with enhanced context
5. **Structured Output**: Results include risk assessment, tactics, and response actions

### Analysis Workflow

```
Security Offense → Query Processing → RAG Retrieval → AI Analysis → Structured Report
      ↓                    ↓              ↓             ↓              ↓
QRadar Sample → Clean Text → Top-K ATT&CK → Mistral API → JSON Result
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/api/status` | GET | System status and model info |
| `/api/offenses` | GET | List QRadar offense samples |
| `/api/techniques` | GET | Search MITRE ATT&CK techniques |
| `/api/analyze` | POST | Start offense analysis |
| `/api/progress/{id}` | GET | Check analysis progress |
| `/api/results` | GET | List saved analysis results |

## Configuration

### Model Settings
```python
OPENROUTER_MODEL = "anthropic/claude-sonnet-4"  # AI model
EMBEDDING_MODEL = "all-MiniLM-L6-v2"            # Embedding model
TOP_K_TECHNIQUES = 8                            # Retrieved techniques
SIMILARITY_THRESHOLD = 0.5                      # Relevance threshold
```

### File Locations
```python
SAMPLES_FILE = "qradar_samples.yaml"           # Offense samples
TECHNIQUES_FILE = "techniques.json"            # ATT&CK techniques
EMBEDDINGS_FILE = "technique_embeddings.pkl"   # Vector embeddings
FAISS_INDEX_FILE = "technique_index.faiss"     # Search index
OUTPUT_DIR = "analysis_results"                # Analysis outputs
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
