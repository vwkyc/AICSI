// Global variables
let selectedOffenseIndex = null;
let offenses = [];
let analysisPolling = null;

// Check AI model status
async function checkStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        const statusDot = document.getElementById('statusDot');
        const statusText = document.getElementById('statusText');
        const modelInfo = document.getElementById('modelInfo');
        
        // Determine overall status based on both AI model and RAG system
        const aiReady = data.model_loaded;
        const ragReady = data.rag_ready;
        const aiLoading = data.loading;
        const ragLoading = data.rag_loading;
        
        if (aiReady && ragReady) {
            statusDot.className = 'status-dot ready';
            statusText.textContent = 'AI & RAG System Ready';
            modelInfo.textContent = `${data.model_name || 'AI Model'} + RAG (${data.embedding_model})`;
        } else if (aiLoading || ragLoading) {
            statusDot.className = 'status-dot loading';
            if (aiLoading && ragLoading) {
                statusText.textContent = 'Loading AI Model & RAG System...';
                modelInfo.textContent = 'Initializing both systems...';
            } else if (aiLoading) {
                statusText.textContent = 'Loading AI Model...';
                modelInfo.textContent = 'RAG ready, loading AI...';
            } else {
                statusText.textContent = 'Loading RAG System...';
                modelInfo.textContent = 'AI ready, loading RAG...';
            }
        } else if (aiReady && !ragReady) {
            statusDot.className = 'status-dot loading';
            statusText.textContent = 'AI Ready, RAG Initializing...';
            modelInfo.textContent = 'Using fallback technique selection';
        } else {
            statusDot.className = 'status-dot';
            statusText.textContent = 'Systems Not Available';
            modelInfo.textContent = 'Failed to load required components';
        }
        
        return aiReady;  // Only require AI model for basic functionality
    } catch (error) {
        console.error('Error checking status:', error);
        return false;
    }
}

// Load available offenses
async function loadOffenses() {
    try {
        const response = await fetch('/api/offenses');
        offenses = await response.json();
        
        const offenseList = document.getElementById('offenseList');
        offenseList.innerHTML = '';
        
        offenses.forEach((offense, index) => {
            const item = document.createElement('div');
            item.className = 'offense-item';
            item.onclick = () => selectOffense(index);
            
            item.innerHTML = `
                <div class="offense-name">${offense.offense_name}</div>
                <div class="offense-meta">
                    <span>Severity: ${offense.severity}</span>
                    <span>Magnitude: ${offense.magnitude}</span>
                    <span>Credibility: ${offense.credibility}</span>
                    <span>Source: ${offense.source_ip || 'N/A'}</span>
                </div>
            `;
            
            offenseList.appendChild(item);
        });
    } catch (error) {
        console.error('Error loading offenses:', error);
        document.getElementById('offenseList').innerHTML = 
            '<div class="error-message">Error loading offenses</div>';
    }
}

// Select an offense
function selectOffense(index) {
    selectedOffenseIndex = index;
    
    // Update UI
    document.querySelectorAll('.offense-item').forEach((item, i) => {
        item.classList.toggle('selected', i === index);
    });
    
    // Enable analyze button if model is ready
    checkStatus().then(ready => {
        document.getElementById('analyzeBtn').disabled = !ready;
    });
}

// Analyze selected offense
async function analyzeOffense() {
    if (selectedOffenseIndex === null) return;
    
    const analyzeBtn = document.getElementById('analyzeBtn');
    const analysisResults = document.getElementById('analysisResults');
    
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<div class="loading-spinner"></div> Analyzing...';
    
    analysisResults.innerHTML = `
        <div class="loading-container" style="flex: 1; display: flex; flex-direction: column; justify-content: center;">
            <div class="loading-spinner"></div>
            <p>AI is analyzing the security offense...</p>
            <small>This may take a few moments</small>
        </div>
    `;
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({offense_index: selectedOffenseIndex})
        });
        
        const data = await response.json();
        
        if (data.analysis_id) {
            // Poll for results
            pollAnalysisResult(data.analysis_id);
        } else {
            throw new Error(data.error || 'Unknown error');
        }
    } catch (error) {
        console.error('Error analyzing offense:', error);
        analysisResults.innerHTML = `<div class="error-message">Error: ${error.message}</div>`;
        resetAnalyzeButton();
    }
}

// Poll for analysis results
function pollAnalysisResult(analysisId) {
    analysisPolling = setInterval(async () => {
        try {
            const response = await fetch(`/api/analysis/${analysisId}`);
            const data = await response.json();
            
            if (data.status === 'completed') {
                clearInterval(analysisPolling);
                displayAnalysisResult(data.result);
                resetAnalyzeButton();
                loadPreviousResults(); // Refresh results list
            } else if (data.status === 'error') {
                clearInterval(analysisPolling);
                document.getElementById('analysisResults').innerHTML = 
                    `<div class="error-message">Analysis failed: ${data.error}</div>`;
                resetAnalyzeButton();
            }
        } catch (error) {
            console.error('Error polling analysis:', error);
            clearInterval(analysisPolling);
            resetAnalyzeButton();
        }
    }, 1000);
}

// Simple markdown to HTML converter
function simpleMarkdownToHtml(text) {
    return text
        // Bold text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        // Headers
        .replace(/^### (.*$)/gim, '<h3>$1</h3>')
        .replace(/^## (.*$)/gim, '<h2>$1</h2>')
        .replace(/^# (.*$)/gim, '<h1>$1</h1>')
        // Line breaks
        .replace(/\n\n/g, '</p><p>')
        .replace(/\n/g, '<br>')
        // Wrap in paragraphs
        .replace(/^(.+)/, '<p>$1')
        .replace(/(.+)$/, '$1</p>')
        // Clean up empty paragraphs
        .replace(/<p><\/p>/g, '')
        .replace(/<p><br>/g, '<p>')
        .replace(/<br><\/p>/g, '</p>');
}

// Display analysis result
function displayAnalysisResult(result) {
    const analysisResults = document.getElementById('analysisResults');
    
    // Handle both 'ai_analysis' and 'analysis' field names for backward compatibility
    const analysisText = result.ai_analysis || result.analysis || 'Analysis not available';
    const formattedAnalysis = simpleMarkdownToHtml(analysisText);
    
    analysisResults.innerHTML = `
        <div class="analysis-result">
            <div class="analysis-text">${formattedAnalysis}</div>
        </div>
    `;
}

// Reset analyze button
function resetAnalyzeButton() {
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    analyzeBtn.innerHTML = '🔍 Analyze Selected Offense';
    analyzeBtn.disabled = selectedOffenseIndex === null;
}

// Load previous results
async function loadPreviousResults() {
    try {
        const response = await fetch('/api/results');
        const results = await response.json();
        
        const previousResults = document.getElementById('previousResults');
        
        if (results.length === 0) {
            previousResults.innerHTML = '<div class="loading-container"><p>No previous results found</p></div>';
            return;
        }
        
        previousResults.innerHTML = '';
        
        results.forEach(result => {
            const item = document.createElement('div');
            item.className = 'result-item';
            item.onclick = () => viewResult(result.filename);
            
            // Display date in UAE timezone (Gulf Standard Time - UTC+4)
            const date = new Date(result.timestamp).toLocaleString('en-US', {
                timeZone: 'Asia/Dubai',
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            
            item.innerHTML = `
                <div class="result-name">${result.offense_name}</div>
                <div class="result-time">${date} GST</div>
            `;
            
            previousResults.appendChild(item);
        });
    } catch (error) {
        console.error('Error loading previous results:', error);
        document.getElementById('previousResults').innerHTML = 
            '<div class="error-message">Error loading previous results</div>';
    }
}

// View a specific result
async function viewResult(filename) {
    try {
        const response = await fetch(`/api/result/${filename}`);
        const result = await response.json();
        
        displayAnalysisResult(result);
    } catch (error) {
        console.error('Error viewing result:', error);
    }
}

// Initialize the app
async function init() {
    // Check status periodically until model is loaded
    const statusCheck = setInterval(async () => {
        const ready = await checkStatus();
        if (ready) {
            clearInterval(statusCheck);
        }
    }, 2000);
    
    // Load initial data
    await loadOffenses();
    await loadPreviousResults();
    
    // Initial status check
    checkStatus();
}

// Set up event listeners when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Set up analyze button
    document.getElementById('analyzeBtn').onclick = analyzeOffense;
    
    // Start the app
    init();
});
