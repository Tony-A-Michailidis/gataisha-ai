# Continuous Authority to Operate (cATO) Agent for Azure AKS

An AI-powered compliance monitoring agent that provides **Continuous Authority to Operate** for Azure Kubernetes Service (AKS) clusters, focused on NIST 800-53 Rev 5 Access Control (AC) and System and Communications Protection (SC) control families.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![AI Powered](https://img.shields.io/badge/AI-Claude%20Sonnet%204-purple.svg)](https://www.anthropic.com/claude)

## 🎯 Overview

This agent automates the continuous compliance monitoring and evidence collection required to maintain an Authority to Operate (ATO) in regulated environments (FedRAMP, NIST, DoD, etc.).

### Key Features

- **Real-time Compliance Monitoring** - Continuously validates NIST 800-53 control implementations
- **Automated Evidence Collection** - Gathers technical evidence from Azure Policy, Defender for Cloud, and AKS API
- **AI-Powered Assessments** - Generates control narratives and implementation status using Claude Sonnet 4
- **Gap Analysis** - Identifies compliance gaps with prioritized remediation steps
- **Interactive Dashboard** - Web-based UI for viewing compliance posture
- **Evidence Repository** - Organized storage of compliance evidence for audits
- **Executive Summaries** - Business-language reports for leadership
- **Remediation Planning** - Phased implementation plans with effort estimates

### Supported Controls

**Access Control (AC) Family:**
- AC-2: Account Management
- AC-3: Access Enforcement
- AC-6: Least Privilege

**System and Communications Protection (SC) Family:**
- SC-7: Boundary Protection
- SC-8: Transmission Confidentiality and Integrity
- SC-28: Protection of Information at Rest

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Azure CLI (authenticated)
- Access to an Azure AKS cluster
- Anthropic API key (for AI features)
- Required Azure permissions:
  - Reader on subscription/resource group
  - Security Reader (for Defender for Cloud)
  - Kubernetes cluster access

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cato-agent.git
cd cato-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your Azure configuration and API keys

# Authenticate with Azure
az login
az account set --subscription <your-subscription-id>
az aks get-credentials --resource-group <your-rg> --name <your-cluster>
```

### Running the Agent

**Option 1: Command Line Assessment**
```bash
python cato_agent.py
```

**Option 2: Web Dashboard**
```bash
# Start the API server
uvicorn cato_enhanced_dashboard:app --host 0.0.0.0 --port 8000

# Open browser to http://localhost:8000
# Click "✨ AI-Enhanced Assessment"
```

**Option 3: Docker**
```bash
docker build -t cato-agent .
docker run -p 8000:8000 \
  -v ~/.kube:/root/.kube:ro \
  -v ~/.azure:/root/.azure:ro \
  -e AZURE_SUBSCRIPTION_ID=<your-sub-id> \
  -e AZURE_RESOURCE_GROUP=<your-rg> \
  -e AKS_CLUSTER_NAME=<your-cluster> \
  -e ANTHROPIC_API_KEY=<your-api-key> \
  cato-agent
```

## 📊 AI Features

With Claude API integration, the agent provides:

### Intelligent Narratives
Context-aware, technically accurate implementation descriptions that reference your specific Azure/AKS configurations.

### Smart Risk Scoring
Holistic risk analysis considering related controls, cascading risks, and Azure-specific security implications.

### Actionable Recommendations
Specific Azure CLI/kubectl commands tailored to your environment, not generic advice.

### Executive Summaries
Business-language summaries for leadership with posture assessment, key concerns, and recommended actions.

### Remediation Planning
Phased implementation plans with task dependencies, effort estimates, and specific commands.

### Interactive Analysis
Ask Claude custom questions about your controls:
```python
"What are the security implications of this gap?"
"How does this relate to FedRAMP requirements?"
"What's the fastest way to remediate this?"
```

## 📁 Project Structure

```
cato-agent/
├── cato_agent.py                  # Main agent logic
├── cato_ai_enhanced.py            # AI enhancement module
├── cato_enhanced_dashboard.py     # FastAPI web application
├── requirements.txt               # Python dependencies
├── Dockerfile                     # Container image
├── .env.example                   # Configuration template
├── static/                        # Web dashboard
│   └── index.html
├── kubernetes/                    # K8s deployment manifests
│   └── deployment.yaml
├── .github/workflows/             # CI/CD pipeline
│   └── ci-cd.yaml
├── docs/                          # Documentation
│   ├── AI_FEATURES.md
│   └── CLAUDE_PRO_ENHANCEMENTS.md
└── evidence/                      # Evidence storage (runtime)
    ├── raw_data/
    └── assessments/
```

## 🔧 Configuration

### Environme