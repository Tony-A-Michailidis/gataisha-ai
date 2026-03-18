# Continuous Authority to Operate (cATO) Agent for Azure AKS — v2.2

An AI-powered compliance monitoring agent written with the help of Claude AI that provides **Continuous Authority to Operate** for Azure Kubernetes Service (AKS) clusters. Built on NIST 800-53 Rev 5, it implements **22 security controls** across **6 control families** (AC, SC, AU, CM, IA, SI), providing comprehensive technical compliance monitoring for regulated environments. If you decide to attempt to run this please do not commit secrets and/or evidence to a public repo!

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
- **OSCAL Export** - Standards-compliant OSCAL 1.1.2 Assessment Results (AR) export for GRC tool integration
  
<img width="3252" height="1093" alt="image" src="https://github.com/user-attachments/assets/ecbc8765-4c59-4de5-92e6-3990f83d76af" />

<img width="2604" height="1428" alt="Untitled1" src="https://github.com/user-attachments/assets/25fa0aad-7dde-4532-942b-2e5722b3ddcc" />

<img width="2604" height="1428" alt="Untitled2" src="https://github.com/user-attachments/assets/206822de-2a40-4de7-8993-be073df84b32" />

### Supported Controls

**Access Control (AC) Family:**
- AC-2: Account Management
- AC-3: Access Enforcement
- AC-6: Least Privilege

**System and Communications Protection (SC) Family:**
- SC-7: Boundary Protection
- SC-8: Transmission Confidentiality and Integrity
- SC-28: Protection of Information at Rest

**Audit and Accountability (AU) Family:**
- AU-2: Event Logging
- AU-3: Content of Audit Records
- AU-6: Audit Record Review, Analysis, and Reporting
- AU-9: Protection of Audit Information
- AU-12: Audit Record Generation

**Configuration Management (CM) Family:**
- CM-2: Baseline Configuration
- CM-3: Configuration Change Control
- CM-6: Configuration Settings
- CM-7: Least Functionality

**Identification and Authentication (IA) Family:**
- IA-2: Identification and Authentication
- IA-4: Identifier Management
- IA-5: Authenticator Management

**System and Information Integrity (SI) Family:**
- SI-2: Flaw Remediation
- SI-3: Malicious Code Protection
- SI-4: System Monitoring
- SI-5: Security Alerts and Advisories

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
├── oscal_exporter.py              # OSCAL Assessment Results generator
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

### Environment Variables

Edit `.env` file:

```bash
# Azure Configuration
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_RESOURCE_GROUP=your-resource-group
AKS_CLUSTER_NAME=your-aks-cluster

# AI Enhancement (optional but recommended - do not commit this to a repo !!!! 
ANTHROPIC_API_KEY=your-anthropic-api-key

# Application Settings
EVIDENCE_STORAGE_PATH=./evidence
LOG_LEVEL=INFO
API_HOST=0.0.0.0
API_PORT=8000
```

### Azure Authentication

The agent uses `DefaultAzureCredential` which supports:

1. **Azure CLI** (recommended for local development)
   ```bash
   az login
   ```

2. **Service Principal** (for production-  do not commit this to a repo!!!)
   ```bash
   export AZURE_CLIENT_ID=<client-id>
   export AZURE_CLIENT_SECRET=<client-secret>
   export AZURE_TENANT_ID=<tenant-id>
   ```

3. **Managed Identity** (when running in Azure)

### Kubernetes Authentication

```bash
az aks get-credentials --resource-group <rg> --name <cluster>
```

## 📡 API Reference

### Key Endpoints

**Configuration**
- `POST /api/config` - Configure AKS cluster

**Assessment**
- `POST /api/assess` - Basic assessment
- `POST /api/assess/enhanced` - AI-enhanced assessment
- `GET /api/status` - Assessment status
- `GET /api/results` - Latest results

**AI Features**
- `GET /api/executive-summary` - Executive summary
- `GET /api/remediation-plan` - Remediation plan
- `POST /api/ai/analyze-control` - Ask custom questions
- `GET /api/insights/security-posture` - Security insights

**Analysis**
- `GET /api/gaps` - All identified gaps
- `GET /api/recommendations` - All recommendations
- `GET /api/trends` - Historical trends
- `GET /api/compare` - Compare assessments

**Evidence & Export**
- `GET /api/evidence` - List evidence
- `GET /api/export/ato-package` - Export full ATO package as JSON
- `GET /api/export/oscal` - Export OSCAL 1.1.2 Assessment Results (AR) document

### Example Usage

```python
import requests

# Configure cluster
config = {
    "subscription_id": "xxx",
    "resource_group": "my-rg",
    "cluster_name": "my-aks"
}
requests.post("http://localhost:8000/api/config", json=config)

# Run AI-enhanced assessment
requests.post("http://localhost:8000/api/assess/enhanced")

# Get executive summary
summary = requests.get("http://localhost:8000/api/executive-summary").json()
print(f"Posture: {summary['overall_posture']}")
print(f"Compliance: {summary['compliance_readiness']}")
```

## 📄 OSCAL Export

The `GET /api/export/oscal` endpoint produces a standards-compliant **OSCAL 1.1.2 Assessment Results (AR)** document in JSON format. OSCAL (Open Security Controls Assessment Language) is the NIST standard for machine-readable security documentation, supported by FedRAMP and most modern GRC platforms.

### What the export contains

| OSCAL element | Source data |
|---|---|
| `findings` | One finding per control with `satisfied` / `not-satisfied` state |
| `observations` | Control narratives and evidence IDs |
| `risks` | One risk per identified gap, with likelihood and impact facets |
| `metadata` | Cluster name, framework, OSCAL version, generation timestamp |

### Status mapping

| cATO status | OSCAL state |
|---|---|
| Implemented | `satisfied` |
| Partially Implemented | `not-satisfied` |
| Not Implemented | `not-satisfied` |
| Not Assessed | `not-satisfied` |

### Risk score mapping

| Risk score | Likelihood / Impact |
|---|---|
| 0 – 30 | `low` |
| 31 – 60 | `moderate` |
| 61 – 100 | `high` |

### Example usage

```python
import requests

# Download the OSCAL AR document after running an assessment
response = requests.get("http://localhost:8000/api/export/oscal")
with open("oscal_assessment_results.json", "wb") as f:
    f.write(response.content)
```

The resulting file can be imported into any OSCAL-compatible tool (e.g., XSLT-based validators, FedRAMP automation tooling, or GRC platforms that support OSCAL 1.1.x).

## 🎨 Dashboard Features

The web dashboard provides:

- **Real-time Status** - Assessment progress and cluster configuration
- **Compliance Metrics** - Overall score, control breakdown, risk scores
- **Executive Summary** - AI-generated business-language summaries
- **Control Details** - Individual control cards with narratives
- **Gap Analysis** - Prioritized compliance gaps
- **Remediation Plan** - Phased implementation approach
- **Interactive Chat** - Ask Claude questions about controls
- **Trend Analysis** - Historical compliance tracking

## 🐳 Deployment

### Docker

```bash
docker build -t cato-agent:latest .
docker run -p 8000:8000 cato-agent:latest
```

### Kubernetes

```bash
# Update kubernetes/deployment.yaml with your values
kubectl apply -f kubernetes/deployment.yaml

# Verify deployment
kubectl get pods -n cato-system
kubectl get svc -n cato-system
```

### Scheduled Assessments

The Kubernetes deployment includes a CronJob that runs assessments every 6 hours automatically.

## 📈 Value Delivered

### Time Savings
- **Manual ATO preparation**: 40-80 hours
- **With AI Agent**: 4-8 hours
- **Savings**: ~90% reduction

### Cost Benefits
- **Traditional ATO**: $50K - $200K+ (consultants)
- **AI Agent operational cost**: ~$2-5/month (API costs)
- **ROI**: 10,000%+

### Quality Improvements
- Professional, audit-ready documentation
- Context-aware risk analysis
- Specific, actionable recommendations
- Executive communication in business language

## 🔐 Security Considerations

### Permissions Required

**Azure:**
- `Reader` role on subscription or resource group
- `Security Reader` role for Defender for Cloud

**Kubernetes:**
- Read access to cluster configuration
- List/Get permissions for RBAC resources, NetworkPolicies, Pods

### Best Practices

1. Use Managed Identity when running in Azure
2. Grant only required permissions (least privilege)
3. Secure evidence storage (may contain sensitive data)
4. Review agent access logs regularly
5. Run agent in secured network segment
6. Rotate API keys periodically

### Data Privacy

- Evidence data may be sent to Anthropic API for AI analysis
- Review your data handling policies
- Consider data sanitization for sensitive information
- Review Anthropic's privacy policy: https://www.anthropic.com/legal/privacy

## 🛠️ Development

### Running Tests

```bash
pytest tests/
```

### Code Quality

```bash
# Format code
black .

# Lint
flake8 .

# Type checking
mypy cato_agent.py cato_ai_enhanced.py
```

### Adding New Controls

To add support for additional NIST controls:

1. Add control definition in `ControlAssessor._initialize_controls()`
2. Create assessment method: `def assess_XX_Y(self, evidence_data: Dict)`
3. Add to `assess_all_controls()` method
4. Update dashboard to display new control

Example:
```python
def assess_ac_17(self, evidence_data: Dict) -> ControlAssessment:
    """Assess AC-17: Remote Access"""
    gaps = []
    recommendations = []
    
    # Assessment logic here
    
    return ControlAssessment(
        control_id='AC-17',
        control_name='Remote Access',
        family='AC',
        status=status,
        implementation_narrative=narrative,
        evidence_ids=evidence_ids,
        gaps=gaps,
        recommendations=recommendations,
        last_assessed=datetime.now(),
        risk_score=risk_score
    )
```

## 📚 Documentation

- [QUICKSTART.md](QUICKSTART.md) - 5-minute getting started guide
- [docs/AI_FEATURES.md](docs/AI_FEATURES.md) - Comprehensive AI capabilities guide
- [docs/CLAUDE_PRO_ENHANCEMENTS.md](docs/CLAUDE_PRO_ENHANCEMENTS.md) - Enhancement details
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [https://deepwiki.com/Tony-A-Michailidis/gataisha-ai](https://deepwiki.com/Tony-A-Michailidis/gataisha-ai) - DeepWiki generated documentation

## 🗺️ Roadmap

### Current (v2.2)
- ✅ AC, SC, AU, CM, IA, and SI control families (22 controls total)
- ✅ Comprehensive audit controls (AU-2, AU-3, AU-6, AU-9, AU-12)
- ✅ Full configuration management (CM-2, CM-3, CM-6, CM-7)
- ✅ Complete identity management (IA-2, IA-4, IA-5)
- ✅ Comprehensive integrity controls (SI-2, SI-3, SI-4, SI-5)
- ✅ Azure Policy, Defender for Cloud, AKS API integration
- ✅ AI-powered analysis with Claude Sonnet 4
- ✅ Interactive web dashboard
- ✅ REST API
- ✅ Comprehensive health monitoring endpoint
- ✅ OSCAL 1.1.2 Assessment Results (AR) export (`GET /api/export/oscal`)

### Planned (v2.3)
- [ ] Multi-cluster support
- [ ] Real-time alerting
- [ ] Integration with Azure DevOps for POA&M tracking
- [ ] Automated control evidence collection scheduling

### Future (v3.0)
- [ ] Automated remediation execution
- [ ] Integration with GRC platforms
- [ ] Predictive compliance drift detection
- [ ] Natural language query interface
- [ ] Integration with security scanning tools (Trivy, Falco)
- [ ] Add/Create Model Context Protocol (MCP) capabilities - very ambitious ! 

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- NIST 800-53 Rev 5 Security Controls
- Azure Security Best Practices
- Kubernetes Security Documentation
- FedRAMP Continuous Monitoring Guidelines
- Anthropic Claude AI

## 📞 Support

For issues, questions, or contributions:
- **GitHub Issues**: [Create an issue](https://github.com/yourusername/cato-agent/issues)
- **Documentation**: [Wiki](https://github.com/yourusername/cato-agent/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/cato-agent/discussions)

## ⚠️ Disclaimer

This tool is provided as-is for compliance monitoring assistance. It does not guarantee ATO approval or replace professional security assessment. Always consult with your organization's security and compliance teams.

---

**Made with ❤️ with the help of Anthropic for the Azure AKS, DevSecOps and Cyber Security community**

**Star ⭐ this repo if you find it useful!**
