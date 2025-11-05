# Quick Start Guide

Get your Continuous ATO Agent running in 5 minutes!

## Prerequisites Checklist

- [ ] Python 3.11 or higher
- [ ] Azure CLI installed and configured
- [ ] Access to an Azure AKS cluster
- [ ] kubectl configured
- [ ] Required Azure permissions (Reader + Security Reader)

## 5-Minute Setup

### 1. Clone and Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd cato-agent

# Run automated setup
chmod +x setup.sh
./setup.sh
```

The setup script will:
- Create Python virtual environment
- Install dependencies
- Create directory structure
- Guide you through configuration

### 2. Configure Azure Access

```bash
# Login to Azure
az login

# Set your subscription
az account set --subscription "<your-subscription-id>"

# Get AKS credentials
az aks get-credentials \
  --resource-group "<your-resource-group>" \
  --name "<your-cluster-name>"
```

### 3. Update Configuration

Edit `.env` file with your details:

```bash
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_RESOURCE_GROUP=your-resource-group
AKS_CLUSTER_NAME=your-aks-cluster-name
```

### 4. Run Your First Assessment

**Option A: Command Line**

```bash
# Activate virtual environment
source venv/bin/activate

# Run assessment
python cato_agent.py
```

**Option B: Web Dashboard**

```bash
# Start the web server
uvicorn dashboard:app --reload

# Open browser to http://localhost:8000
# Click "Run Assessment"
```

## What You'll See

### Command Line Output

```
=== Starting Continuous ATO Assessment ===
INFO: Collecting Azure Policy compliance data...
INFO: Collecting Defender for Cloud recommendations...
INFO: Collecting AKS configuration...
INFO: Collecting Kubernetes RBAC configuration...
INFO: Collecting Network Policies...
INFO: Collecting Pod Security...
INFO: Starting control assessments...

================================================================================
CONTINUOUS ATO ASSESSMENT RESULTS
================================================================================

Compliance Summary:
  Total Controls Assessed: 6
  Implemented: 3
  Partially Implemented: 2
  Not Implemented: 1
  Compliance Percentage: 50.0%
  Average Risk Score: 35.0/100

Control Assessments:
--------------------------------------------------------------------------------

AC-2: Account Management
  Status: Implemented
  Risk Score: 0/100
  Implementation: The AKS cluster implements account management through...
  
AC-3: Access Enforcement
  Status: Partially Implemented
  Risk Score: 30/100
  Gaps:
    - No RoleBindings configured
  Recommendations:
    - Create RoleBindings to enforce access controls

...
```

### Web Dashboard

1. **Status Bar**: Shows cluster configuration and assessment status
2. **Metrics**: Compliance score, control breakdown, risk scores
3. **Controls Tab**: Individual control cards with details
4. **Gaps Tab**: Prioritized list of compliance issues
5. **Recommendations Tab**: Actionable remediation steps

## Understanding Your Results

### Control Status

- **🟢 Implemented**: Control is fully implemented, no gaps identified
- **🟡 Partially Implemented**: Control is implemented with some gaps
- **🔴 Not Implemented**: Control has significant gaps or missing

### Risk Scores

- **0-25**: Low risk, minor improvements needed
- **26-50**: Medium risk, should be addressed
- **51-75**: High risk, requires attention
- **76-100**: Critical risk, immediate action required

### Key Metrics

**Compliance Percentage**: Overall percentage of controls fully implemented
- Target: 80%+ for initial ATO
- Goal: 100% for continuous ATO

**Average Risk Score**: Mean risk across all controls
- Target: <25 for production environments
- Goal: <10 for high-security environments

## Common First-Time Issues

### Issue: "Cluster not configured"

**Solution**: Make sure `.env` file has correct values:
```bash
# Check your configuration
cat .env

# Verify Azure access
az aks show --resource-group <RG> --name <CLUSTER>
```

### Issue: "Authentication failed"

**Solution**: Refresh Azure credentials:
```bash
az login
az account set --subscription "<your-subscription-id>"
```

### Issue: "Kubernetes cluster inaccessible"

**Solution**: Update kubeconfig:
```bash
az aks get-credentials --resource-group <RG> --name <CLUSTER> --overwrite-existing
kubectl cluster-info
```

### Issue: "Permission denied" errors

**Solution**: Verify you have required permissions:
- Reader role on subscription/resource group
- Security Reader for Defender for Cloud
- Kubernetes cluster access

## Next Steps

### 1. Review Your Results

Focus on controls with highest risk scores:
- Read the gaps identified
- Review recommendations
- Prioritize remediation

### 2. Address High-Priority Gaps

Common quick wins:
- Enable Azure AD integration (`AC-2`)
- Enable RBAC (`AC-3`)
- Configure network policies (`SC-7`)
- Enable disk encryption (`SC-28`)

### 3. Schedule Regular Assessments

**Manual**: Run periodically
```bash
python cato_agent.py
```

**Automated**: Deploy to AKS with CronJob
```bash
kubectl apply -f kubernetes/deployment.yaml
```

**Continuous**: Enable real-time monitoring in dashboard

### 4. Document Your Compliance

Evidence is automatically stored in `./evidence/`:
- `raw_data/`: Technical evidence files
- `assessments/`: Control assessment results

Use these for:
- Audit trail
- Compliance reports
- ATO documentation packages

## Advanced Usage

### Custom Assessment Schedule

Edit `cato_agent.py` to customize which controls to assess:

```python
async def assess_all_controls(self, evidence_data: Dict):
    assessments = [
        self.assessor.assess_ac_2(evidence_data),
        self.assessor.assess_ac_3(evidence_data),
        # Add more controls here
    ]
    return assessments
```

### Export Results

```python
import json

# Load latest results
with open('evidence/assessments/AC-2.json', 'r') as f:
    ac2_results = json.load(f)

# Generate report
print(f"AC-2 Status: {ac2_results['status']}")
print(f"Risk: {ac2_results['risk_score']}/100")
```

### Integrate with CI/CD

```yaml
# .github/workflows/compliance-check.yml
- name: Run Compliance Check
  run: |
    python cato_agent.py
    # Parse results and fail if compliance < 80%
```

## Getting Help

### Logs

Check logs for detailed information:
```bash
# Application logs
tail -f *.log

# Dashboard logs
uvicorn dashboard:app --log-level debug
```

### Debug Mode

Enable debug logging in `.env`:
```bash
LOG_LEVEL=DEBUG
```

### Common Commands

```bash
# Check Azure authentication
az account show

# Check Kubernetes access
kubectl cluster-info
kubectl get nodes

# Check agent status
curl http://localhost:8000/api/status

# Trigger assessment via API
curl -X POST http://localhost:8000/api/assess

# Get results
curl http://localhost:8000/api/results | jq
```

## Support Resources

- **Documentation**: See [README.md](README.md)
- **NIST 800-53**: [https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- **Azure Security**: [https://docs.microsoft.com/azure/security/](https://docs.microsoft.com/azure/security/)
- **AKS Best Practices**: [https://docs.microsoft.com/azure/aks/best-practices](https://docs.microsoft.com/azure/aks/best-practices)

## Success Criteria

You're successfully running when you see:

✅ Assessment completes without errors
✅ Controls are being evaluated
✅ Gaps are identified
✅ Recommendations are actionable
✅ Evidence is being collected
✅ Dashboard shows real-time status

## What's Next?

1. ✅ **Complete**: Initial setup and first assessment
2. 📋 **Next**: Review and address identified gaps
3. 🔄 **Then**: Schedule continuous monitoring
4. 📊 **Finally**: Generate compliance reports for stakeholders

Welcome to continuous compliance monitoring! 🎉