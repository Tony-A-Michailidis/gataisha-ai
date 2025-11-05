#!/bin/bash
# setup.sh - Setup script for Continuous ATO Agent

set -e

echo "=========================================="
echo "Continuous ATO Agent Setup"
echo "=========================================="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}! $1${NC}"
}

# Check prerequisites
echo "Checking prerequisites..."

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    print_success "Python $PYTHON_VERSION found"
else
    print_error "Python 3.11+ is required"
    exit 1
fi

# Check Azure CLI
if command -v az &> /dev/null; then
    AZ_VERSION=$(az version --output tsv --query '"azure-cli"')
    print_success "Azure CLI found"
else
    print_error "Azure CLI is required. Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

# Check kubectl
if command -v kubectl &> /dev/null; then
    print_success "kubectl found"
else
    print_warning "kubectl not found. Required for Kubernetes operations."
fi

# Check Docker
if command -v docker &> /dev/null; then
    print_success "Docker found"
else
    print_warning "Docker not found. Optional for containerized deployment."
fi

echo

# Create virtual environment
echo "Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_success "Virtual environment created"
else
    print_warning "Virtual environment already exists"
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt > /dev/null 2>&1
print_success "Dependencies installed"

echo

# Create directory structure
echo "Creating directory structure..."
mkdir -p evidence/raw_data
mkdir -p evidence/assessments
mkdir -p static
print_success "Directory structure created"

echo

# Setup configuration
echo "Setting up configuration..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    print_warning "Created .env file. Please edit with your Azure configuration."
    
    read -p "Enter Azure Subscription ID: " SUBSCRIPTION_ID
    read -p "Enter Resource Group: " RESOURCE_GROUP
    read -p "Enter AKS Cluster Name: " CLUSTER_NAME
    
    sed -i "s/your-subscription-id-here/$SUBSCRIPTION_ID/g" .env
    sed -i "s/your-resource-group/$RESOURCE_GROUP/g" .env
    sed -i "s/your-aks-cluster-name/$CLUSTER_NAME/g" .env
    
    print_success "Configuration file updated"
else
    print_warning ".env file already exists"
fi

echo

# Azure authentication
echo "Checking Azure authentication..."
if az account show &> /dev/null; then
    ACCOUNT_NAME=$(az account show --query name -o tsv)
    print_success "Authenticated to Azure: $ACCOUNT_NAME"
else
    print_warning "Not authenticated to Azure"
    read -p "Authenticate now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        az login
        print_success "Azure authentication complete"
    fi
fi

echo

# AKS credentials
echo "Setting up AKS credentials..."
source .env
if [ ! -z "$AZURE_RESOURCE_GROUP" ] && [ ! -z "$AKS_CLUSTER_NAME" ]; then
    read -p "Get AKS credentials? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        az aks get-credentials --resource-group $AZURE_RESOURCE_GROUP --name $AKS_CLUSTER_NAME --overwrite-existing
        print_success "AKS credentials configured"
    fi
fi

echo

# Test configuration
echo "Testing configuration..."
if kubectl cluster-info &> /dev/null; then
    print_success "Kubernetes cluster accessible"
else
    print_warning "Cannot access Kubernetes cluster"
fi

echo

# Create static files
echo "Creating static files..."
if [ ! -f "static/index.html" ]; then
    cat > static/index.html << 'EOF'
<!-- Placeholder - Copy the dashboard HTML here -->
<!DOCTYPE html>
<html>
<head>
    <title>cATO Dashboard</title>
</head>
<body>
    <h1>Continuous ATO Dashboard</h1>
    <p>Dashboard will be available at http://localhost:8000</p>
</body>
</html>
EOF
    print_success "Static files created"
fi

echo
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo
echo "Next steps:"
echo "1. Review and update .env file with your configuration"
echo "2. Ensure you're authenticated to Azure: az login"
echo "3. Get AKS credentials: az aks get-credentials --resource-group <RG> --name <CLUSTER>"
echo "4. Run the agent:"
echo "   - Command line: python cato_agent.py"
echo "   - Web dashboard: uvicorn dashboard:app --host 0.0.0.0 --port 8000"
echo
echo "For more information, see README.md"
echo