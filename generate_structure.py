#!/usr/bin/env python3
"""
Continuous ATO Agent - File Generator
Run this script once to generate all project files
"""

import os
from pathlib import Path

def create_directory_structure():
    """Create all necessary directories"""
    directories = [
        '.github/workflows',
        'kubernetes',
        'static',
        'docs',
        'tests'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    print("✓ Directory structure created")

def create_gitignore():
    """Create .gitignore file"""
    content = """# Python
__pycache__/
*.py[cod]
*$py.class
.Python
venv/
env/
.env
.env.local

# Evidence and Logs
evidence/
*.log
logs/

# IDE
.vscode/
.idea/

# Testing
.pytest_cache/
.coverage

# OS
.DS_Store
Thumbs.db

# Secrets
*.pem
*.key
"""
    
    with open('.gitignore', 'w') as f:
        f.write(content)
    
    print("✓ .gitignore created")

def create_env_example():
    """Create .env.example file"""
    content = """# Azure Configuration
AZURE_SUBSCRIPTION_ID=your-subscription-id-here
AZURE_RESOURCE_GROUP=your-resource-group
AKS_CLUSTER_NAME=your-aks-cluster-name

# Application Configuration
EVIDENCE_STORAGE_PATH=./evidence
LOG_LEVEL=INFO
API_HOST=0.0.0.0
API_PORT=8000

# AI Enhancement - Claude API
ANTHROPIC_API_KEY=your-anthropic-api-key-here
"""
    
    with open('.env.example', 'w') as f:
        f.write(content)
    
    print("✓ .env.example created")

def create_requirements():
    """Create requirements.txt"""
    content = """# Core Azure SDK packages
azure-identity==1.15.0
azure-mgmt-resource==23.0.1
azure-mgmt-security==6.0.0
azure-mgmt-containerservice==28.0.0

# Kubernetes client
kubernetes==28.1.0

# FastAPI and web framework
fastapi==0.109.0
uvicorn[standard]==0.27.0
python-multipart==0.0.6

# Utilities
pydantic==2.5.3
python-dotenv==1.0.0
aiofiles==23.2.1

# AI/ML - Claude API
anthropic==0.39.0

# Data analysis
pandas==2.1.4
plotly==5.18.0

# Testing and quality
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
black==23.12.1
flake8==7.0.0
mypy==1.8.0
"""
    
    with open('requirements.txt', 'w') as f:
        f.write(content)
    
    print("✓ requirements.txt created")

def create_license():
    """Create LICENSE file"""
    content = """MIT License

Copyright (c) 2024 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
    
    with open('LICENSE', 'w') as f:
        f.write(content)
    
    print("✓ LICENSE created")

def create_contributing():
    """Create CONTRIBUTING.md"""
    content = """# Contributing to Continuous ATO Agent

Thank you for your interest in contributing!

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Development Setup
```bash
git clone https://github.com/yourusername/cato-agent.git
cd cato-agent
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Testing
```bash
pytest tests/
```
"""
    
    with open('CONTRIBUTING.md', 'w') as f:
        f.write(content)
    
    print("✓ CONTRIBUTING.md created")

def create_placeholder_files():
    """Create placeholder files for code that needs to be copied from artifacts"""
    
    placeholders = {
        'cato_agent.py': '# TODO: Copy content from artifact "Continuous ATO Agent - Main Application"',
        'cato_ai_enhanced.py': '# TODO: Copy content from artifact "AI-Enhanced Control Assessor"',
        'dashboard.py': '# TODO: Copy content from artifact "Continuous ATO Dashboard"',
        'cato_enhanced_dashboard.py': '# TODO: Copy content from artifact "AI-Enhanced Dashboard API"',
        'README.md': '# TODO: Copy content from artifact "README.md - Project Documentation"',
        'QUICKSTART.md': '# TODO: Copy content from artifact "QUICKSTART.md"',
        'docs/AI_FEATURES.md': '# TODO: Copy content from artifact "AI_FEATURES.md"',
        'docs/CLAUDE_PRO_ENHANCEMENTS.md': '# TODO: Copy content from artifact "CLAUDE_PRO_ENHANCEMENTS.md"',
        'kubernetes/deployment.yaml': '# TODO: Copy content from artifact "Kubernetes Deployment Manifests"',
        '.github/workflows/ci-cd.yaml': '# TODO: Copy content from artifact "GitHub Actions CI/CD"',
        'static/index.html': '<!-- TODO: Copy content from artifact "static/index.html - Complete Dashboard File" -->',
        'Dockerfile': '# TODO: Copy content from artifact "Dockerfile for Containerization"',
        'setup.sh': '#!/bin/bash\n# TODO: Copy content from artifact "Setup and Installation Scripts"',
        'tests/__init__.py': '# Empty file for Python package'
    }
    
    for filepath, content in placeholders.items():
        with open(filepath, 'w') as f:
            f.write(content + '\n')
    
    print("✓ Placeholder files created")

def create_instructions():
    """Create SETUP_INSTRUCTIONS.md with next steps"""
    content = """# Setup Instructions

## ✅ What This Script Created

This script has created the basic file and directory structure for the Continuous ATO Agent.

## 📋 Files Created Automatically:
- ✓ .gitignore
- ✓ .env.example
- ✓ requirements.txt
- ✓ LICENSE
- ✓ CONTRIBUTING.md
- ✓ Directory structure

## 📝 Files You Need to Complete:

The following files have been created as placeholders. You need to copy the content from the Claude conversation artifacts:

### Python Code Files:
1. **cato_agent.py** - Copy from artifact "Continuous ATO Agent - Main Application"
2. **cato_ai_enhanced.py** - Copy from artifact "AI-Enhanced Control Assessor"
3. **dashboard.py** - Copy from artifact "Continuous ATO Dashboard" (optional)
4. **cato_enhanced_dashboard.py** - Copy from artifact "AI-Enhanced Dashboard API"

### Documentation Files:
5. **README.md** - Copy from artifact "README.md - Project Documentation"
6. **QUICKSTART.md** - Copy from artifact "QUICKSTART.md"
7. **docs/AI_FEATURES.md** - Copy from artifact "AI_FEATURES.md"
8. **docs/CLAUDE_PRO_ENHANCEMENTS.md** - Copy from artifact "CLAUDE_PRO_ENHANCEMENTS.md"

### Deployment Files:
9. **kubernetes/deployment.yaml** - Copy from artifact "Kubernetes Deployment Manifests"
10. **.github/workflows/ci-cd.yaml** - Copy from artifact "GitHub Actions CI/CD"
11. **Dockerfile** - Copy from artifact "Dockerfile for Containerization"
12. **setup.sh** - Copy from artifact "Setup and Installation Scripts"

### Frontend:
13. **static/index.html** - Copy from artifact "static/index.html - Complete Dashboard File"

## 🚀 Next Steps:

1. Open each file with "TODO" in it
2. Find the corresponding artifact in your Claude conversation
3. Copy the content and replace the TODO line
4. Save the file
5. Move to the next file

## ⚡ Quick Commands:
```bash
# See all TODO files
grep -r "TODO" .

# After copying all files, initialize git:
git init
git add .
git commit -m "Initial commit: Continuous ATO Agent"

# Then push to GitHub (follow the GitHub push guide)
```

## ✨ When Complete:

You should have all files with actual content (no TODOs remaining).

Then follow the GitHub push guide to upload to GitHub!
"""
    
    with open('SETUP_INSTRUCTIONS.md', 'w') as f:
        f.write(content)
    
    print("✓ SETUP_INSTRUCTIONS.md created")
    print("\n" + "="*60)
    print("📖 READ: SETUP_INSTRUCTIONS.md for next steps!")
    print("="*60)

def main():
    """Main function"""
    print("\n" + "="*60)
    print("Continuous ATO Agent - File Generator")
    print("="*60 + "\n")
    
    # Create structure
    create_directory_structure()
    
    # Create config files
    create_gitignore()
    create_env_example()
    create_requirements()
    create_license()
    create_contributing()
    
    # Create placeholders
    create_placeholder_files()
    
    # Create instructions
    create_instructions()
    
    print("\n" + "="*60)
    print("✅ Basic structure created successfully!")
    print("="*60)
    print("\n📝 Next: Open SETUP_INSTRUCTIONS.md for next steps\n")

if __name__ == "__main__":
    main()