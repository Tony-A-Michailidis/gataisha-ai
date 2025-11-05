# Contributing to Continuous ATO Agent

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
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Code Style

- Follow PEP 8
- Use Black for formatting: `black .`
- Run linting: `flake8 .`
- Add type hints where appropriate

## Testing
```bash
pytest tests/
```

## Pull Request Guidelines

- Update documentation for new features
- Add tests for new functionality
- Ensure all tests pass
- Update CHANGELOG.md (if it exists)
- Keep commits atomic and well-described

## Adding New Controls

To add support for additional NIST 800-53 controls:

1. Add control definition in `ControlAssessor._initialize_controls()`
2. Create assessment method: `def assess_XX_Y(self, evidence_data: Dict)`
3. Add to `assess_all_controls()` method
4. Update documentation

Example:
```python
def assess_ac_17(self, evidence_data: Dict) -> ControlAssessment:
    """Assess AC-17: Remote Access"""
    # Your assessment logic here
    pass
```

## Reporting Issues

When reporting issues, please include:
- Python version
- Azure SDK versions
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

## Feature Requests

We welcome feature requests! Please:
- Check existing issues first
- Clearly describe the feature and use case
- Explain how it benefits users
- Be open to discussion and feedback

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Assume good intentions

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for general questions
- Check the documentation first

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for making Continuous ATO Agent better! 🎉
```

## File Location:
```
cato-agent/
├── CONTRIBUTING.md          ← Create this file here
├── README.md
├── LICENSE
├── .gitignore
└── ... other files