# Azure & Microsoft 365 Privilege Audit Tool 🛡️

A comprehensive security audit tool for Azure and Microsoft 365 environments, providing deep insights into permissions, roles, and security configurations across your cloud infrastructure.

![Python](https://img.shields.io/badge/python-v3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Azure](https://img.shields.io/badge/Azure-supported-0089D6)
![M365](https://img.shields.io/badge/M365-supported-00A4EF)


![image](https://github.com/user-attachments/assets/2c0955a2-0783-492c-b760-4483f3a90711)


## 🚀 Features

- **Azure Security Auditing**
  - RBAC Assignments Analysis
  - Custom Role Definitions
  - Resource Permissions
  - Subscription Access Review
  - Principal Data Enrichment

- **Microsoft 365 Security Auditing**
  - Admin Role Assignments
  - Exchange Permissions
  - SharePoint Permissions
  - Teams Configurations
  - PIM Assignments
  - Conditional Access Policies
  - Application Permissions

- **Comprehensive Reporting**
  - Excel Reports
  - JSON Export
  - Security Insights
  - Resource Distribution Analysis
  - High-Privilege Role Detection

## 📋 Prerequisites

```bash
# Required Python version
Python 3.7 or higher
Higly recommended to use Python 3.10 
# Required Azure Permissions
- Reader role at subscription level
- Microsoft Graph API permissions
- Azure AD Directory Reader

# Required M365 Permissions
- Exchange Administrator
- SharePoint Administrator
- Teams Administrator
- Security Reader
```

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/Curious4Tech/azure_m365_audit_tool.git
cd azure_m365_audit_tool/Azure_M365_Audit
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your credentials
```

## ⚙️ Configuration
## 🔑 Application Registration Setup

### Azure AD App Registration

1. **Create New Registration**
   ```plaintext
   Navigate to:
   Azure Portal → Azure Active Directory → App registrations → New registration
   ```
   - Name: Azure M365 Privilege Audit Tool
   - Supported account type: Single tenant
   - Redirect URI: (Leave blank)

2. **Required API Permissions**

   #### Microsoft Graph Permissions
   ```plaintext
   Application Permissions:
   
   # Directory Permissions
   - Directory.Read.All
   - Directory.ObjectRead.All
   - RoleManagement.Read.All
   
   # Identity Permissions
   - IdentityRiskEvent.Read.All
   - Identity.Risk.Read.All
   
   # Security Permissions
   - SecurityEvents.Read.All
   - SecurityAlert.Read.All
   
   # Microsoft 365 Services
   - Exchange.ManageAsApp
   - SharePoint.Read.All
   - Sites.Read.All
   - Team.Read.All
   - TeamSettings.Read.All
   - User.Read.All
   - Group.Read.All
   - Application.Read.All
   - Policy.Read.All
   ```

![image](https://github.com/user-attachments/assets/8bc47641-8339-4bae-b056-dc14cb41379c)

Create a `.env` file with the following variables:

```ini
# Azure Service Principal Credentials
AZURE_TENANT_ID=your_tenant_id
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret

# Optional Configuration
OUTPUT_DIR=./audit_results
```

## 🚀 Usage

Run the tool with different audit scopes:

```bash

# Ensure you're logged into Azure:
 az login

# Full audit (Azure + M365)
python azure_m365_audit.py full

# Azure-only audit
python azure_m365_audit.py azure

# M365-only audit
python azure_m365_audit.py m365

# Specify custom output directory
python azure_m365_audit.py full --output-dir ./custom_output
```

## 📊 Sample Output

```plaintext
Azure and Microsoft 365 Privilege Audit Tool
Current Date and Time (UTC): 2025-04-18 17:06:13
Current User's Login: Curious4Tech

✓ Found 3 subscriptions
✓ Found 156 RBAC assignments
✓ Found 12 custom roles
✓ Found 289 resources
...
```

## 📋 Output Files

The tool generates two types of reports:

1. **Excel Report** (`privilege_audit_YYYYMMDD_HHMMSS.xlsx`)
   - Detailed worksheets for each audit category
   - Pivot-ready data format
   - Formatted security findings

2. **JSON Report** (`privilege_audit_YYYYMMDD_HHMMSS.json`)
   - Complete raw data
   - Automation-friendly format
   - Detailed metadata

## 🔒 Security Considerations

- Store credentials securely
- Use least-privilege service principals
- Rotate secrets regularly
- Monitor audit tool access
- Review generated reports securely

## 🛠️ Troubleshooting

Common issues and solutions:

1. **Authentication Failed**
   ```bash
   # Verify environment variables
   python -c "import os; from dotenv import load_dotenv; load_dotenv(); print(os.getenv('AZURE_TENANT_ID'))"
   ```

2. **Permission Issues**
   - Verify service principal permissions
   - Check Microsoft Graph API consents
   - Review role assignments

3. **Network Issues**
   - Check Azure connectivity
   - Verify proxy settings
   - Test Microsoft Graph API access

## 📝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Azure Security Team for API documentation
- Microsoft Graph SDK contributors
- Cloud security community for feedback

## 📧 Contact

Azizou GNANKPE - [@LinkedIn](https://www.linkedin.com/in/azizou-gnankpe/)

---
⭐️ If this tool helped you, consider giving it a star!
