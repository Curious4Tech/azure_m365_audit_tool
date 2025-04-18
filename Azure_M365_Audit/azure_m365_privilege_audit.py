#!/usr/bin/env python3
"""
Azure and Microsoft 365 Privilege Audit Tool

This script performs a comprehensive audit of privileges and permissions across:
- Azure (Resource permissions, RBAC)
- Office 365 (Exchange, SharePoint, Teams)
- Microsoft 365 (Admin roles, Conditional Access, Privileged Identity Management)

Requirements:
pip install azure-identity azure-mgmt-authorization azure-mgmt-resource azure-mgmt-subscription
pip install msgraph-sdk requests pandas openpyxl
"""

import os
import json
import datetime
import argparse
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
from typing import Dict, List, Any, Set
import asyncio

# Corrected Azure SDK imports
from azure.identity import AzureCliCredential, DefaultAzureCredential  # Added missing import
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.core.exceptions import HttpResponseError
from msgraph import GraphServiceClient
from dotenv import load_dotenv
from pathlib import Path
from colorama import init, Fore, Back, Style
from rich.console import Console

from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import print as rprint
from rich.table import Table
from rich.box import ROUNDED
from rich.style import Style as RichStyle
# Initialize colorama
init(autoreset=True)

# Initialize Rich console
console = Console()

class AzureM365PrivilegeAudit:
    def __init__(self, output_dir: str = "./audit_results"):
        """Initialize the audit tool."""
        self.console = Console()
        # Load environment variables from .env file
        env_path = Path('.') / '.env'
        print(f"Looking for .env file at: {env_path.absolute()}")
        print(f"File exists: {env_path.exists()}")
        load_dotenv(dotenv_path=env_path)
        
        # Verify required environment variables
        self._verify_environment()
        self.audit_timestamp = datetime.datetime.now(datetime.timezone.utc)  
        self.audit_date = self.audit_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        self.audit_user = "Curious4Tech"
        self.output_dir = output_dir
        self.azure_credential = None
        self.graph_client = None
        self._initialize_authentication()
        
        # Initialize results dictionaries
        self.azure_results = {
            "subscriptions": [],
            "rbac_assignments": [],
            "custom_roles": [],
            "resources": []
        }
        
        self.m365_results = {
            "admin_roles": [],
            "exchange_permissions": [],
            "sharepoint_permissions": [],
            "teams_permissions": [],
            "pim_assignments": [],
            "conditional_access": [],
            "application_permissions": []
        }
    def _print_section_header(self, text: str):
        """Print a beautifully formatted section header."""
        self.console.print(Panel(
            f"[bold blue]{text}[/bold blue]",
            style="blue",
            box=ROUNDED
        ))

    def _print_success(self, text: str):
        """Print a success message."""
        self.console.print(f"[green]✓[/green] {text}")

    def _print_error(self, text: str):
        """Print an error message."""
        self.console.print(f"[red]✗[/red] {text}")

    def _print_warning(self, text: str):
        """Print a warning message."""
        self.console.print(f"[yellow]![/yellow] {text}")

    def _print_info(self, text: str):
        """Print an info message."""
        self.console.print(f"[blue]ℹ[/blue] {text}")
    def _verify_environment(self):
        """Verify all required environment variables are set."""
        required_vars = ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET']
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        
        if missing_vars:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing_vars)}\n"
                f"Please check your .env file and ensure all required variables are set."
            )

    def _initialize_authentication(self):
        """Initialize authentication using environment variables."""
        try:
            print("Using environment credentials for authentication.")
            from azure.identity import ClientSecretCredential
            
            # Get credentials from environment variables
            tenant_id = os.getenv('AZURE_TENANT_ID')
            client_id = os.getenv('AZURE_CLIENT_ID')
            client_secret = os.getenv('AZURE_CLIENT_SECRET')
            
            # Initialize the credential
            graph_credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            
            # Initialize Graph client with properly formatted scopes
            scopes = [
                'https://graph.microsoft.com/.default'  # Keep only the default scope
            ]
            
            self.graph_client = GraphServiceClient(
                credentials=graph_credential,
                scopes=scopes  # Pass as a list
            )
            
            # Store Azure credential for Azure-specific operations
            self.azure_credential = graph_credential
            
            print("Authentication initialized successfully.")
        except Exception as e:
            print(f"Authentication failed: {str(e)}")
            raise
    async def audit_azure_subscriptions(self):
        """Audit Azure subscriptions"""
        print("Auditing Azure subscriptions...")
        try:
            sub_client = SubscriptionClient(self.azure_credential)
            subscriptions = sub_client.subscriptions.list()
            
            # Process each subscription
            for sub in subscriptions:
                self.azure_results["subscriptions"].append({
                    "id": sub.subscription_id,
                    "name": sub.display_name,
                    "state": sub.state,
                    "tenant_id": sub.tenant_id if hasattr(sub, 'tenant_id') else None
                })
            
            print(f"Found {len(self.azure_results['subscriptions'])} subscriptions.")
        except Exception as e:
            print(f"Error auditing subscriptions: {str(e)}")
            raise

    async def audit_azure_rbac(self):
        """Audit Azure RBAC assignments"""
        print("Auditing Azure RBAC assignments...")
        try:
            if not self.azure_results["subscriptions"]:
                raise ValueError("No subscriptions found. Run audit_azure_subscriptions first.")
                
            auth_client = AuthorizationManagementClient(
                credential=self.azure_credential,
                subscription_id=self._get_first_subscription_id()
            )
            
            # Use list_for_scope instead of list
            scope = f"/subscriptions/{self._get_first_subscription_id()}"
            assignments = auth_client.role_assignments.list_for_scope(
                scope=scope,
                filter=None
            )
            
            for assignment in assignments:
                self.azure_results["rbac_assignments"].append({
                    "role": assignment.role_definition_id.split('/')[-1],
                    "principal_id": assignment.principal_id,
                    "scope": assignment.scope,
                    "principal_type": assignment.principal_type if hasattr(assignment, 'principal_type') else None
                })
            
            print(f"Found {len(self.azure_results['rbac_assignments'])} RBAC assignments.")
        except Exception as e:
            print(f"Error auditing RBAC assignments: {str(e)}")
            raise
    async def audit_azure_custom_roles(self):
        """Audit custom RBAC roles"""
        print("Auditing custom roles...")
        try:
            auth_client = AuthorizationManagementClient(
                credential=self.azure_credential,
                subscription_id=self._get_first_subscription_id()
            )
            
            # Add the required scope parameter
            scope = f"/subscriptions/{self._get_first_subscription_id()}"
            roles = auth_client.role_definitions.list(scope=scope)
            
            for role in roles:
                if role.role_type == "CustomRole":
                    self.azure_results["custom_roles"].append({
                        "name": role.role_name,
                        "id": role.id,
                        "description": role.description if hasattr(role, 'description') else None,
                        "permissions": [p.actions for p in role.permissions] if role.permissions else []
                    })
            
            print(f"Found {len(self.azure_results['custom_roles'])} custom roles.")
        except Exception as e:
            print(f"Error auditing custom roles: {str(e)}")
            raise
    async def audit_azure_resources(self):
        """Audit resource permissions"""
        print("Auditing Azure resources...")
        try:
            resource_client = ResourceManagementClient(
                credential=self.azure_credential,
                subscription_id=self._get_first_subscription_id()
            )
            
            # Initialize the resources list if it doesn't exist
            if "resources" not in self.azure_results:
                self.azure_results["resources"] = []
            
            # Get resources with error handling and progress tracking
            try:
                resources = list(resource_client.resources.list())
                print(f"Scanning {len(resources)} Azure resources...")
                
                for resource in resources:
                    self.azure_results["resources"].append({
                        "name": resource.name,
                        "type": resource.type,
                        "location": resource.location,
                        "id": resource.id
                    })
                
                print(f"Found {len(self.azure_results['resources'])} resources.")
                
                # Add resource type summary
                resource_types = {}
                for resource in self.azure_results["resources"]:
                    resource_type = resource["type"]
                    resource_types[resource_type] = resource_types.get(resource_type, 0) + 1
                
                # Print resource type distribution
                if resource_types:
                    print("\nResource type distribution:")
                    for rtype, count in sorted(resource_types.items(), key=lambda x: x[1], reverse=True):
                        print(f"  {rtype}: {count}")
                    
            except Exception as list_error:
                print(f"Error listing resources: {str(list_error)}")
                raise
                
        except Exception as e:
            print(f"Error auditing resources: {str(e)}")
            raise

    def _get_first_subscription_id(self):
        """Get first subscription ID from results"""
        if not self.azure_results["subscriptions"]:
            raise ValueError("No subscriptions found")
        return self.azure_results["subscriptions"][0]["id"]

    async def enrich_principal_data(self):
        """Enrich principal data with async calls to Microsoft Graph"""
        print("Enriching principal data...")
        
        async def get_principal_details(principal_id):
            try:
                user = await self.graph_client.users.by_user_id(principal_id).get()
                return {
                    'type': 'User',
                    'name': user.display_name,
                    'email': user.mail if hasattr(user, 'mail') else None
                }
            except Exception:
                try:
                    group = await self.graph_client.groups.by_group_id(principal_id).get()
                    return {
                        'type': 'Group',
                        'name': group.display_name,
                        'email': group.mail if hasattr(group, 'mail') else None
                    }
                except Exception:
                    try:
                        sp = await self.graph_client.service_principals.by_service_principal_id(principal_id).get()
                        return {
                            'type': 'ServicePrincipal',
                            'name': sp.display_name,
                            'appId': sp.app_id if hasattr(sp, 'app_id') else None
                        }
                    except Exception:
                        return {'type': 'Unknown', 'name': 'Not Found', 'id': principal_id}

        try:
            # Process Azure RBAC assignments
            for assignment in self.azure_results["rbac_assignments"]:
                principal_id = assignment.get("principal_id")
                if principal_id:
                    details = await get_principal_details(principal_id)
                    assignment.update(details)
            
            print("Principal data enrichment completed.")
        except Exception as e:
            print(f"Error enriching principal data: {str(e)}")
            raise
            
    def export_to_excel(self):
        """Export audit results to Excel."""
        try:
            timestamp = self.audit_timestamp.strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.output_dir, f"privilege_audit_{timestamp}.xlsx")
            
            print(f"Exporting results to {filename}...")
                
            # Check if we have any data to export
            has_data = any(self.azure_results.values()) or any(self.m365_results.values())
            
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                # Create audit info sheet with metadata
                audit_info = {
                    "Audit Date (UTC)": [self.audit_date],
                    "Audit User": [self.audit_user],
                    "Export Time (UTC)": [datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")]
                }
                
                pd.DataFrame(audit_info).to_excel(
                    writer, 
                    sheet_name="Audit_Info",
                    index=False
                )
                
                if not has_data:
                    print("No data to export. Only metadata sheet will be created.")
                    return filename
                
                # Helper function to convert timezone-aware datetimes
                def prepare_data(data):
                    if isinstance(data, list):
                        return [{k: v.replace(tzinfo=None) if isinstance(v, datetime.datetime) else v 
                                for k, v in item.items()} for item in data]
                    return data
                
                # Export Azure results
                for category, data in self.azure_results.items():
                    if data:
                        try:
                            if category == "custom_roles":
                                flattened_roles = self._flatten_custom_roles(data)
                                prepared_data = prepare_data(flattened_roles)
                                pd.DataFrame(prepared_data).to_excel(
                                    writer, 
                                    sheet_name=f"Azure_{category[:25]}", 
                                    index=False
                                )
                            else:
                                prepared_data = prepare_data(data)
                                pd.DataFrame(prepared_data).to_excel(
                                    writer, 
                                    sheet_name=f"Azure_{category[:25]}", 
                                    index=False
                                )
                        except Exception as e:
                            print(f"Warning: Failed to export {category}: {str(e)}")
                
                # Export M365 results
                for category, data in self.m365_results.items():
                    if data:
                        try:
                            prepared_data = prepare_data(data)
                            df = pd.DataFrame(prepared_data)
                            
                            # Additional handling for datetime columns
                            for col in df.select_dtypes(include=['datetime64[ns, UTC]']).columns:
                                df[col] = df[col].dt.tz_localize(None)
                            
                            df.to_excel(
                                writer, 
                                sheet_name=f"M365_{category[:25]}", 
                                index=False
                            )
                        except Exception as e:
                            print(f"Warning: Failed to export {category}: {str(e)}")
            
            print(f"Results exported successfully to {filename}")
            return filename
        except Exception as e:
            print(f"Error exporting to Excel: {str(e)}")
            raise
    def export_to_json(self):
        """Export audit results to JSON."""
        try:
            timestamp = self.audit_timestamp.strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.output_dir, f"privilege_audit_{timestamp}.json")
            
            print(f"Exporting results to {filename}...")
            
            combined_results = {
                "azure": self.azure_results,
                "m365": self.m365_results,
                "metadata": {
                    "audit_date_utc": self.audit_date,
                    "audit_user": self.audit_user,
                    "export_time_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    "data_categories": {
                        "azure": list(self.azure_results.keys()),
                        "m365": list(self.m365_results.keys())
                    }
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(combined_results, f, indent=2, default=str)
            
            print(f"Results exported successfully to {filename}")
            return filename
        except Exception as e:
            print(f"Error exporting to JSON: {str(e)}")
            raise

    def _flatten_custom_roles(self, custom_roles):
        """Helper method to flatten custom roles for Excel export."""
        try:
            flattened_roles = []
            for role in custom_roles:
                try:
                    flat_role = {
                        "subscription_id": role.get("subscription_id", ""),
                        "subscription_name": role.get("subscription_name", ""),
                        "role_id": role.get("role_id", ""),
                        "role_name": role.get("role_name", ""),
                        "description": role.get("description", ""),
                        "assignable_scopes": ";".join(role.get("assignable_scopes", []))
                    }
                    
                    # Flatten permissions
                    permissions = role.get("permissions", [])
                    for i, perm in enumerate(permissions):
                        flat_role[f"actions_{i}"] = ";".join(perm.get("actions", []))
                        flat_role[f"not_actions_{i}"] = ";".join(perm.get("not_actions", []))
                        flat_role[f"data_actions_{i}"] = ";".join(perm.get("data_actions", []))
                        flat_role[f"not_data_actions_{i}"] = ";".join(perm.get("not_data_actions", []))
                    
                    flattened_roles.append(flat_role)
                except Exception as e:
                    print(f"Warning: Failed to flatten role {role.get('role_name', 'unknown')}: {str(e)}")
                    continue
            
            return flattened_roles
        except Exception as e:
            print(f"Error flattening custom roles: {str(e)}")
            raise
    
    
    async def audit_m365_admin_roles(self):
        """Audit Microsoft 365 admin roles."""
        try:
            print("Auditing Microsoft 365 admin roles...")
            
            # Get directory roles
            response = await self.graph_client.directory_roles.get()
            directory_roles = response.value if hasattr(response, 'value') else []
            
            for role in directory_roles:
                # Get members of each role
                members_response = await self.graph_client.directory_roles.by_directory_role_id(role.id).members.get()
                members = members_response.value if hasattr(members_response, 'value') else []
                
                for member in members:
                    self.m365_results["admin_roles"].append({
                        "role_id": role.id,
                        "role_name": role.display_name,
                        "member_id": member.id,
                        "member_display_name": member.display_name,
                        "member_type": member.object_type if hasattr(member, 'object_type') else member.odata_type
                    })
            
            print(f"Found {len(self.m365_results['admin_roles'])} admin role assignments.")
            return self.m365_results["admin_roles"]
        except Exception as e:
            print(f"Error auditing M365 admin roles: {str(e)}")
            return []

    async def audit_exchange_permissions(self):
        """Audit Exchange Online permissions."""
        try:
            print("Auditing Exchange Online permissions...")
            
            # Get mailboxes
            response = await self.graph_client.users.get()
            mailboxes = response.value if hasattr(response, 'value') else []
            
            for mailbox in mailboxes:
                try:
                    # Delegate permissions
                    rules_response = await self.graph_client.users.by_user_id(mailbox.id).mail_folders.by_mail_folder_id('inbox').message_rules.get()
                    delegates = rules_response.value if hasattr(rules_response, 'value') else []
                    
                    for delegate in delegates:
                        self.m365_results["exchange_permissions"].append({
                            "mailbox_id": mailbox.id,
                            "mailbox_name": mailbox.display_name,
                            "permission_type": "Delegate",
                            "grantee_id": delegate.id if hasattr(delegate, 'id') else "",
                            "permissions": json.dumps(delegate.actions.to_dict()) if hasattr(delegate, 'actions') else ""
                        })
                except Exception as e:
                    pass
            
            print(f"Found {len(self.m365_results['exchange_permissions'])} Exchange permissions.")
            return self.m365_results["exchange_permissions"]
        except Exception as e:
            print(f"Error auditing Exchange permissions: {str(e)}")
            return []

    async def audit_sharepoint_permissions(self):
        """Audit SharePoint Online permissions."""
        try:
            print("Auditing SharePoint Online permissions...")
            
            # Get sites
            response = await self.graph_client.sites.get()
            sites = response.value if hasattr(response, 'value') else []
            
            for site in sites:
                try:
                    # Get site permissions
                    perms_response = await self.graph_client.sites.by_site_id(site.id).permissions.get()
                    permissions = perms_response.value if hasattr(perms_response, 'value') else []
                    
                    for permission in permissions:
                        self.m365_results["sharepoint_permissions"].append({
                            "site_id": site.id,
                            "site_name": site.display_name,
                            "permission_id": permission.id,
                            "grantee": permission.granted_to_identities[0].display_name if hasattr(permission, 'granted_to_identities') and permission.granted_to_identities else "",
                            "roles": ",".join(permission.roles) if hasattr(permission, 'roles') else ""
                        })
                except Exception:
                    pass
            
            print(f"Found {len(self.m365_results['sharepoint_permissions'])} SharePoint permissions.")
            return self.m365_results["sharepoint_permissions"]
        except Exception as e:
            print(f"Error auditing SharePoint permissions: {str(e)}")
            return []

    async def audit_teams_permissions(self):
        """Audit Teams permissions."""
        try:
            print("Auditing Teams permissions...")
            
            # Get teams
            response = await self.graph_client.teams.get()
            teams = response.value if hasattr(response, 'value') else []
            
            for team in teams:
                try:
                    # Get team members
                    members_response = await self.graph_client.teams.by_team_id(team.id).members.get()
                    members = members_response.value if hasattr(members_response, 'value') else []
                    
                    for member in members:
                        self.m365_results["teams_permissions"].append({
                            "team_id": team.id,
                            "team_name": team.display_name,
                            "member_id": member.id,
                            "member_name": member.display_name if hasattr(member, 'display_name') else "",
                            "role": member.roles[0] if hasattr(member, 'roles') and member.roles else "Member"
                        })
                except Exception:
                    pass
            
            print(f"Found {len(self.m365_results['teams_permissions'])} Teams permissions.")
            return self.m365_results["teams_permissions"]
        except Exception as e:
            print(f"Error auditing Teams permissions: {str(e)}")
            return []

    async def audit_pim_assignments(self):
        """Audit Privileged Identity Management (PIM) assignments."""
        try:
            print("Auditing PIM assignments...")
            
            # Try different PIM API endpoints
            try:
                # First attempt: Direct role assignments
                response = await self.graph_client.directory.role_assignments.get()
                assignments = response.value if hasattr(response, 'value') else []
                
                if not assignments:
                    # Second attempt: Role eligibility schedules
                    response = await self.graph_client.role_management.directory.role_eligibility_schedules.get()
                    assignments = response.value if hasattr(response, 'value') else []
                    
                if not assignments:
                    # Third attempt: Role assignments via beta endpoint
                    response = await self.graph_client.directory.role_management.directory_roles.role_assignments.get()
                    assignments = response.value if hasattr(response, 'value') else []

            except Exception as api_error:
                print(f"Warning: Error accessing PIM API: {str(api_error)}")
                assignments = []

            for assignment in assignments:
                try:
                    # Extract assignment details with safe attribute access
                    assignment_data = {
                        "role_id": getattr(assignment, 'role_definition_id', ''),
                        "role_name": getattr(assignment, 'role_display_name', 
                                        getattr(assignment, 'role_definition_display_name', '')),
                        "principal_id": getattr(assignment, 'principal_id', ''),
                        "principal_name": getattr(assignment, 'principal_display_name', 
                                                getattr(assignment, 'principal_name', '')),
                        "status": getattr(assignment, 'status', 'Active'),
                        "assignment_type": getattr(assignment, 'assignment_type', 'Eligible'),
                        "start_datetime": None,
                        "end_datetime": None
                    }

                    # Handle datetime fields
                    if hasattr(assignment, 'start_datetime'):
                        assignment_data['start_datetime'] = assignment.start_datetime
                    elif hasattr(assignment, 'schedule_info') and hasattr(assignment.schedule_info, 'start_date_time'):
                        assignment_data['start_datetime'] = assignment.schedule_info.start_date_time

                    if hasattr(assignment, 'end_datetime'):
                        assignment_data['end_datetime'] = assignment.end_datetime
                    elif hasattr(assignment, 'schedule_info') and hasattr(assignment.schedule_info, 'end_date_time'):
                        assignment_data['end_datetime'] = assignment.schedule_info.end_date_time

                    # Convert datetime objects to naive datetime if they exist
                    if assignment_data['start_datetime']:
                        assignment_data['start_datetime'] = assignment_data['start_datetime'].replace(tzinfo=None)
                    if assignment_data['end_datetime']:
                        assignment_data['end_datetime'] = assignment_data['end_datetime'].replace(tzinfo=None)

                    self.m365_results["pim_assignments"].append(assignment_data)

                except Exception as e:
                    print(f"Warning: Failed to process PIM assignment: {str(e)}")
                    continue

            print(f"Found {len(self.m365_results['pim_assignments'])} PIM assignments.")
            return self.m365_results["pim_assignments"]

        except Exception as e:
            print(f"Error auditing PIM assignments: {str(e)}")
            return []

    async def audit_conditional_access(self):
        """Audit Conditional Access policies."""
        try:
            print("Auditing Conditional Access policies...")
            
            # Get Conditional Access policies
            response = await self.graph_client.identity.conditional_access.policies.get()
            policies = response.value if hasattr(response, 'value') else []
            
            for policy in policies:
                included_users = []
                excluded_users = []
                
                if hasattr(policy, 'conditions') and hasattr(policy.conditions, 'users'):
                    if hasattr(policy.conditions.users, 'include_users'):
                        included_users = policy.conditions.users.include_users
                    if hasattr(policy.conditions.users, 'exclude_users'):
                        excluded_users = policy.conditions.users.exclude_users
                
                self.m365_results["conditional_access"].append({
                    "policy_id": policy.id,
                    "display_name": policy.display_name,
                    "state": policy.state,
                    "included_users": ",".join(included_users),
                    "excluded_users": ",".join(excluded_users),
                    "created_datetime": policy.created_date_time if hasattr(policy, 'created_date_time') else "",
                    "modified_datetime": policy.modified_date_time if hasattr(policy, 'modified_date_time') else ""
                })
            
            print(f"Found {len(self.m365_results['conditional_access'])} Conditional Access policies.")
            return self.m365_results["conditional_access"]
        except Exception as e:
            print(f"Error auditing Conditional Access policies: {str(e)}")
            return []

    async def audit_application_permissions(self):
        """Audit application permissions."""
        try:
            print("Auditing application permissions...")
            
            # Get service principals
            response = await self.graph_client.service_principals.get()
            service_principals = response.value if hasattr(response, 'value') else []
            
            for sp in service_principals:
                try:
                    # Get app roles
                    roles_response = await self.graph_client.service_principals.by_service_principal_id(sp.id).app_role_assignments.get()
                    assignments = roles_response.value if hasattr(roles_response, 'value') else []
                    
                    for assignment in assignments:
                        self.m365_results["application_permissions"].append({
                            "app_id": sp.id,
                            "app_display_name": sp.display_name,
                            "principal_id": assignment.principal_id,
                            "resource_id": assignment.resource_id,
                            "app_role_id": assignment.app_role_id,
                            "created_datetime": assignment.created_date_time if hasattr(assignment, 'created_date_time') else ""
                        })
                except Exception:
                    pass
            
            print(f"Found {len(self.m365_results['application_permissions'])} application permissions.")
            return self.m365_results["application_permissions"]
        except Exception as e:
            print(f"Error auditing application permissions: {str(e)}")
            return []
    def generate_summary_report(self):
        """Generate a summary report of the audit findings."""
        self._print_section_header("Generating Audit Summary")

        # Create a rich table for the summary
        table = Table(title="Audit Results Summary", box=ROUNDED)
        table.add_column("Category", style="cyan")
        table.add_column("Count", justify="right", style="green")

        # Azure results
        table.add_row("Azure Subscriptions", str(len(self.azure_results["subscriptions"])))
        table.add_row("RBAC Assignments", str(len(self.azure_results["rbac_assignments"])))
        table.add_row("Custom Roles", str(len(self.azure_results["custom_roles"])))
        table.add_row("Resources", str(len(self.azure_results["resources"])))

        # M365 results
        table.add_row("M365 Admin Roles", str(len(self.m365_results["admin_roles"])))
        table.add_row("Exchange Permissions", str(len(self.m365_results["exchange_permissions"])))
        table.add_row("SharePoint Permissions", str(len(self.m365_results["sharepoint_permissions"])))
        table.add_row("Teams Permissions", str(len(self.m365_results["teams_permissions"])))
        table.add_row("PIM Assignments", str(len(self.m365_results["pim_assignments"])))
        table.add_row("Conditional Access Policies", str(len(self.m365_results["conditional_access"])))
        table.add_row("Application Permissions", str(len(self.m365_results["application_permissions"])))

        self.console.print(table)

        # Display security risks in a panel
        if security_risks := self._get_security_risks():
            risk_panel = Panel(
                "\n".join([f"• {risk['risk']}: {risk['details']}" for risk in security_risks]),
                title="[red]Security Risks Identified[/red]",
                style="red",
                box=ROUNDED
            )
            self.console.print(risk_panel)
        
        # Find highly privileged roles
        high_privilege_roles = []
        for assignment in self.azure_results["rbac_assignments"]:
            if assignment["role_name"] in ["Owner", "Contributor", "User Access Administrator", "Global Administrator"]:
                high_privilege_roles.append({
                    "subscription": assignment["subscription_name"],
                    "role": assignment["role_name"],
                    "principal": assignment.get("principal_name", assignment["principal_id"]),
                    "scope": assignment["scope"]
                })
        report["high_privilege_roles"] = high_privilege_roles
        
        # Find security risks
        security_risks = []
        
        # Check for users with owner/contributor rights
        owner_contributors = set()
        for assignment in self.azure_results["rbac_assignments"]:
            if assignment["role_name"] in ["Owner", "Contributor"] and assignment["principal_type"] == "User":
                owner_contributors.add(assignment.get("principal_name", assignment["principal_id"]))
        
        if owner_contributors:
            security_risks.append({
                "risk": "Users with Owner/Contributor rights",
                "details": f"Found {len(owner_contributors)} users with Owner/Contributor rights at subscription level"
            })
        
        # Check for applications with high privileges
        high_priv_apps = set()
        for permission in self.m365_results["application_permissions"]:
            app_name = permission["app_display_name"]
            if "Admin" in permission.get("app_role_id", ""):
                high_priv_apps.add(app_name)
        
        if high_priv_apps:
            security_risks.append({
                "risk": "Applications with admin permissions",
                "details": f"Found {len(high_priv_apps)} applications with administrative permissions"
            })
        
        report["security_risks"] = security_risks
        
        # Export to file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"privilege_audit_summary_{timestamp}.json")
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Summary report exported to {filename}")
        return report, filename
    
    def run_full_audit(self):
        """Run a full audit of Azure and M365 permissions."""
        print("\n=== Starting full privilege audit ===\n")
        
        # Create thread pool for parallel execution
        with ThreadPoolExecutor(max_workers=5) as executor:
            # Azure audits
            azure_futures = [
                executor.submit(self.audit_azure_subscriptions),
                executor.submit(self.audit_azure_rbac),
                executor.submit(self.audit_azure_custom_roles),
                executor.submit(self.audit_azure_resources)
            ]
            
            # M365 audits
            m365_futures = [
                executor.submit(self.audit_m365_admin_roles),
                executor.submit(self.audit_exchange_permissions),
                executor.submit(self.audit_sharepoint_permissions),
                executor.submit(self.audit_teams_permissions),
                executor.submit(self.audit_pim_assignments),
                executor.submit(self.audit_conditional_access),
                executor.submit(self.audit_application_permissions)
            ]
            
            # Wait for all Azure audits to complete
            for future in azure_futures:
                try:
                    future.result()
                except Exception as e:
                    print(f"An audit task failed: {str(e)}")
            
            # Wait for all M365 audits to complete
            for future in m365_futures:
                try:
                    future.result()
                except Exception as e:
                    print(f"An audit task failed: {str(e)}")
        
        # Enrich data after all audits
        self.enrich_principal_data()
        
        # Export results
        excel_file = self.export_to_excel()
        json_file = self.export_to_json()
        summary, summary_file = self.generate_summary_report()
        
        print("\n=== Audit completed ===")
        print(f"Excel report: {excel_file}")
        print(f"JSON report: {json_file}")
        print(f"Summary report: {summary_file}")
        
        return {
            "excel_report": excel_file,
            "json_report": json_file,
            "summary_report": summary_file,
            "summary": summary
        }


async def main_async():
    """Main async function for the Azure/M365 Privilege Audit Tool."""
    console = Console()
    
    # Get current time and user
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    current_user = os.getenv('USERNAME', 'Curious4Tech')
    
    # Display welcome banner
    console.print("\n")
    console.print(Panel(
        "[bold blue]Azure and Microsoft 365 Privilege Audit Tool[/bold blue]\n" +
        f"[cyan]Current Date and Time (UTC):[/cyan] {current_time}\n" +
        f"[cyan]Current User's Login:[/cyan] {current_user}",
        box=ROUNDED,
        expand=False,
        padding=(1, 2)
    ))

    # Argument parsing
    parser = argparse.ArgumentParser(description="Azure/M365 Privilege Audit Tool")
    parser.add_argument(
        "command",
        choices=["azure", "m365", "full"],
        help="Audit scope: azure, m365, or full audit"
    )
    parser.add_argument(
        "--output-dir",
        default="./audit_results",
        help="Output directory for audit results"
    )
    args = parser.parse_args()

    try:
        # Initialize environment and verify components
        with Progress(SpinnerColumn(), *Progress.get_default_columns()) as progress:
            init_task = progress.add_task("[cyan]Initializing environment...", total=5)
            
            # Step 1: Verify .env file
            env_path = Path('.') / '.env'
            console.print(f"Looking for .env file at: {env_path.absolute()}")
            console.print(f"File exists: {env_path.exists()}")
            if not env_path.exists():
                raise ValueError(f".env file not found at: {env_path.absolute()}")
            progress.update(init_task, advance=1)
            
            # Step 2: Load environment variables
            load_dotenv(dotenv_path=env_path)
            progress.update(init_task, advance=1)
            
            # Step 3: Verify credentials
            required_vars = ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET']
            missing_vars = [var for var in required_vars if not os.getenv(var)]
            if missing_vars:
                console.print(Panel(
                    "[bold red]Missing Required Environment Variables![/bold red]\n\n" +
                    "The following variables are missing:\n" +
                    "\n".join(f"[red]• {var}[/red]" for var in missing_vars) +
                    "\n\nPlease set these variables in your .env file or environment.",
                    title="[red]Configuration Error[/red]",
                    box=ROUNDED
                ))
                return 1
            progress.update(init_task, advance=1)
            
            # Step 4: Create output directory
            output_dir = Path(args.output_dir)
            output_dir.mkdir(exist_ok=True, parents=True)
            progress.update(init_task, advance=1)
            
            # Step 5: Display configuration
            config_table = Table(show_header=True, header_style="bold magenta", box=ROUNDED)
            config_table.add_column("Setting", style="cyan", justify="right")
            config_table.add_column("Value", style="green")
            config_table.add_row("Audit Type", f"[bold]{args.command.upper()}[/bold]")
            config_table.add_row("Output Directory", str(output_dir))
            config_table.add_row("Start Time (UTC)", current_time)
            config_table.add_row("Tenant ID", f"...{os.getenv('AZURE_TENANT_ID')[-4:]}")
            progress.update(init_task, advance=1)

        console.print("\n")
        console.print(config_table)
        console.print("\n")

        # Initialize audit tool with detailed status
        audit_tool = None
        with console.status("[cyan]Initializing authentication...[/cyan]") as status:
            try:
                audit_tool = AzureM365PrivilegeAudit(output_dir=args.output_dir)
                console.print("[green]✓[/green] Authentication initialized successfully")
            except Exception as e:
                console.print(Panel(
                    f"[bold red]Authentication Failed![/bold red]\n\n"
                    f"[red]Error:[/red] {str(e)}\n\n"
                    "[yellow]Troubleshooting Steps:[/yellow]\n"
                    "1. Verify your credentials in .env file\n"
                    "2. Check if the service principal has sufficient permissions\n"
                    "3. Ensure your tenant ID is correct\n"
                    "4. Verify network connectivity to Azure",
                    title="[red]Authentication Error[/red]",
                    box=ROUNDED
                ))
                return 1

        # Azure audit section
        if args.command in ["azure", "full"]:
            console.print(Panel("[bold blue]Starting Azure Audit[/bold blue]", box=ROUNDED))
            
            # Subscription validation
            try:
                with console.status("[cyan]Checking Azure subscriptions...[/cyan]") as status:
                    await audit_tool.audit_azure_subscriptions()
                    
                if not audit_tool.azure_results["subscriptions"]:
                    console.print(Panel(
                        "[bold yellow]Warning: No Azure subscriptions found![/bold yellow]\n\n"
                        "[yellow]Possible causes:[/yellow]\n"
                        "1. No subscriptions in the tenant\n"
                        "2. Insufficient permissions\n"
                        "3. Authentication issues\n\n"
                        "[cyan]Troubleshooting steps:[/cyan]\n"
                        "1. Verify the service principal has 'Reader' role at tenant root\n"
                        "2. Check subscription access in Azure Portal\n"
                        "3. Verify tenant ID matches your target environment\n"
                        "4. Ensure no subscription filters are active",
                        title="[yellow]Subscription Warning[/yellow]",
                        box=ROUNDED
                    ))
                    
                    if args.command == "azure":
                        console.print("\n[yellow]Cannot proceed with Azure audit without subscriptions.[/yellow]")
                        return 1
                    else:
                        console.print("\n[yellow]Proceeding with M365 audit only.[/yellow]")
                else:
                    console.print(f"[green]✓[/green] Found {len(audit_tool.azure_results['subscriptions'])} subscription(s)")
                    
                    # Display subscription info
                    sub_table = Table(show_header=True, header_style="bold magenta", box=ROUNDED)
                    sub_table.add_column("Subscription Name", style="cyan")
                    sub_table.add_column("Subscription ID", style="green")
                    sub_table.add_column("State", style="yellow")
                    
                    for sub in audit_tool.azure_results["subscriptions"]:
                        sub_table.add_row(
                            sub["name"],
                            f"...{sub['id'][-8:]}",
                            sub["state"]
                        )
                    console.print(sub_table)
                    console.print("")

                    # Proceed with detailed Azure audit
                    with Progress() as progress:
                        azure_task = progress.add_task("[cyan]Running Azure audit...", total=4)
                        
                        try:
                            # RBAC Assignments Audit
                            console.print("\n[cyan]Auditing RBAC assignments...[/cyan]")
                            await audit_tool.audit_azure_rbac()
                            progress.update(azure_task, advance=1)
                            console.print(f"[green]✓[/green] Found {len(audit_tool.azure_results['rbac_assignments'])} RBAC assignments")

                            # Custom Roles Audit
                            console.print("\n[cyan]Auditing custom roles...[/cyan]")
                            await audit_tool.audit_azure_custom_roles()
                            progress.update(azure_task, advance=1)
                            console.print(f"[green]✓[/green] Found {len(audit_tool.azure_results['custom_roles'])} custom roles")

                            # Resources Audit
                            console.print("\n[cyan]Auditing Azure resources...[/cyan]")
                            await audit_tool.audit_azure_resources()
                            progress.update(azure_task, advance=1)
                            console.print(f"[green]✓[/green] Found {len(audit_tool.azure_results['resources'])} resources")

                            # Principal Data Enrichment
                            console.print("\n[cyan]Enriching principal data...[/cyan]")
                            await audit_tool.enrich_principal_data()
                            progress.update(azure_task, advance=1)
                            console.print("[green]✓[/green] Principal data enrichment completed")

                            # Display Azure Audit Summary
                            azure_summary = Table(
                                title="Azure Audit Summary",
                                box=ROUNDED,
                                show_header=True,
                                header_style="bold magenta"
                            )
                            azure_summary.add_column("Category", style="cyan")
                            azure_summary.add_column("Count", style="green", justify="right")
                            azure_summary.add_column("Details", style="yellow")

                            # Add summary rows
                            azure_summary.add_row(
                                "Subscriptions",
                                str(len(audit_tool.azure_results["subscriptions"])),
                                "Accessible subscriptions found"
                            )
                            azure_summary.add_row(
                                "RBAC Assignments",
                                str(len(audit_tool.azure_results["rbac_assignments"])),
                                "Role assignments across subscriptions"
                            )
                            azure_summary.add_row(
                                "Custom Roles",
                                str(len(audit_tool.azure_results["custom_roles"])),
                                "Custom role definitions"
                            )
                            azure_summary.add_row(
                                "Resources",
                                str(len(audit_tool.azure_results["resources"])),
                                "Total Azure resources"
                            )

                            console.print("\n")
                            console.print(azure_summary)

                            # Security Analysis
                            high_privilege_roles = [
                                assignment for assignment in audit_tool.azure_results["rbac_assignments"]
                                if any(role in assignment.get("role", "").lower() 
                                      for role in ["owner", "contributor", "administrator"])
                            ]

                            if high_privilege_roles:
                                security_table = Table(
                                    title="[bold red]Security Alerts - High Privilege Assignments[/bold red]",
                                    box=ROUNDED
                                )
                                security_table.add_column("Role", style="red")
                                security_table.add_column("Assigned To", style="yellow")
                                security_table.add_column("Scope", style="cyan")

                                for role in high_privilege_roles[:5]:
                                    security_table.add_row(
                                        role.get("role", "Unknown"),
                                        role.get("name", role.get("principal_id", "Unknown")),
                                        role.get("scope", "Unknown")
                                    )

                                console.print("\n")
                                console.print(security_table)
                                
                                if len(high_privilege_roles) > 5:
                                    console.print(f"\n[yellow]... and {len(high_privilege_roles) - 5} more high-privilege assignments[/yellow]")

                            # Resource Distribution
                            resource_types = {}
                            for resource in audit_tool.azure_results.get("resources", []):
                                resource_type = resource.get("type", "Unknown")
                                resource_types[resource_type] = resource_types.get(resource_type, 0) + 1

                            if resource_types:
                                resource_table = Table(
                                    title="Resource Distribution",
                                    box=ROUNDED
                                )
                                resource_table.add_column("Resource Type", style="cyan")
                                resource_table.add_column("Count", style="green", justify="right")

                                for res_type, count in sorted(resource_types.items(), key=lambda x: x[1], reverse=True)[:10]:
                                    resource_table.add_row(res_type, str(count))

                                console.print("\n")
                                console.print(resource_table)

                        except Exception as e:
                            error_msg = str(e)
                            console.print(Panel(
                                f"[bold red]Azure Audit Error![/bold red]\n\n"
                                f"[red]Error:[/red] {error_msg}\n\n"
                                "[yellow]Troubleshooting Steps:[/yellow]\n"
                                "1. Verify service principal permissions\n"
                                "2. Check network connectivity\n"
                                "3. Ensure API access is not throttled\n"
                                "4. Verify resource provider registration\n\n"
                                "[cyan]Recommended Actions:[/cyan]\n"
                                "1. Check Azure Activity Log for related errors\n"
                                "2. Verify RBAC assignments for the service principal\n"
                                "3. Check for any Azure Policy restrictions",
                                title="[red]Error Details[/red]",
                                box=ROUNDED
                            ))
                            if args.command == "azure":
                                return 1

            except Exception as e:
                console.print(Panel(
                    f"[bold red]Azure Subscription Error![/bold red]\n\n"
                    f"[red]Error:[/red] {str(e)}\n\n"
                    "[yellow]Troubleshooting Steps:[/yellow]\n"
                    "1. Check network connectivity\n"
                    "2. Verify subscription access\n"
                    "3. Check service principal permissions",
                    title="[red]Azure Error[/red]",
                    box=ROUNDED
                ))
                if args.command == "azure":
                    return 1

        # M365 audit section
        if args.command in ["m365", "full"]:
            console.print(Panel("[bold blue]Starting Microsoft 365 Audit[/bold blue]", box=ROUNDED))
            with Progress() as progress:
                m365_task = progress.add_task("[cyan]Running M365 audit...", total=7)
                
                try:
                    await audit_tool.audit_m365_admin_roles()
                    progress.update(m365_task, advance=1)
                    
                    await audit_tool.audit_exchange_permissions()
                    progress.update(m365_task, advance=1)
                    
                    await audit_tool.audit_sharepoint_permissions()
                    progress.update(m365_task, advance=1)
                    
                    await audit_tool.audit_teams_permissions()
                    progress.update(m365_task, advance=1)
                    
                    await audit_tool.audit_pim_assignments()
                    progress.update(m365_task, advance=1)
                    
                    await audit_tool.audit_conditional_access()
                    progress.update(m365_task, advance=1)
                    
                    await audit_tool.audit_application_permissions()
                    progress.update(m365_task, advance=1)
                    
                    console.print("[green]✓[/green] M365 audit completed successfully")
                except Exception as e:
                    console.print(f"[red]✗[/red] Error during M365 audit: {str(e)}")
                    if args.command == "m365":
                        return 1

        # Export results
        with console.status("[green]Exporting results...[/green]") as status:
            try:
                excel_file = audit_tool.export_to_excel()
                json_file = audit_tool.export_to_json()
                
                console.print(Panel(
                    "[bold green]Audit Completed Successfully![/bold green]\n\n" +
                    f"[cyan]Excel Report:[/cyan] {excel_file}\n" +
                    f"[cyan]JSON Report:[/cyan] {json_file}\n\n" +
                    f"[white]Start Time (UTC):[/white] {current_time}\n" +
                    f"[white]End Time (UTC):[/white] {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
                    title="[bold green]Audit Summary[/bold green]",
                    box=ROUNDED
                ))
            except Exception as e:
                console.print(f"[red]✗[/red] Error exporting results: {str(e)}")
                return 1

        return 0

    except Exception as e:
        console.print(Panel(
            f"[bold red]Audit Failed![/bold red]\n\n"
            f"[red]Error Message:[/red] {str(e)}\n"
            f"[yellow]Time of Error (UTC):[/yellow] {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
            title="[red]Error Details[/red]",
            box=ROUNDED
        ))
        return 1
def main():
    return asyncio.run(main_async())

if __name__ == "__main__":
    exit(main())