# Global Secure Access Troubleshooting Tool (GSATool)

## Overview 
Troubleshooting Global Secure Access can be challenging due to its multiple components, often requiring significant time, effort and local admin permissions. However, with the Global Secure Access Troubleshooting Tool (GSATool), diagnosing and resolving issues has never been easier. The GSATool PowerShell is a comprehensive tool that performs over 50 different tests to help identify and resolve the most common Global Secure Access issues across all components, including Microsoft Entra Private Access, Microsoft Entra Internet Access, and Microsoft Entra Internet Access for Microsoft Services. By leveraging GSATool, organizations can significantly reduce troubleshooting time, enhance operational efficiency. 

## Prerequisites 
You can run GSATool as a standard user without requiring the installation of any PowerShell modules. However, to validate the GSA cloud service configuration, you need to use an account with both NetworkAccess.Read.All and Application.Read.All permissions.

## Running the tool 
Download and run the GSATool.ps1 script from [this](https://github.com/mzmaili/GSATool/archive/refs/heads/main.zip) Github repo

## Submit feedback 
You can submit feedback, suggestions, or comments at https://aka.ms/GSAToolFeedback.  

## What assessments does GSATool conduct? 

> [!NOTE] 
> Note: The current version includes Entra Private Access tests. Other tests will be included in the next version. 

### Troubleshoot Entra Private Access
- Checking GSA client services 
  - Tunneling Service 
  - Management Service 
  - Policy Retrieval Service 
  - GSA Driver Service
- Checking Private Access registry key settings 
  - Testing PA enablement 
- Checking if the device is connected to Entra ID 
- Checking Private Access Profile 
  - Testing if Forwarding profile key exists 
  - Testing if forwarding profile key value is not empty 
  - Private forwarding profile configuration has retrieved 
- Checking connectivity to Private Access Edge 
  - Testing connection to the primary Private Access Edge 
  - If failed, testing connection to the secondary Private Access Edge 
- Checking connectivity to Private Access health endpoint 
- Checking GSA client forwarding profile configuration 
  - Testing if there is rule configured and retrieved for the provided FQDNorIP, port, protocol. If exists, the tool shows the configured Rule ID, App ID 
- Checking Global Secure Access Activation Status 
- Checking Private forwarding profile enablement 
- Checking user assignments to Private Access forwarding profile 
  - Testing if assignment required for Private Access forwarding profile 
  - If so, testing if user is assigned directly to Private Access forwarding profile 
  - If not, test if user is a member of a group assigned to Private Access forwarding profile 
- Checking Private Access Application configuration 
  - Testing the access with Global Secure Access client is enabled 
  - Testing if Private Access application is enabled 
  - Testing if assignment required for Private Access application 
  - If so, testing if user is assigned directly to Private Access application 
  - If not, testing if user is a member of a group assigned to Private Access application 
- Checking tunnel establishing 
  - Testing if connection has established to SSE edge with the provided port and protocol. If so, the tool retrieves syntactic address. 
  - Testing the internal DNS record for the target resource. If found, the tool retrieves internal addresses. 
