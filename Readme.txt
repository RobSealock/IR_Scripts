Incident Response Scripts to use for:

A. Baseline analysis of a system - See Readme.pdf
    Windows 11 baseline (hyperv): Win11_10.0.26200_7840.json
    Windows Server 2025 baseline (hyperv): Server2025_10.0.26100_32230.json
Files Required:
Generate-OSBaseline.ps1
WinHostBaseline.Collectors.psm1
WinHostBaseline.ps1
WinHostBaselineCore.psm1

B. Browser Extension Lookup - scans and resolves chrome and edge extensions
BrowserExtenstion-Scan-Resolve.ps1
OfflineBrowserExtenstion-Scan-Resolve.ps1

C. Get-DomainLogons.ps1 - Consulidates accross DCs logons

D. LocalLogons.ps1 - logons on the local machine

E. Account Failures - Test script, DC logs and local log review 
AuthEventParser.psm1
AuthExport.psm1
AuthHeuristics.psm1
DC-FailedLogons-Report.ps1
Local-FailedLogons-Report.ps1
Test-DCLogAccess.ps1

F. Invoke-IRLocalTriage.ps1 - start of LoTL scanning script (work in progress)

G. Invoke-SysinternalsIR.ps1 - uses the Sysinternal Tools for capture 


External IR Tools
https://docs.velociraptor.app/downloads/
    Velociraptor is an advanced digital forensic and incident response tool that enhances your visibility into your endpoints.
#
https://www.kroll.com/en/services/cyber/incident-response-recovery/kroll-artifact-parser-and-extractor-kape
https://tryhackme.com/room/kape
https://medium.com/@jcm3/kape-tryhackme-walkthrough-800b4c9175e6
#
https://github.com/Gerenios/AADInternals
#
Sysinternals TCPView
Sysinternals Autoruns


