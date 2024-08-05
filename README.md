# Zabbix-APP-Windows Defender

## Overview

Collect selected events for Windows Defender and receives values with wmi. 


## Items collected
	
Name | Triggers | Key | Interval | History | Trends | Type | Status | Tags
Anti Spyware Protection Enabled	Triggers 1 
wmi.get["root\microsoft\windows\defender","select AntispywareEnabled from MSFT_MpComputerStatus"]
	1h	31d		Zabbix agent (active)	
Enabled
	Application: Features
	
Anti Spyware Signature Age	Triggers 1	
wmi.get["root\microsoft\windows\defender","select AntispywareSignatureAge from MSFT_MpComputerStatus"]
	3h	31d	365d	Zabbix agent (active)	
Enabled
	Application: Scan Ages
	
Anti Spyware Signature Last updated		
wmi.get["root\microsoft\windows\defender","select AntispywareSignatureLastUpdated from MSFT_MpComputerStatus"]
	3h	31d		Zabbix agent (active)	
Enabled
	Application: Scan Ages
	
Antivirus Enabled	Triggers 1	
wmi.get["root\microsoft\windows\defender","select AntivirusEnabled from MSFT_MpComputerStatus"]
	1h	31d		Zabbix agent (active)	
Enabled
	Application: Features
	
Antivirus Signature Age	Triggers 1	
wmi.get["root\microsoft\windows\defender","select AntivirusSignatureAge from MSFT_MpComputerStatus"]
	3h	31d	365d	Zabbix agent (active)	
Enabled
	Application: Scan Ages
	
Antivirus Signature Last updated		
wmi.get["root\microsoft\windows\defender","select AntivirusSignatureLastUpdated from MSFT_MpComputerStatus"]
	3h	31d		Zabbix agent (active)	
Enabled
	Application: Scan Ages
	
Behavior Monitor Enabled	Triggers 1	
wmi.get["root\microsoft\windows\defender","select BehaviorMonitorEnabled from MSFT_MpComputerStatus"]
	1h	31d		Zabbix agent (active)	
Enabled
	Application: Features
	
Current computer state	Triggers 1	
wmi.get["root\microsoft\windows\defender","select ComputerState from MSFT_MpComputerStatus"]
	10m	31d	365d	Zabbix agent (active)	
Enabled
	Application: Computer State
	
Full Scan Age	Triggers 1	
wmi.get["root\microsoft\windows\defender","select FullScanAge from MSFT_MpComputerStatus"]
	3h	31d	365d	Zabbix agent (active)	
Enabled
	Application: Scan Ages
	
Ioav Protection Enabled	Triggers 1	
wmi.get["root\microsoft\windows\defender","select IoavProtectionEnabled from MSFT_MpComputerStatus"]
	1h	31d		Zabbix agent (active)	
Enabled
	Application: Features
	
MALWAREPROTECTION_BEHAVIOR_DETECTED	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1015,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_FOLDER_GUARD_SECTOR_BLOCK	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1127,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_MALWARE_ACTION_FAILED	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1008,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_MALWARE_ACTION_TAKEN	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1007,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_MALWARE_DETECTED	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1006,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_SCAN_CANCELLED	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1002,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_SCAN_FAILED	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1005,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_SCAN_PAUSED	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1003,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_SCAN_RESUMED	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1004,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_STATE_MALWARE_ACTION_CRITICALLY_FAILED	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1119,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_STATE_MALWARE_ACTION_FAILED	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1118,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_STATE_MALWARE_ACTION_TAKEN	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1117,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
MALWAREPROTECTION_STATE_MALWARE_DETECTED	Triggers 1	
eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1116,,skip]
	5m	31d		Zabbix agent (active)	
Enabled
	Application: Windows Defender
	
NIIS Signature Age	Triggers 1	
wmi.get["root\microsoft\windows\defender","select NISSignatureAge from MSFT_MpComputerStatus"]
	3h	31d	365d	Zabbix agent (active)	
Enabled
	Application: Scan Ages
	
NIS Protection Enabled	Triggers 1	
wmi.get["root\microsoft\windows\defender","select NISEnabled from MSFT_MpComputerStatus"]
	1h	31d		Zabbix agent (active)	
Enabled
	Application: Features
	
NIS Signature Last updated		
wmi.get["root\microsoft\windows\defender","select NISSignatureLastUpdated from MSFT_MpComputerStatus"]
	3h	31d		Zabbix agent (active)	
Enabled
	Application: Scan Ages
	
OnAccess Protection Enabled	Triggers 1	
wmi.get["root\microsoft\windows\defender","select OnAccessProtectionEnabled from MSFT_MpComputerStatus"]
	1h	31d		Zabbix agent (active)	
Enabled
	Application: Features
	
Quick Scan Age	Triggers 1	
wmi.get["root\microsoft\windows\defender","select QuickScanAge from MSFT_MpComputerStatus"]
	3h	31d	365d	Zabbix agent (active)	
Enabled
	Application: Scan Ages
	
Real Time Protection Enabled	Triggers 1	
wmi.get["root\microsoft\windows\defender","select RealTimeProtectionEnabled from MSFT_MpComputerStatus"]
	1h	31d		Zabbix agent (active)	
Enabled
	Application: Features

## Triggers

Severity
	
Name
	Operational data	Expression	
Status
	Tags
	Warning	An antimalware scan failed on {HOST.HOST}		
logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1005,,skip],,1005)<>0
	
Enabled
	
	Warning	An antimalware scan was paused on {HOST.HOST}		
Problem: logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1003,,skip],,1003)=1
Recovery: logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1004,,skip],,1004)=1
	
Enabled
	
	Warning	An antimalware scan was stopped before it finished on {HOST.HOST}		
logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1002,,skip],,1002)<>0
	
Enabled
	
	Warning	Anti Spyware Disabled on {HOST.HOST}		
find(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select AntispywareEnabled from MSFT_MpComputerStatus"],,"like","True")<>1
	
Enabled
	
	High	Anti Spyware Signature was not updated for more then 5 days on {HOST.HOST}		
last(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select AntispywareSignatureAge from MSFT_MpComputerStatus"])>5
	
Enabled
	
	Warning	Anti Virus Disabled on {HOST.HOST}		
find(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select AntivirusEnabled from MSFT_MpComputerStatus"],,"like","True")<>1
	
Enabled
	
	High	Anti Virus Signature was not updated for more then 5 days on {HOST.HOST}		
last(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select AntivirusSignatureAge from MSFT_MpComputerStatus"])>5
	
Enabled
	
	Warning	Behavior Monitor Disabled on {HOST.HOST}		
find(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select BehaviorMonitorEnabled from MSFT_MpComputerStatus"],,"like","True")<>1
	
Enabled
	
	High	Controlled Folder Access(CFA) blocked an untrusted process from making changes to the memory on {HOST.HOST}		
logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1127,,skip],,1127)<>0
	
Enabled
	
	Average	Full Scan was not performed for more then 5 days on {HOST.HOST}		
last(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select FullScanAge from MSFT_MpComputerStatus"])>5
	
Enabled
	
	Warning	Ioav Protection Disabled on {HOST.HOST}		
find(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select IoavProtectionEnabled from MSFT_MpComputerStatus"],,"like","True")<>1
	
Enabled
	
	High	NIIS Signature was not updated for more then 5 days on {HOST.HOST}		
last(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select NISSignatureAge from MSFT_MpComputerStatus"])>5
	
Enabled
	
	Warning	NIS Protection Disabled on {HOST.HOST}		
find(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select NISEnabled from MSFT_MpComputerStatus"],,"like","True")<>1
	
Enabled
	
	Warning	OnAccess Protection Disabled on {HOST.HOST}		
find(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select OnAccessProtectionEnabled from MSFT_MpComputerStatus"],,"like","True")<>1
	
Enabled
	
	Average	Quick Scan was not performed for more then 3 days on {HOST.HOST}		
last(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select QuickScanAge from MSFT_MpComputerStatus"])>3
	
Enabled
	
	Warning	Real Time Protection Disabled on {HOST.HOST}		
find(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select RealTimeProtectionEnabled from MSFT_MpComputerStatus"],,"like","True")<>1
	
Enabled
	
	High	The antimalware engine found malware or other potentially unwanted software on {HOST.HOST}		
logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1006,,skip],,1006)<>0 or logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1116,,skip],,1116)<>0
	
Enabled
	
	Disaster	The antimalware platform attempted to perform an action to protect your system from malware or other potentially unwanted software, but the action failed on {HOST.HOST}		
logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1008,,skip],,1008)<>0 or logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1118,,skip],,1118)<>0
	
Enabled
	
	High	The antimalware platform detected suspicious behavior on {HOST.HOST}		
logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1015,,skip],,1015)<>0
	
Enabled
	
	Disaster	The antimalware platform encountered a critical error when trying to take action on malware or other potentially unwanted software on {HOST.HOST}		
logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1119,,skip],,1119)<>0
	
Enabled
	
	High	The antimalware platform performed an action to protect your system from malware or other potentially unwanted software on {HOST.HOST}		
logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1007,,skip],,1007)<>0 or logeventid(/APP-Windows Defender by Zabbix Agent 2 active/eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1117,,skip],,1117)<>0
	
Enabled
	
	High	Windows Defender has failed critically on {HOST.HOST}		
last(/APP-Windows Defender by Zabbix Agent 2 active/wmi.get["root\microsoft\windows\defender","select ComputerState from MSFT_MpComputerStatus"])=16
	
Enabled

## Dashboard

There is also a dashboard with the following Honeycomb "Topics"
- Age of Signature Updates
- Protection Status
- Age of Windows Defender Scan
	
