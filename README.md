# Zabbix-APP-Windows Defender

## Overview

Collect selected events for Windows Defender and receives values with wmi. 


## Features

#### State of Service
- Anti Spyware Protection
- Antivirus
- Behaviour Monitor
- Windows Defender itself
- Ioav Protection
- NIIS Protection
- OnAccess Protection
- Real Time Protection

#### Age and Date of last Signature Update
- Anti Spyware
- Antivirus
- NIIS

#### Age of last Antivirus Scan
- Full Scan
- Quick Scan

#### Various Events monitored in the Event Viewer
Name | Key
MALWAREPROTECTION_BEHAVIOR_DETECTED | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1015,,skip]
MALWAREPROTECTION_FOLDER_GUARD_SECTOR_BLOCK | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1127,,skip]
MALWAREPROTECTION_MALWARE_ACTION_FAILED | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1008,,skip]
MALWAREPROTECTION_MALWARE_ACTION_TAKEN | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1007,,skip]
MALWAREPROTECTION_MALWARE_DETECTED | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1006,,skip]
MALWAREPROTECTION_SCAN_CANCELLED | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1002,,skip]
MALWAREPROTECTION_SCAN_FAILED | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1005,,skip]
MALWAREPROTECTION_SCAN_PAUSED | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1003,,skip]
MALWAREPROTECTION_SCAN_RESUMED | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1004,,skip]
MALWAREPROTECTION_STATE_MALWARE_ACTION_CRITICALLY_FAILED | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1119,,skip]
MALWAREPROTECTION_STATE_MALWARE_ACTION_FAILED | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1118,,skip]
MALWAREPROTECTION_STATE_MALWARE_ACTION_TAKEN | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1117,,skip]
MALWAREPROTECTION_STATE_MALWARE_DETECTED | eventlog[Microsoft-Windows-Windows Defender/Operational,,,,1116,,skip]

## Dashboard

There is also a dashboard with the following Honeycomb "Topics"
- Age of Signature Updates
- Protection Status
- Age of Windows Defender Scan
	
