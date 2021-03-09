How to collect data to Azure Sentinel using Syslog Server (RSyslog)
===================================================================

Table of Contents
=================

1. [Introduction](https://github.com/Welasco/AzureSentinelSyslog#1-introduction)
2. [Setup Log Analytics agent on Linux (log forward)](https://github.com/Welasco/AzureSentinelSyslog#2-setup-log-analytics-agent-on-linux--log-forward)
3. [Setup RSyslog](https://github.com/Welasco/AzureSentinelSyslog#3-setup-rSyslog)
4. [Validate Configuration](https://github.com/Welasco/AzureSentinelSyslog#4-validate-configuration)
5. [Troubleshooting](https://github.com/Welasco/AzureSentinelSyslog#5-troubleshooting)

## 1. Introduction

Azure Sentinel can be connected via an agent to any other data source that can perform real-time log streaming using the Syslog protocol. 

Most appliances use the Syslog protocol to send event messages that include the log itself and data about the log. The format of the logs varies, but most appliances support CEF-based formatting for log data.

The Azure Sentinel agent, which is actually the Log Analytics agent, converts CEF-formatted logs into a format that can be ingested by Log Analytics. Depending on the appliance type, the agent is installed either directly on the appliance, or on a dedicated Linux-based log forwarder. The agent for Linux receives events from the Syslog daemon over UDP, but if a Linux machine is expected to collect a high volume of Syslog events, they are sent over TCP from the Syslog daemon to the agent and from there to Log Analytics.

Here is a diagram of how it works:

![Syslog OnPrem](media/cef-syslog-onprem.png)

## 2. Setup Log Analytics agent on Linux (log forward)



## 3. Setup RSyslog

## 4. Validate Configuration

## 5. Troubleshooting

