How to collect data to Azure Sentinel using Syslog Server (RSyslog)
===================================================================

Table of Contents
=================

1. [Introduction](https://github.com/Welasco/AzureSentinelSyslog#1-introduction)
1. [What is Syslog?](https://github.com/Welasco/AzureSentinelSyslog#1-what-is-syslog)
1. [Setup Log Analytics agent on Linux (log forward)](https://github.com/Welasco/AzureSentinelSyslog#2-setup-log-analytics-agent-on-linux--log-forward)
1. [Setup RSyslog](https://github.com/Welasco/AzureSentinelSyslog#3-setup-rSyslog)
1. [Validate Configuration](https://github.com/Welasco/AzureSentinelSyslog#4-validate-configuration)
1. [Troubleshooting](https://github.com/Welasco/AzureSentinelSyslog#5-troubleshooting)

## 1. Introduction

Azure Sentinel can be connected via an agent to any other data source that can perform real-time log streaming using the Syslog protocol. 

Most appliances use the Syslog protocol to send event messages that include the log itself and data about the log. The format of the logs varies, but most appliances support CEF-based formatting for log data.

The Azure Sentinel agent, which is actually the Log Analytics agent, converts CEF-formatted logs into a format that can be ingested by Log Analytics. Depending on the appliance type, the agent is installed either directly on the appliance, or on a dedicated Linux-based log forwarder. The agent for Linux receives events from the Syslog daemon over UDP, but if a Linux machine is expected to collect a high volume of Syslog events, they are sent over TCP from the Syslog daemon to the agent and from there to Log Analytics.

Here is a diagram of how it works:

![Syslog OnPrem](media/cef-syslog-onprem.png)

## 2. What is Syslog?

Syslog stands for System Logging Protocol and is a standard protocol used to send system log or event messages to a specific server, called a syslog server. It is primarily used to collect various device logs from several different machines in a central location for monitoring and review.

Syslog is defined in RFC 5424, The Syslog Protocol, which obsoleted the previous RFC 3164:

 - [The Syslog Protocol - RFC5424](https://datatracker.ietf.org/doc/rfc5424/)
 - [The Syslog Protocol - **obsolete** RFC3164](https://datatracker.ietf.org/doc/rfc3164/)

Currently Syslog has two main implementations RSyslog and Syslog-NG.
 - Syslog-NG (1998)
 - RSyslog (2004)

This article will be based in RSyslog.

### Facility

In short, a facility level is used to determine the program or part of the system that produced the logs.
By default, some parts of your system are given facility levels such as the kernel using the kern facility, or your mailing system using the mail facility.
If a third-party wants to issue a log, it would probably a reserved set of facility levels from 16 to 23 called “local use” facility levels.
Alternatively, they can use the “user-level” facility, meaning that they would issue logs related to the user that issued the commands.

| **Facility Number** | **Keyword** | **Facility Description** |
| --- | --- | --- |
| 0 | kern | kernel messages |
| 1 | user | user-level messages |
| 2 | mail | mail system |
| 3 | daemon | system daemons |
| 4 | auth | security/authorization messages |
| 5 | syslog | messages generated internally by syslogd |
| 6 | lpr | line printer subsystem |
| 7 | news | network news subsystem |
| 8 | uucp | UUCP subsystem |
| 9 | cron | clock daemon |
| 10 | authpriv | security/authorization messages |
| 11 |  | FTP daemon |
| 12 |  | NTP subsystem |
| 13 |  | log audit |
| 14 |  | log alert |
| 15 |  | clock daemon (note 2) |
| 16 | local0 | local use 0  (local0) |
| 17 | local1 | local use 1  (local1) |
| 18 | local2 | local use 2  (local2) |
| 19 | local3 | local use 3  (local3) |
| 20 | local4 | local use 4  (local4) |
| 21 | local5 | local use 5  (local5) |
| 22 | local6 | local use 6  (local6) |
| 23 | local7 | local use 7  (local7) |

### Severity

The Severity is one of the following keywords, in ascending order: debug, info, notice, warning, warn
(same as warning), err, error (same as err), crit, alert, emerg, panic (same as emerg).

| **Numerical Code** | **Keyword** | **Severity Description** |
| --- | --- | --- |
| 0 | emerg | Emergency: system is unusable |
| 1 | alert | Alert: action must be taken immediately |
| 2 | crit | Critical: critical conditions |
| 3 | err | Error: error conditions |
| 4 | warning | Warning: warning conditions |
| 5 | notice | Notice: normal but significant condition |
| 6 | info | Informational: informational messages |
| 7 | debug | Debug: debug-level messages |

### Syslog message format

The two values are combined to produce a Priority Value sent with the message. The Priority Value is calculated by multiplying the Facility value by eight and then adding the Severity Value to the result. The lower the PRI, the higher the priority.

```
(Facility Value * 8) + Severity Value = PRI
```

In this way, a kernel message receives lower value (higher priority) than a log alert, regardless of the severity of the log alert. Additional identifiers in the packet include the hostname, IP address, process ID, app name, and timestamp of the message.
The actual verbiage or content of the syslog message is not defined by the protocol. Some messages are simple, readable text, others may only be machine readable.
```
Facility syslog (5), Severity alert (1)
Msg: 1 2021-04-19T15:00:22.303078+00:00 CentOSClient node 444969 123 [timeQuality tzKnown="1" isSynced="1" syncAccuracy="1513"] node test msg

<41>1.2021-04-19T15:00:22.303078+00:00.CentOSClient.node.444969.123.[timeQuality.tzKnown="1".isSynced="1".syncAccuracy="1513"].node.test.msg
```

| **Part** | **Value** | **Information** |
| --- | --- | --- |
PRI | 41 | (5*8)=40 Syslog, 1 = Alert |
VERSION | 1 | Version 1 |
TIMESTAMP | 2021-04-19T15:00:22.303078+00:00 | Message created on Apr, 19, 2021 at 15:00:22, 3 milliseconds into the next second |
HOSTNAME | CentOSClient | Message originated from host 'CentOSClient' |
APP-NAME | node | App Name: node |
PROCID | 444969 | Process ID: 444969 |
MSGID | 123 | Message-ID: 123 |
STRUCTURED-DATA | [timeQuality tzKnown="1" isSynced="1" syncAccuracy="1513"] | Structured Data Element with a non-IANA controlled with 3 parameters timeQuality.tzKnown="1" isSynced="1" syncAccuracy="1513" |
MSG | node test msg | Log message: node test msg |

## 3. What is Log Analytics Agent

Azure Log Analytics relies on agents to collect data to a Log Analytics Workspace. Azure Sentinel will use the data in a Log Analytics workspace to work with.

The Azure Sentinel agent, which is actually the Log Analytics agent, converts CEF-formatted logs into a format that can be ingested by Log Analytics. The data can also be a regular Syslog message format.

There are many ways in how you can install Log Analytics Agent:

- **Azure Portal**
    - You can install (connect) from a Log Analytics Workspace to an Azure VM using using connect option:
    ![Install from Workspace](media/install-from-workspace.png)
    - You can setup Azure Security Center to set a default Workspace to install the agent in all VMs in a subscription:
    ![Install from Security Center](media/install-from-security-center.png)
    - You can deploy at scale using Azure Policy:
    [Deploy Azure Monitor at scale using Azure Policy](https://docs.microsoft.com/en-us/azure/azure-monitor/deploy-scale#log-analytics-agent)
    - All those options will use a Azure VM Extension to install and setup the agent:
    ![VM Extension](media/vm-extension.png)
- **Manual instalation**
    - Install the agent using wrapper script:
    
        To configure the Linux computer to connect to a Log Analytics workspace, run the following command providing the workspace ID and primary key. The following command downloads the agent, validates its checksum, and installs it.
        ```
        wget https://raw.githubusercontent.com/Microsoft/OMS-Agent-for-Linux/master/installer/scripts/onboard_agent.sh && sh onboard_agent.sh -w <YOUR WORKSPACE ID> -s <YOUR WORKSPACE PRIMARY KEY>
        ```

        The following command includes the `-p` proxy parameter and example syntax when authentication is required by your proxy server:

        ```
        wget https://raw.githubusercontent.com/Microsoft/OMS-Agent-for-Linux/master/installer/scripts/onboard_agent.sh && sh onboard_agent.sh -p [protocol://]<proxy user>:<proxy password>@<proxyhost>[:port] -w <YOUR WORKSPACE ID> -s <YOUR WORKSPACE PRIMARY KEY>
        ```
        Reference: [Install the agent using wrapper script](https://docs.microsoft.com/en-us/azure/azure-monitor/agents/agent-linux#install-the-agent-using-wrapper-script)

    - Install the agent manually

        The Log Analytics agent for Linux is provided in a self-extracting and installable shell script bundle. This bundle contains Debian and RPM packages for each of the agent components and can be installed directly or extracted to retrieve the individual packages. One bundle is provided for x64 and one for x86 architectures. 

        > **Note:** For Azure VMs, we recommend you install the agent on them using the [Azure Log Analytics VM extension](https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/oms-linux) for Linux. 

        1. [Download](https://github.com/microsoft/OMS-Agent-for-Linux#azure-install-guide) and transfer the appropriate bundle (x64 or x86) to your Linux VM or physical computer, using scp/sftp.

        2. Install the bundle by using the `--install` argument. To onboard to a Log Analytics workspace during installation, provide the `-w <WorkspaceID>` and `-s <workspaceKey>` parameters copied earlier.

            >**Note:** You need to use the `--upgrade` argument if any dependent packages such as omi, scx, omsconfig or their older versions are installed, as would be the case if the system Center Operations Manager agent for Linux is already installed. 

            ```
            sudo sh ./omsagent-*.universal.x64.sh --install -w <workspace id> -s <shared key>
            ```

        3. To configure the Linux agent to install and connect to a Log Analytics workspace through a Log Analytics gateway, run the following command providing the proxy, workspace ID, and workspace key parameters. This configuration can be specified on the command line by including `-p [protocol://][user:password@]proxyhost[:port]`. The *proxyhost* property accepts a fully qualified domain name or IP address of the Log Analytics gateway server.  

            ```
            sudo sh ./omsagent-*.universal.x64.sh --upgrade -p https://<proxy address>:<proxy port> -w <workspace id> -s <shared key>
            ```

            If authentication is required, you need to specify the username and password. For example: 
            
            ```
            sudo sh ./omsagent-*.universal.x64.sh --upgrade -p https://<proxy user>:<proxy password>@<proxy address>:<proxy port> -w <workspace id> -s <shared key>
            ```

        4. To configure the Linux computer to connect to a Log Analytics workspace in Azure Government cloud, run the following command providing the workspace ID and primary key copied earlier.

            ```
            sudo sh ./omsagent-*.universal.x64.sh --upgrade -w <workspace id> -s <shared key> -d opinsights.azure.us
            ```

        If you want to install the agent packages and configure it to report to a specific Log Analytics workspace at a later time, run the following command:

        ```
        sudo sh ./omsagent-*.universal.x64.sh --upgrade
        ```

        If you want to extract the agent packages from the bundle without installing the agent, run the following command:

        ```
        sudo sh ./omsagent-*.universal.x64.sh --extract
        ```
        Reference: [Install the agent manually](https://docs.microsoft.com/en-us/azure/azure-monitor/agents/agent-linux#install-the-agent-manually)

## 4. Setup Log Analytics agent on Linux (log forward)

By default Log Analytics agent will collect any syslog message and inject in the Log analytics workspace. 

## 5. Setup RSyslog

## 6. Validate Configuration

## 7. Troubleshooting

