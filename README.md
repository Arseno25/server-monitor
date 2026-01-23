<div align="center">

# Server Process Monitoring MCP Server
### Forensic Investigator for Silent Server Failures

<p align="center">
  <img src="https://img.shields.io/badge/Status-Stable-green?style=flat-square" alt="Status" />
  <img src="https://img.shields.io/badge/Platform-Linux%20Server-blue?style=flat-square" alt="Platform" />
  <img src="https://img.shields.io/badge/Python-3.10+-yellow?style=flat-square" alt="Python" />
  <img src="https://img.shields.io/badge/License-MIT-orange?style=flat-square" alt="License" />
</p>

<p>
  A specialized Model Context Protocol (MCP) server designed to diagnose "silent failures" on Linux servers. 
  It digs deeper than standard logs to find zombie processes, resource leaks, and hidden Docker issues.
</p>

</div>

<br>

## ✨ Forensic Capabilities

<table width="100%">
  <thead>
    <tr>
      <th width="25%">Tool</th>
      <th width="75%">Diagnosis Capability</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>scan_process_anomalies</code></td>
      <td>
        <strong>Detects Deadlocks & Zombies</strong><br>
        Identifies processes stuck in <code>Disk Sleep (D)</code> or <code>Zombie (Z)</code> state that cause hidden system hangs without high CPU usage.
      </td>
    </tr>
    <tr>
      <td><code>deep_docker_inspect</code></td>
      <td>
        <strong>Container Forensics</strong><br>
        Deep dive into Docker containers to find <code>OOMKilled</code> events, silent restarts, failing health checks, and storage corruption.
      </td>
    </tr>
    <tr>
      <td><code>check_resource_leaks</code></td>
      <td>
        <strong>Resource Exhaustion Hunter</strong><br>
        Detects File Descriptor (FD) exhaustion and connection leaks (e.g., high <code>CLOSE_WAIT</code> or <code>TIME_WAIT</code>) that paralyze servers.
      </td>
    </tr>
    <tr>
      <td><code>read_kernel_ring_buffer</code></td>
      <td>
        <strong>Kernel-Level Errors</strong><br>
        Reads <code>dmesg</code> to catch critical events like Out-Of-Memory (OOM) kills, segfaults, and hardware errors often missed by app logs.
      </td>
    </tr>
    <tr>
      <td><code>analyze_background_tasks</code></td>
      <td>
        <strong>Hidden Resource Hogs</strong><br>
        Uncovers non-root background processes that are silently consuming CPU or Memory resources.
      </td>
    </tr>
    <tr>
      <td><code>kill_process</code></td>
      <td>
        <strong>Remediation Action</strong><br>
        Terminates stuck, zombie, or runaway processes. Includes safety checks to prevent killing critical system processes.
      </td>
    </tr>
    <tr>
      <td><code>restart_container</code></td>
      <td>
        <strong>Container Recovery</strong><br>
        Restarts malfunctioning Docker containers to quickly recover from stuck states or health check failures.
      </td>
    </tr>
  </tbody>
</table>

<br>

## 🚀 Quick Setup (Linux Server)

Run this simple command on your Server to set up everything automatically:

```bash
curl -sSL https://raw.githubusercontent.com/Arseno25/server-monitor/main/install.sh | bash
```

<details>
<summary><strong>Or Manual Installation</strong></summary>

```bash
# Clone and install
git clone https://github.com/Arseno25/server-monitor.git
cd Server-process-monitoring
chmod +x install.sh
./install.sh
```
</details>

<br>

## 🔌 Client Configuration

Connect your MCP client to your Server securely via SSH.

### Claude Desktop & Cursor
Add the following configuration to your MCP config file (`claude_desktop_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "Server-forensics": {
      "command": "ssh",
      "args": [
        "-i",
        "/path/to/your/private-key.pem",
        "user@your-Server-ip",
        "python",
        "/opt/Server-process-monitoring/server.py"
      ]
    }
  }
}
```

> 💡 **Note:** Replace `/path/to/your/private-key.pem` with your local SSH key path, and update the user/IP accordingly.

### 🤖 AI Agents & Chatbots

If you are building a custom AI Agent or Chatbot (using LangChain, CrewAI, etc.), you can use the same SSH tunneling method. Configure your MCP Client to execute the remote server command via SSH:

```python
# Example for a Python-based Agent
server_params = StdioServerParameters(
    command="ssh",
    args=[
        "-i", "/path/to/private-key.pem",
        "user@your-Server-ip", 
        "python", "/opt/Server-process-monitoring/server.py"
    ]
)
```

<br>

<br>
<div align="center">
  <sub>Built with ❤️ using <strong>Model Context Protocol</strong></sub>
</div>
