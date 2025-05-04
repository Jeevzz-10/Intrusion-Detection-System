<h1>DoS Attack Detection using Python (IDS)</h1>

<p>This project simulates a basic Denial of Service (DoS) attack and demonstrates how an Intrusion Detection System (IDS) can detect abnormal SYN flood traffic using raw sockets in Python.</p>

<h2>Project Structure</h2>
<ul>
  <li><b>DoS_server.py</b> – Runs the IDS (Intrusion Detection System) that monitors incoming TCP packets and detects SYN flood patterns.</li>
  <li><b>DoS_attack_host.py</b> – Simulates a DoS attack by sending a large number of SYN packets to a target.</li>
  <li><b>README.md</b> – Project explanation and usage instructions.</li>
</ul>

<h2>How It Works</h2>
<ul>
  <li>The attacker script (<code>DoS_attack_host.py</code>) sends multiple fake TCP SYN packets to the victim.</li>
  <li>The server script (<code>DoS_server.py</code>) captures TCP packets in real time using raw sockets.</li>
  <li>If the IDS detects unusually high SYN requests from the same IP, it flags it as a potential SYN flood attack.</li>
</ul>

<h2>Requirements</h2>
<ul>
  <li>Python 3.x</li>
  <li>Admin/root privileges (required for raw socket access)</li>
  <li><code>colorama</code> library (for colored alerts in terminal)</li>
</ul>

<p><b>Install required Python package:</b></p>
<pre><code>pip install colorama</code></pre>

<h2>Usage</h2>
<ol>
  <li>
    <b>Start IDS server:</b><br>
    <code>sudo python DoS_server.py</code><br>
    Provide how many TCP packets to capture when prompted.
  </li>
  <li>
    <b>Start attacker script from another system or VM:</b><br>
    <code>python DoS_attack_host.py</code><br>
    Enter:
    <ul>
      <li>Target IP (victim's IP)</li>
      <li>Target port (e.g., 80)</li>
      <li>Number of packets to send (e.g., 100)</li>
    </ul>
  </li>
</ol>

<h2>Example Output</h2>
<pre>
[*] IDS Initialized - Capturing only TCP packets
[*] Waiting to capture 50 TCP packets...

#1: 192.168.0.105:42424 → 192.168.0.106:80 [SYN]
#2: 192.168.0.105:42535 → 192.168.0.106:80 [SYN]
...

[ALERT] High SYN rate detected from 192.168.0.105! Possible SYN flood attack.

--- IDS TCP Packet Analysis Summary ---

IP: 192.168.0.105 (hostname.local)
    ↳ Total TCP Packets: 50
    ↳ Unique Ports Contacted: 1
    ↳ SYN Packets: 50
      CRITICAL (Definite SYN flood or attack!)

[*] Capture completed in 12.30 seconds.
</pre>

<h2>What You Learn</h2>
<ul>
  <li>Working with raw sockets in Python</li>
  <li>Understanding TCP/IP headers</li>
  <li>Building a basic packet sniffer</li>
  <li>Detecting SYN flood DoS attacks</li>
  <li>Using <code>struct</code> for binary data parsing</li>
</ul>

<h2>Disclaimer</h2>
<p>This project is for <b>educational purposes only</b>. Do not use this code to attack any system without explicit permission.</p>
