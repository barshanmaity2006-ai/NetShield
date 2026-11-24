
import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox

PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    27017: "MongoDB",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch"
}

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def start_scan():
    ip = ip_entry.get().strip()

    try:
        socket.inet_aton(ip)
    except socket.error:
        messagebox.showerror("Error", "Enter a valid IPv4 address")
        return

    scan_button.config(state="disabled")
    result_table.delete(*result_table.get_children())
    status_label.config(text="Scanning...")

    threading.Thread(
        target=scan_network,
        args=(ip,),
        daemon=True
    ).start()

def scan_network(ip):
    found = []

    for port, service in PORTS.items():
        if scan_port(ip, port):
            found.append((port, service, "OPEN"))

    root.after(0, show_results, found)

def show_results(found):
    for port, service, status in found:
        result_table.insert(
            "",
            "end",
            values=(port, service, status)
        )

    status_label.config(
        text=f"Scan completed. {len(found)} open port(s) found."
    )

    scan_button.config(state="normal")

root = tk.Tk()
root.title("NetShield Network Scanner")
root.geometry("650x480")
root.configure(bg="#101827")

title = tk.Label(
    root,
    text="NETSHIELD",
    font=("Arial", 22, "bold"),
    bg="#101827",
    fg="#00E5A8"
)
title.pack(pady=15)

subtitle = tk.Label(
    root,
    text="Simple Network Security Scanner",
    font=("Arial", 11),
    bg="#101827",
    fg="white"
)
subtitle.pack()

input_frame = tk.Frame(root, bg="#101827")
input_frame.pack(pady=20)

ip_label = tk.Label(
    input_frame,
    text="Target IP:",
    bg="#101827",
    fg="white"
)
ip_label.pack(side="left", padx=5)

ip_entry = tk.Entry(input_frame, width=25)
ip_entry.pack(side="left", padx=5)
ip_entry.insert(0, "127.0.0.1")

scan_button = tk.Button(
    input_frame,
    text="START SCAN",
    command=start_scan,
    bg="#00E5A8",
    fg="black",
    font=("Arial", 10, "bold")
)
scan_button.pack(side="left", padx=5)

columns = ("Port", "Service", "Status")

result_table = ttk.Treeview(
    root,
    columns=columns,
    show="headings",
    height=15
)

for column in columns:
    result_table.heading(column, text=column)
    result_table.column(column, width=180)

result_table.pack(pady=15, padx=20, fill="both")

status_label = tk.Label(
    root,
    text="Ready to scan",
    bg="#101827",
    fg="#00E5A8"
)
status_label.pack(pady=10)

footer = tk.Label(
    root,
    text="Only scan networks you own or have permission to test.",
    bg="#101827",
    fg="gray",
    font=("Arial", 9)
)
footer.pack(pady=5)

root.mainloop()
