import tkinter as tk
from tkinter import messagebox, scrolledtext
import scapy_firewall_core as core
import threading
import os

class FirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Personal Firewall")
        self.root.geometry("700x500")

        # Create log directory if it doesn't exist
        os.makedirs(os.path.dirname(core.log_file_path), exist_ok=True)

        # Log Viewer
        self.log_area = scrolledtext.ScrolledText(root, height=20, width=85)
        self.log_area.pack(pady=10)

        # IP/Port Block Entry
        self.entry_frame = tk.Frame(root)
        self.entry_frame.pack()

        tk.Label(self.entry_frame, text="Block IP:").grid(row=0, column=0)
        self.block_ip = tk.Entry(self.entry_frame)
        self.block_ip.grid(row=0, column=1, padx=5)

        tk.Label(self.entry_frame, text="Block Port:").grid(row=0, column=2)
        self.block_port = tk.Entry(self.entry_frame)
        self.block_port.grid(row=0, column=3, padx=5)

        self.block_button = tk.Button(self.entry_frame, text="Add to Blocklist", command=self.add_block)
        self.block_button.grid(row=0, column=4, padx=5)

        # Start/Stop Buttons
        self.control_frame = tk.Frame(root)
        self.control_frame.pack(pady=10)

        self.start_btn = tk.Button(self.control_frame, text="Start Firewall", command=self.start_firewall)
        self.start_btn.grid(row=0, column=0, padx=10)

        self.stop_btn = tk.Button(self.control_frame, text="Stop Firewall", command=self.stop_firewall)
        self.stop_btn.grid(row=0, column=1, padx=10)

        self.update_logs()

    def add_block(self):
        ip = self.block_ip.get().strip()
        port = self.block_port.get().strip()

        if ip:
            core.blocked_ips.add(ip)
        if port.isdigit():
            core.blocked_ports.add(int(port))

        messagebox.showinfo("Success", f"Blocked: IP={ip if ip else 'N/A'}, Port={port if port else 'N/A'}")
        self.block_ip.delete(0, tk.END)
        self.block_port.delete(0, tk.END)

    def start_firewall(self):
        core.start_firewall()
        messagebox.showinfo("Firewall", "Firewall Started.")

    def stop_firewall(self):
        core.stop_sniffing()
        messagebox.showinfo("Firewall", "Firewall Stopped.")

    def update_logs(self):
        try:
            with open(core.log_file_path, "r", encoding="utf-8") as f:
                data = f.read()
                self.log_area.delete("1.0", tk.END)
                self.log_area.insert(tk.END, data)
        except FileNotFoundError:
            self.log_area.insert(tk.END, "[INFO] Waiting for logs...\n")
        self.root.after(2000, self.update_logs)

# Launch the app
if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()
