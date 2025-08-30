import socket
import threading
from tkinter import *
from tkinter import messagebox, scrolledtext
from datetime import datetime

def scan_ports(target, ports, output_box):
    output_box.insert(END, f"Scanning {target}...\nStarted at {datetime.now()}\n")
    output_box.insert(END, "-"*50 + "\n")

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)
            result = sock.connect_ex((target, port))

            if result == 0:
                output_box.insert(END, f"[+] Port {port} is OPEN\n")
            else:
                output_box.insert(END, f"[-] Port {port} is closed\n")
            sock.close()
        except Exception as e:
            output_box.insert(END, f"[!] Error: {e}\n")
            break

    output_box.insert(END, "-"*50 + "\nScan Complete!\n\n")


def start_scan():
    target = target_entry.get()
    port_range = port_entry.get()

    if not target:
        messagebox.showerror("Input Error", "Please enter a target IP or domain.")
        return

    try:
        if "-" in port_range:
            start_port, end_port = map(int, port_range.split('-'))
            ports = range(start_port, end_port + 1)
        else:
            ports = [int(port.strip()) for port in port_range.split(',')]
    except:
        messagebox.showerror("Input Error", "Enter ports as a range (e.g., 20-80) or comma-separated list.")
        return

    output_box.delete(1.0, END)
    threading.Thread(target=scan_ports, args=(target, ports, output_box), daemon=True).start()

# GUI Setup
app = Tk()
app.title("TCP Port Scanner")
app.geometry("600x500")
app.resizable(False, False)

Label(app, text="Target IP / Domain:", font=("Arial", 12)).pack(pady=5)
target_entry = Entry(app, width=40, font=("Arial", 12))
target_entry.pack(pady=5)

Label(app, text="Ports (e.g. 20-80 or 22,80,443):", font=("Arial", 12)).pack(pady=5)
port_entry = Entry(app, width=40, font=("Arial", 12))
port_entry.pack(pady=5)

Button(app, text="Start Scan", font=("Arial", 12, "bold"), command=start_scan, bg="#4CAF50", fg="white").pack(pady=10)

output_box = scrolledtext.ScrolledText(app, width=70, height=20, font=("Consolas", 10))
output_box.pack(padx=10, pady=10)

app.mainloop()
