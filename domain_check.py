import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import whois
from datetime import datetime
import threading
import requests
from urllib.parse import urlparse

class EnhancedDomainChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Professional Domain Analyzer")
        self.root.geometry("800x700")
        self.root.configure(bg="black")
        self.root.resizable(True, True)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure styles for black and white theme
        self.style.configure('TFrame', background='black')
        self.style.configure('TLabel', background='black', foreground='white', font=('Consolas', 10))
        self.style.configure('TButton', background='white', foreground='black', font=('Consolas', 10, 'bold'))
        self.style.configure('TEntry', fieldbackground='white', foreground='black', font=('Consolas', 10))
        self.style.configure('Header.TLabel', background='black', foreground='white', font=('Consolas', 18, 'bold'))
        self.style.configure('Footer.TLabel', background='black', foreground='white', font=('Consolas', 8))
        self.style.configure('Section.TLabel', background='black', foreground='white', font=('Consolas', 12, 'bold'))
        self.style.configure('Available.TLabel', background='black', foreground='green', font=('Consolas', 10, 'bold'))
        self.style.configure('NotAvailable.TLabel', background='black', foreground='red', font=('Consolas', 10, 'bold'))
        self.style.configure('Info.TLabel', background='black', foreground='cyan', font=('Consolas', 10))
        self.style.configure('TLabelframe', background='black', foreground='white')
        self.style.configure('TLabelframe.Label', background='black', foreground='white')
        self.style.configure('Horizontal.TSeparator', background='white')
        
        self.create_header()
        self.create_main_section()
        self.create_results_section()
        self.create_footer()
        
    def create_header(self):
        # Header frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill='x', pady=(10, 5))
        
        # Title
        title_label = ttk.Label(header_frame, text="PROFESSIONAL DOMAIN ANALYZER", style='Header.TLabel')
        title_label.pack()
        
        # Separator
        separator = ttk.Separator(header_frame, orient='horizontal', style='Horizontal.TSeparator')
        separator.pack(fill='x', padx=20, pady=10)
        
        # Description
        desc_label = ttk.Label(header_frame, 
                              text="Comprehensive domain information tool - Check availability, WHOIS data, and more", 
                              style='Info.TLabel')
        desc_label.pack()
        
    def create_main_section(self):
        # Main input frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='x', padx=20, pady=10)
        
        # Domain input
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill='x', pady=10)
        
        domain_label = ttk.Label(input_frame, text="Enter Domain Name:")
        domain_label.pack(anchor='w')
        
        input_subframe = ttk.Frame(input_frame)
        input_subframe.pack(fill='x', pady=5)
        
        self.domain_var = tk.StringVar()
        domain_entry = ttk.Entry(input_subframe, textvariable=self.domain_var, width=50)
        domain_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        domain_entry.bind('<Return>', lambda e: self.check_domain())
        
        # TLD selection
        tld_frame = ttk.Frame(main_frame)
        tld_frame.pack(fill='x', pady=5)
        
        tld_label = ttk.Label(tld_frame, text="Common TLDs (click to add):")
        tld_label.pack(anchor='w')
        
        tld_button_frame = ttk.Frame(tld_frame)
        tld_button_frame.pack(fill='x', pady=5)
        
        tlds = ['.com', '.org', '.net', '.io', '.dev', '.ai', '.co', '.uk', '.edu', '.gov']
        for tld in tlds:
            btn = ttk.Button(tld_button_frame, text=tld, width=5, 
                            command=lambda t=tld: self.add_tld(t))
            btn.pack(side='left', padx=2)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=10)
        
        check_button = ttk.Button(button_frame, text="Check Domain", command=self.check_domain)
        check_button.pack(side='left', padx=5)
        
        clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        clear_button.pack(side='left', padx=5)
        
        export_button = ttk.Button(button_frame, text="Export Results", command=self.export_results)
        check_button.pack(side='left', padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill='x', pady=5)
        
    def create_results_section(self):
        # Notebook for organized results
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Overview tab
        self.overview_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.overview_frame, text="Overview")
        
        # WHOIS tab
        self.whois_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.whois_frame, text="WHOIS Data")
        
        # Technical tab
        self.tech_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.tech_frame, text="Technical Info")
        
        # Create text areas for results
        self.overview_text = scrolledtext.ScrolledText(self.overview_frame, bg="black", fg="white", 
                                                      font=('Consolas', 10), insertbackground='white')
        self.overview_text.pack(fill='both', expand=True)
        
        self.whois_text = scrolledtext.ScrolledText(self.whois_frame, bg="black", fg="white", 
                                                  font=('Consolas', 10), insertbackground='white')
        self.whois_text.pack(fill='both', expand=True)
        
        self.tech_text = scrolledtext.ScrolledText(self.tech_frame, bg="black", fg="white", 
                                                  font=('Consolas', 10), insertbackground='white')
        self.tech_text.pack(fill='both', expand=True)
        
        # Disable editing
        for text_widget in [self.overview_text, self.whois_text, self.tech_text]:
            text_widget.config(state=tk.DISABLED)
        
    def create_footer(self):
        # Footer frame
        footer_frame = ttk.Frame(self.root)
        footer_frame.pack(fill='x', pady=(5, 10))
        
        # Separator
        separator = ttk.Separator(footer_frame, orient='horizontal', style='Horizontal.TSeparator')
        separator.pack(fill='x', padx=20, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Enter a domain name to begin analysis")
        status_bar = ttk.Label(footer_frame, textvariable=self.status_var, style='Footer.TLabel')
        status_bar.pack()
        
        # Copyright
        copyright_label = ttk.Label(footer_frame, 
                                   text="© 2023 Domain Analyzer Tool | Professional Grade Domain Intelligence", 
                                   style='Footer.TLabel')
        copyright_label.pack()
        
    def add_tld(self, tld):
        current_domain = self.domain_var.get().strip()
        if current_domain:
            # Remove any existing TLD and add the new one
            base_domain = current_domain.split('.')[0]
            self.domain_var.set(base_domain + tld)
        else:
            self.domain_var.set("example" + tld)
            
    def check_domain(self):
        domain = self.domain_var.get().strip()
        if not domain:
            messagebox.showwarning("Input Error", "Please enter a domain name")
            return
            
        # Clear previous results
        self.clear_results_text()
        
        # Start progress bar
        self.progress.start(10)
        self.status_var.set(f"Analyzing {domain}...")
        
        # Run in a separate thread to avoid UI freezing
        thread = threading.Thread(target=self.perform_analysis, args=(domain,))
        thread.daemon = True
        thread.start()
        
    def perform_analysis(self, domain):
        try:
            # Add http:// if missing for parsing
            if not domain.startswith(('http://', 'https://')):
                domain_to_check = 'http://' + domain
            else:
                domain_to_check = domain
                
            parsed_url = urlparse(domain_to_check)
            domain_name = parsed_url.netloc or parsed_url.path
            
            # Get domain information
            domain_info = whois.whois(domain_name)
            
            # Get IP address
            try:
                ip_address = socket.gethostbyname(domain_name)
            except:
                ip_address = "Could not resolve"
                
            # Get HTTP status if available
            http_status = "N/A"
            try:
                response = requests.get(domain_to_check, timeout=5)
                http_status = f"{response.status_code} {response.reason}"
            except:
                http_status = "No HTTP response"
            
            # Update UI with results
            self.root.after(0, self.display_results, domain_name, domain_info, ip_address, http_status)
            
        except whois.parser.PywhoisError:
            self.root.after(0, self.display_domain_available, domain_name)
        except Exception as e:
            self.root.after(0, self.display_error, str(e))
            
    def display_results(self, domain, domain_info, ip_address, http_status):
        # Stop progress bar
        self.progress.stop()
        self.status_var.set(f"Analysis complete for {domain}")
        
        # Overview tab
        self.overview_text.config(state=tk.NORMAL)
        self.overview_text.delete(1.0, tk.END)
        
        overview_content = f"""
╔══════════════════════════════════════════════════════════════╗
║                     DOMAIN ANALYSIS REPORT                  ║
╚══════════════════════════════════════════════════════════════╝

Domain: {domain}
IP Address: {ip_address}
HTTP Status: {http_status}

Status: REGISTERED

Registrar: {domain_info.registrar or 'N/A'}
Creation Date: {self.format_date(domain_info.creation_date)}
Expiration Date: {self.format_date(domain_info.expiration_date)}
Last Updated: {self.format_date(domain_info.updated_date)}

Name Servers:
{self.format_list(domain_info.name_servers)}

"""
        self.overview_text.insert(1.0, overview_content)
        self.overview_text.config(state=tk.DISABLED)
        
        # WHOIS tab
        self.whois_text.config(state=tk.NORMAL)
        self.whois_text.delete(1.0, tk.END)
        
        whois_content = f"""
╔══════════════════════════════════════════════════════════════╗
║                         WHOIS DATA                          ║
╚══════════════════════════════════════════════════════════════╝

Registrant:
{self.format_person_info(domain_info, 'registrant')}

Administrative Contact:
{self.format_person_info(domain_info, 'admin')}

Technical Contact:
{self.format_person_info(domain_info, 'tech')}

Raw WHOIS Data:
{domain_info.text}

"""
        self.whois_text.insert(1.0, whois_content)
        self.whois_text.config(state=tk.DISABLED)
        
        # Technical tab
        self.tech_text.config(state=tk.NORMAL)
        self.tech_text.delete(1.0, tk.END)
        
        tech_content = f"""
╔══════════════════════════════════════════════════════════════╗
║                     TECHNICAL DETAILS                       ║
╚══════════════════════════════════════════════════════════════╝

Domain Name: {domain}
IP Address: {ip_address}
HTTP Status: {http_status}

DNS Information:
{self.get_dns_info(domain)}

Name Servers:
{self.format_list(domain_info.name_servers)}

Registrar URL: {domain_info.registrar or 'N/A'}
WHOIS Server: {domain_info.whois_server or 'N/A'}

"""
        self.tech_text.insert(1.0, tech_content)
        self.tech_text.config(state=tk.DISABLED)
        
    def display_domain_available(self, domain):
        # Stop progress bar
        self.progress.stop()
        self.status_var.set(f"Analysis complete for {domain}")
        
        # Update overview tab
        self.overview_text.config(state=tk.NORMAL)
        self.overview_text.delete(1.0, tk.END)
        
        available_content = f"""
╔══════════════════════════════════════════════════════════════╗
║                     DOMAIN ANALYSIS REPORT                  ║
╚══════════════════════════════════════════════════════════════╝

Domain: {domain}

Status: AVAILABLE FOR REGISTRATION

This domain is not currently registered.
You may be able to register it through a domain registrar.

"""
        self.overview_text.insert(1.0, available_content)
        self.overview_text.config(state=tk.DISABLED)
        
        # Clear other tabs
        for text_widget in [self.whois_text, self.tech_text]:
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.insert(1.0, "No WHOIS data available for unregistered domains")
            text_widget.config(state=tk.DISABLED)
            
    def display_error(self, error_msg):
        # Stop progress bar
        self.progress.stop()
        self.status_var.set("Error occurred during analysis")
        
        # Update overview tab
        self.overview_text.config(state=tk.NORMAL)
        self.overview_text.delete(1.0, tk.END)
        
        error_content = f"""
╔══════════════════════════════════════════════════════════════╗
║                         ERROR                               ║
╚══════════════════════════════════════════════════════════════╝

An error occurred during domain analysis:

{error_msg}

Please check the domain name and try again.

"""
        self.overview_text.insert(1.0, error_content)
        self.overview_text.config(state=tk.DISABLED)
        
    def format_date(self, date):
        if not date:
            return "N/A"
        if isinstance(date, list):
            date = date[0]
        if isinstance(date, datetime):
            return date.strftime("%Y-%m-%d %H:%M:%S")
        return str(date)
    
    def format_list(self, items):
        if not items:
            return "  N/A"
        if isinstance(items, list):
            return "\n".join([f"  • {item}" for item in items])
        return f"  • {items}"
    
    def format_person_info(self, domain_info, role):
        result = ""
        for field in ['name', 'organization', 'address', 'city', 'state', 'zipcode', 'country', 'email', 'phone']:
            attr_name = f"{role}_{field}"
            value = getattr(domain_info, attr_name, None)
            if value:
                if isinstance(value, list):
                    value = value[0]
                result += f"  {field.title()}: {value}\n"
        return result or "  N/A\n"
    
    def get_dns_info(self, domain):
        try:
            # Basic DNS info
            result = ""
            # Get A record
            try:
                a_record = socket.gethostbyname(domain)
                result += f"  A Record: {a_record}\n"
            except:
                result += "  A Record: Not found\n"
                
            # Try to get MX records
            try:
                mx_records = socket.getaddrinfo(domain, 25)
                if mx_records:
                    result += f"  MX Records: Found {len(mx_records)} records\n"
                else:
                    result += "  MX Records: None found\n"
            except:
                result += "  MX Records: Could not retrieve\n"
                
            return result
        except:
            return "  Could not retrieve DNS information\n"
        
    def clear_results(self):
        self.domain_var.set("")
        self.clear_results_text()
        self.status_var.set("Ready - Enter a domain name to begin analysis")
        
    def clear_results_text(self):
        for text_widget in [self.overview_text, self.whois_text, self.tech_text]:
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.config(state=tk.DISABLED)
            
    def export_results(self):
        # Placeholder for export functionality
        messagebox.showinfo("Export", "Export functionality would be implemented here")

if __name__ == "__main__":
    root = tk.Tk()
    app = EnhancedDomainChecker(root)
    root.mainloop()