#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import base64
import binascii
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from tkinterdnd2 import DND_FILES, TkinterDnD
from PIL import Image, ImageTk

# Import the refactored logic functions
from suo5_full_analyzer import process_pcap_to_excel
from decrypt_suo5_payload import decrypt_hex_string
from decrypt_godzilla_payload import godzilla_decode
from godzilla_pcap_analyzer import process_godzilla_pcap
from behinder_pcap_analyzer import process_behinder_pcap
from decrypt_behinder_payload import decrypt_subsequent_payload as decrypt_behinder_payload_func

class Suo5AnalyzerApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.style = tb.Style(theme="superhero")
        self.title("Webshell 流量分析工具 v1.0")
        self.geometry("900x700")

        try:
            img = Image.open('./icon.ico')
            icon_photo = ImageTk.PhotoImage(img)
            self.iconphoto(False, icon_photo)
        except Exception as e:
            print(f"[!] Could not load icon: {e}. Skipping icon.")
        
        self.create_menu()

        self.notebook = ttk.Notebook(self, bootstyle="dark")
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

        # Create and add tabs in the desired order
        self.create_suo5_tabs()
        self.create_godzilla_tabs()
        self.create_behinder_tabs()

    def create_menu(self):
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        help_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="关于", command=self.show_about)

    def show_about(self):
        about_text = """
Webshell 流量分析工具
版本: 1.0

此工具旨在帮助安全分析师快速解密和分析常见的 Webshell 流量，目前支持:
- suo5
- 哥斯拉 (Godzilla v3/v4)
- 冰蝎 (Behinder v3/v4)
"""
        about_window = tk.Toplevel(self)
        about_window.title("关于")
        about_window.geometry("450x300")
        about_window.resizable(False, False)
        
        text_area = ScrolledText(about_window, wrap=tk.WORD, state=tk.NORMAL, autohide=True)
        text_area.pack(expand=True, fill="both", padx=10, pady=10)
        text_area.insert(tk.END, about_text)
        text_area.text.config(state=tk.DISABLED)
        
        close_button = ttk.Button(about_window, text="关闭", command=about_window.destroy, bootstyle="success")
        close_button.pack(pady=10)

    # Grouped Tab Creation
    def create_suo5_tabs(self):
        # PCAP Analysis Tab
        suo5_pcap_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(suo5_pcap_tab, text="suo5 PCAP 分析")
        self.create_suo5_pcap_widgets(suo5_pcap_tab)

        # Payload Decryption Tab
        suo5_decrypt_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(suo5_decrypt_tab, text="suo5 载荷解密")
        self.create_suo5_decrypt_widgets(suo5_decrypt_tab)

    def create_godzilla_tabs(self):
        # PCAP Analysis Tab
        godzilla_pcap_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(godzilla_pcap_tab, text="哥斯拉 PCAP 分析")
        self.create_godzilla_pcap_widgets(godzilla_pcap_tab)

        # Payload Decryption Tab
        godzilla_decrypt_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(godzilla_decrypt_tab, text="哥斯拉载荷解密")
        self.create_godzilla_decrypt_widgets(godzilla_decrypt_tab)

    def create_behinder_tabs(self):
        # PCAP Analysis Tab
        behinder_pcap_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(behinder_pcap_tab, text="冰蝎 PCAP 分析")
        self.create_behinder_pcap_widgets(behinder_pcap_tab)

        # Payload Decryption Tab
        behinder_decrypt_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(behinder_decrypt_tab, text="冰蝎载荷解密")
        self.create_behinder_decrypt_widgets(behinder_decrypt_tab)

    # --- Widget Creation Methods (Refactored from old create_*_tab methods) ---
    
    def create_suo5_pcap_widgets(self, parent_tab):
        dnd_frame = ttk.LabelFrame(parent_tab, text=" 第一步: 选择或拖拽 suo5 .pcap 文件 ", padding=10)
        dnd_frame.pack(fill="x", padx=10, pady=10)
        dnd_frame.drop_target_register(DND_FILES)
        dnd_frame.dnd_bind('<<Drop>>', self.on_suo5_drop)

        self.suo5_file_path_var = tk.StringVar(value="未选择文件")
        file_label = ttk.Label(dnd_frame, textvariable=self.suo5_file_path_var, wraplength=700)
        file_label.pack(fill='x', pady=5)
        
        self.suo5_select_button = ttk.Button(dnd_frame, text="选择文件...", bootstyle="info-outline", command=self.select_suo5_pcap_file)
        self.suo5_select_button.pack(pady=10)

        self.suo5_analyze_button = ttk.Button(parent_tab, text="第二步: 开始分析", bootstyle="info-outline", command=self.start_suo5_analysis, state=tk.DISABLED)
        self.suo5_analyze_button.pack(pady=5, fill='x', padx=10)

        self.suo5_progress = ttk.Progressbar(parent_tab, mode='indeterminate', bootstyle=(STRIPED, SUCCESS))
        
        log_frame = ttk.LabelFrame(parent_tab, text="分析日志", padding=10)
        log_frame.pack(expand=True, fill="both", padx=10, pady=10)
        self.suo5_pcap_status_text = ScrolledText(log_frame, wrap=tk.WORD, state=tk.DISABLED, autohide=True)
        self.suo5_pcap_status_text.pack(expand=True, fill="both")

    def select_suo5_pcap_file(self):
        filepath = filedialog.askopenfilename(
            title="选择一个 PCAP 文件",
            filetypes=(("PCAP Files", "*.pcap *.pcapng"), ("All files", "*.*"))
        )
        if filepath:
            self.update_suo5_pcap_path(filepath)

    def on_suo5_drop(self, event):
        filepath = event.data.strip('{}') # Clean up path from dnd
        self.update_suo5_pcap_path(filepath)
        
    def update_suo5_pcap_path(self, filepath):
        self.suo5_pcap_filepath = filepath
        self.suo5_file_path_var.set(f"已选择: {filepath}")
        self.suo5_analyze_button.config(state=tk.NORMAL)
        self.log_to_suo5_status("文件已准备就绪，可以开始分析。")

    def log_to_suo5_status(self, message):
        self.suo5_pcap_status_text.text.config(state=tk.NORMAL)
        self.suo5_pcap_status_text.insert(tk.END, message + "\n")
        self.suo5_pcap_status_text.see(tk.END)
        self.suo5_pcap_status_text.text.config(state=tk.DISABLED)

    def start_suo5_analysis(self):
        self.suo5_analyze_button.config(state=tk.DISABLED)
        self.suo5_select_button.config(state=tk.DISABLED)
        self.suo5_pcap_status_text.text.config(state=tk.NORMAL)
        self.suo5_pcap_status_text.delete(1.0, tk.END)
        self.suo5_pcap_status_text.text.config(state=tk.DISABLED)
        self.suo5_progress.pack(pady=5, fill='x', padx=10)
        self.suo5_progress.start()

        output_path = filedialog.asksaveasfilename(
            title="保存 suo5 分析报告",
            initialdir=os.getcwd(),
            initialfile="suo5_attack_analysis.xlsx",
            defaultextension=".xlsx",
            filetypes=(("Excel Files", "*.xlsx"), ("All files", "*.*"))
        )
        if not output_path:
            self.log_to_suo5_status("[!] 操作取消: 未选择保存路径。")
            self.suo5_analyze_button.config(state=tk.NORMAL)
            self.suo5_select_button.config(state=tk.NORMAL)
            self.suo5_progress.stop()
            self.suo5_progress.pack_forget()
            return

        analysis_thread = threading.Thread(
            target=self.run_suo5_pcap_analysis,
            args=(self.suo5_pcap_filepath, output_path)
        )
        analysis_thread.start()

    def run_suo5_pcap_analysis(self, input_path, output_path):
        try:
            process_pcap_to_excel(input_path, output_path, status_callback=self.log_to_suo5_status)
        except Exception as e:
            self.log_to_suo5_status(f"发生严重错误: {e}")
        finally:
            self.suo5_progress.stop()
            self.suo5_progress.pack_forget()
            self.suo5_analyze_button.config(state=tk.NORMAL)
            self.suo5_select_button.config(state=tk.NORMAL)

    def create_godzilla_pcap_widgets(self, parent_tab):
        input_container = ttk.Frame(parent_tab, padding=10)
        input_container.pack(fill='x')

        pcap_frame = ttk.LabelFrame(input_container, text=" 第一步: 选择 PCAP 文件 ", padding=10)
        pcap_frame.pack(fill='x', pady=5)
        self.g_pcap_select_button = ttk.Button(pcap_frame, text="选择文件...", bootstyle="info-outline", command=self.select_godzilla_pcap_file)
        self.g_pcap_select_button.pack(pady=5)
        self.g_pcap_path_var = tk.StringVar(value="未选择文件")
        g_pcap_label = ttk.Label(pcap_frame, textvariable=self.g_pcap_path_var, wraplength=650)
        g_pcap_label.pack(pady=5)

        info_frame = ttk.LabelFrame(input_container, text=" 第二步: 提供 Webshell 信息 ", padding=10)
        info_frame.pack(fill='x', pady=5)
        info_frame.columnconfigure(1, weight=1)
        
        key_label = ttk.Label(info_frame, text="连接密码 (Key):")
        key_label.grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.g_key_input = ttk.Entry(info_frame, width=40)
        self.g_key_input.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        uri_label = ttk.Label(info_frame, text="Webshell URI:")
        uri_label.grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.g_uri_input = ttk.Entry(info_frame, width=40)
        self.g_uri_input.grid(row=1, column=1, sticky='ew', padx=5, pady=5)
        crypter_label = ttk.Label(info_frame, text="加密器类型:")
        crypter_label.grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.g_crypter_var = tk.StringVar(value="AES_BASE64 (V4 Default)")
        crypter_options = ["AES_BASE64 (V4 Default)", "XOR_BASE64 (V3 Default)", "PHP_EVAL_XOR_BASE64"]
        self.g_crypter_menu = ttk.OptionMenu(info_frame, self.g_crypter_var, crypter_options[0], *crypter_options)
        self.g_crypter_menu.grid(row=2, column=1, sticky='w', padx=5, pady=5)

        self.g_analyze_button = ttk.Button(parent_tab, text=" 第三步: 开始分析 ", command=self.start_godzilla_analysis, state=tk.DISABLED, bootstyle="info-outline")
        self.g_analyze_button.pack(pady=5, fill='x', padx=10)

        self.g_progress = ttk.Progressbar(parent_tab, mode='indeterminate', bootstyle=(STRIPED, SUCCESS))
        
        g_log_frame = ttk.LabelFrame(parent_tab, text=" 分析日志 ", padding=10)
        g_log_frame.pack(expand=True, fill="both", padx=10, pady=10)
        self.g_pcap_status_text = ScrolledText(g_log_frame, wrap=tk.WORD, state=tk.DISABLED, autohide=True)
        self.g_pcap_status_text.pack(expand=True, fill="both")

    def select_godzilla_pcap_file(self):
        filepath = filedialog.askopenfilename(
            title="选择一个 PCAP 文件",
            filetypes=(("PCAP Files", "*.pcap *.pcapng"), ("All files", "*.*"))
        )
        if filepath:
            self.godzilla_pcap_filepath = filepath
            self.g_pcap_path_var.set(f"已选择: {filepath}")
            self.g_analyze_button.config(state=tk.NORMAL)
    
    def log_to_godzilla_status(self, message):
        self.g_pcap_status_text.text.config(state=tk.NORMAL)
        self.g_pcap_status_text.insert(tk.END, message + "\n")
        self.g_pcap_status_text.see(tk.END)
        self.g_pcap_status_text.text.config(state=tk.DISABLED)

    def start_godzilla_analysis(self):
        key = self.g_key_input.get().strip()
        uri = self.g_uri_input.get().strip()
        crypter = self.g_crypter_var.get()

        if not hasattr(self, 'godzilla_pcap_filepath') or not self.godzilla_pcap_filepath:
            self.log_to_godzilla_status("[!] 请先选择一个PCAP文件。")
            return
        if not key or not uri:
            self.log_to_godzilla_status("[!] 连接密码和Webshell URI均不能为空。")
            return

        self.g_analyze_button.config(state=tk.DISABLED)
        self.g_pcap_select_button.config(state=tk.DISABLED)
        self.g_pcap_status_text.text.config(state=tk.NORMAL)
        self.g_pcap_status_text.delete(1.0, tk.END)
        self.g_pcap_status_text.text.config(state=tk.DISABLED)
        self.g_progress.pack(pady=5, fill='x', padx=10)
        self.g_progress.start()
        
        output_path = filedialog.asksaveasfilename(
            title="保存 Godzilla 分析报告",
            initialdir=os.getcwd(),
            initialfile="godzilla_attack_analysis.xlsx",
            defaultextension=".xlsx",
            filetypes=(("Excel Files", "*.xlsx"), ("All files", "*.*"))
        )
        if not output_path:
            self.log_to_godzilla_status("[!] 操作取消: 未选择保存路径。")
            self.g_analyze_button.config(state=tk.NORMAL)
            self.g_pcap_select_button.config(state=tk.NORMAL)
            self.g_progress.stop()
            self.g_progress.pack_forget()
            return

        analysis_thread = threading.Thread(
            target=self.run_godzilla_pcap_analysis,
            args=(self.godzilla_pcap_filepath, output_path, key, uri, crypter)
        )
        analysis_thread.start()

    def run_godzilla_pcap_analysis(self, input_path, output_path, key, uri, crypter):
        try:
            process_godzilla_pcap(input_path, output_path, key, uri, crypter, status_callback=self.log_to_godzilla_status)
        except Exception as e:
            self.log_to_godzilla_status(f"发生严重错误: {e}")
        finally:
            self.g_progress.stop()
            self.g_progress.pack_forget()
            self.g_analyze_button.config(state=tk.NORMAL)
            self.g_pcap_select_button.config(state=tk.NORMAL)

    def create_behinder_pcap_widgets(self, parent_tab):
        input_container = ttk.Frame(parent_tab, padding=10)
        input_container.pack(fill='x')

        pcap_frame = ttk.LabelFrame(input_container, text=" 第一步: 选择 PCAP 文件 ", padding=10)
        pcap_frame.pack(fill='x', expand=True, pady=5)
        b_pcap_select_button = ttk.Button(pcap_frame, text="选择文件...", bootstyle="info-outline", command=self.select_behinder_pcap_file)
        b_pcap_select_button.pack(pady=5)
        self.b_pcap_path_var = tk.StringVar(value="未选择文件")
        b_pcap_label = ttk.Label(pcap_frame, textvariable=self.b_pcap_path_var, wraplength=650)
        b_pcap_label.pack(pady=5)

        info_frame = ttk.LabelFrame(input_container, text=" 第二步: 提供 Webshell 连接密码 ", padding=10)
        info_frame.pack(fill='x', expand=True, pady=5)
        info_frame.columnconfigure(1, weight=1)
        key_label = ttk.Label(info_frame, text="连接密码:")
        key_label.grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.b_password_input = ttk.Entry(info_frame, width=40)
        self.b_password_input.grid(row=0, column=1, sticky='ew', padx=5, pady=5)

        self.b_analyze_button = ttk.Button(parent_tab, text=" 第三步: 开始分析 ", command=self.start_behinder_analysis, state=tk.DISABLED, bootstyle="info-outline")
        self.b_analyze_button.pack(pady=5, fill='x', padx=10)

        self.b_progress = ttk.Progressbar(parent_tab, mode='indeterminate', bootstyle=(STRIPED, SUCCESS))
        
        b_log_frame = ttk.LabelFrame(parent_tab, text=" 分析日志 ", padding=10)
        b_log_frame.pack(expand=True, fill="both", padx=10, pady=10)
        self.b_pcap_status_text = ScrolledText(b_log_frame, wrap=tk.WORD, state=tk.DISABLED, autohide=True)
        self.b_pcap_status_text.pack(expand=True, fill="both")

    def select_behinder_pcap_file(self):
        filepath = filedialog.askopenfilename(
            title="选择一个 PCAP 文件",
            filetypes=(("PCAP Files", "*.pcap *.pcapng"), ("All files", "*.*"))
        )
        if filepath:
            self.behinder_pcap_filepath = filepath
            self.b_pcap_path_var.set(f"已选择: {filepath}")
            self.b_analyze_button.config(state=tk.NORMAL)
    
    def log_to_behinder_status(self, message):
        self.b_pcap_status_text.text.config(state=tk.NORMAL)
        self.b_pcap_status_text.insert(tk.END, message + "\n")
        self.b_pcap_status_text.see(tk.END)
        self.b_pcap_status_text.text.config(state=tk.DISABLED)

    def start_behinder_analysis(self):
        password = self.b_password_input.get().strip()

        if not hasattr(self, 'behinder_pcap_filepath') or not self.behinder_pcap_filepath:
            self.log_to_behinder_status("[!] 请先选择一个PCAP文件。")
            return
        if not password:
            self.log_to_behinder_status("[!] 连接密码不能为空。")
            return

        self.b_analyze_button.config(state=tk.DISABLED)
        self.b_pcap_status_text.text.config(state=tk.NORMAL)
        self.b_pcap_status_text.delete(1.0, tk.END)
        self.b_pcap_status_text.text.config(state=tk.DISABLED)
        self.b_progress.pack(pady=5, fill='x', padx=10)
        self.b_progress.start()
        
        output_path = filedialog.asksaveasfilename(
            title="保存 Behinder 分析报告",
            initialdir=os.getcwd(),
            initialfile="behinder_attack_analysis.xlsx",
            defaultextension=".xlsx",
            filetypes=(("Excel Files", "*.xlsx"), ("All files", "*.*"))
        )
        if not output_path:
            self.log_to_behinder_status("[!] 操作取消: 未选择保存路径。")
            self.b_analyze_button.config(state=tk.NORMAL)
            self.b_progress.stop()
            self.b_progress.pack_forget()
            return

        analysis_thread = threading.Thread(
            target=self.run_behinder_pcap_analysis,
            args=(self.behinder_pcap_filepath, output_path, password)
        )
        analysis_thread.start()

    def run_behinder_pcap_analysis(self, input_path, output_path, password):
        try:
            process_behinder_pcap(input_path, output_path, password, status_callback=self.log_to_behinder_status)
        except Exception as e:
            self.log_to_behinder_status(f"发生严重错误: {e}")
        finally:
            self.b_progress.stop()
            self.b_progress.pack_forget()
            self.b_analyze_button.config(state=tk.NORMAL)

    def create_behinder_decrypt_widgets(self, parent_tab):
        b_input_frame = ttk.LabelFrame(parent_tab, text=" 输入冰蝎加密信息 (v3/v4) ", padding=10)
        b_input_frame.pack(fill="x", padx=10, pady=10)
        b_input_frame.columnconfigure(1, weight=1)

        b_key_label = ttk.Label(b_input_frame, text="动态会话密钥 (Base64):")
        b_key_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.b_decrypt_key_input = ttk.Entry(b_input_frame, width=60)
        self.b_decrypt_key_input.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        
        b_key_hint_label = ttk.Label(b_input_frame, text="注意：此处不是Webshell密码，而是从流量中捕获的16字节会话密钥", foreground="gray")
        b_key_hint_label.grid(row=1, column=1, sticky="w", padx=5, pady=(0,5))

        b_payload_label = ttk.Label(b_input_frame, text="加密载荷 (Base64):")
        b_payload_label.grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.b_payload_text = ScrolledText(b_input_frame, height=8, width=60, autohide=True)
        self.b_payload_text.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

        self.b_decrypt_button = ttk.Button(parent_tab, text="解密", command=self.perform_behinder_decryption, bootstyle="info-outline")
        self.b_decrypt_button.pack(pady=10, fill='x', padx=10)

        b_result_frame = ttk.LabelFrame(parent_tab, text=" 解密结果 ", padding=10)
        b_result_frame.pack(expand=True, fill="both", padx=10, pady=10)
        self.b_result_text = ScrolledText(b_result_frame, wrap=tk.WORD, state=tk.DISABLED, autohide=True)
        self.b_result_text.pack(expand=True, fill="both")

    def perform_behinder_decryption(self):
        dynamic_key_b64 = self.b_decrypt_key_input.get().strip()
        payload_b64 = self.b_payload_text.get("1.0", tk.END).strip()
        
        if not dynamic_key_b64 or not payload_b64:
            messagebox.showwarning("输入错误", "动态会话密钥和载荷均不能为空。")
            return

        try:
            # The function expects bytes, so we decode from base64
            dynamic_key_bytes = base64.b64decode(dynamic_key_b64)
            payload_bytes = base64.b64decode(payload_b64)
            
            if len(dynamic_key_bytes) != 16:
                 messagebox.showwarning("密钥错误", "动态会话密钥必须是16字节。请检查您输入的Base64密钥。")
                 return

            result = decrypt_behinder_payload_func(payload_bytes, dynamic_key_bytes)

        except (binascii.Error, Exception) as e:
            result = f"[!] 解密失败: {e}\n\n请检查输入是否为有效的Base64编码，以及密钥是否正确。"

        self.b_result_text.text.config(state=tk.NORMAL)
        self.b_result_text.delete(1.0, tk.END)
        self.b_result_text.insert(tk.END, result)
        self.b_result_text.text.config(state=tk.DISABLED)

    def create_suo5_decrypt_widgets(self, parent_tab):
        input_frame = ttk.LabelFrame(parent_tab, text=" 输入加密的 suo5 载荷 (Hex 格式) ", padding=10)
        input_frame.pack(fill="x", padx=10, pady=10)
        self.suo5_payload_input = ScrolledText(input_frame, height=8, wrap=tk.WORD, autohide=True)
        self.suo5_payload_input.pack(expand=True, fill="x", padx=5, pady=5)

        self.suo5_decrypt_button = ttk.Button(parent_tab, text=" 解密 ", command=self.run_suo5_decryption, bootstyle="info-outline")
        self.suo5_decrypt_button.pack(pady=10, fill='x', padx=10)

        result_frame = ttk.LabelFrame(parent_tab, text=" 解密结果 ", padding=10)
        result_frame.pack(expand=True, fill="both", padx=10, pady=10)
        self.suo5_result_text = ScrolledText(result_frame, wrap=tk.WORD, state=tk.DISABLED, autohide=True)
        self.suo5_result_text.pack(expand=True, fill="both")

    def run_suo5_decryption(self):
        hex_payload = self.suo5_payload_input.get(1.0, tk.END).strip()
        self.suo5_result_text.text.config(state=tk.NORMAL)
        self.suo5_result_text.delete(1.0, tk.END)
        try:
            if not hex_payload:
                raise ValueError("输入载荷不能为空")
            result = decrypt_hex_string(hex_payload)
            self.suo5_result_text.insert(tk.END, "解密成功:\n" + "="*20 + "\n")
            self.suo5_result_text.insert(tk.END, result)
        except (binascii.Error, ValueError) as e:
            self.suo5_result_text.insert(tk.END, f"解密失败: {e}\n请确保输入的是有效的十六进制字符串。")
        except Exception as e:
            self.suo5_result_text.insert(tk.END, f"发生未知错误: {e}")
        finally:
            self.suo5_result_text.text.config(state=tk.DISABLED)

    def create_godzilla_decrypt_widgets(self, parent_tab):
        g_input_frame = ttk.LabelFrame(parent_tab, text=" 输入哥斯拉加密信息 ", padding=10)
        g_input_frame.pack(fill="x", padx=10, pady=10)
        g_input_frame.columnconfigure(1, weight=1)

        g_key_label = ttk.Label(g_input_frame, text="连接密码 (Key):")
        g_key_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.g_decrypt_key_input = ttk.Entry(g_input_frame, width=60)
        self.g_decrypt_key_input.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        g_crypter_label = ttk.Label(g_input_frame, text="加密器类型:")
        g_crypter_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.g_decrypt_crypter_var = tk.StringVar(value="AES_BASE64 (V4 Default)")
        crypter_options = ["AES_BASE64 (V4 Default)", "XOR_BASE64 (V3 Default)", "PHP_EVAL_XOR_BASE64"]
        self.g_decrypt_crypter_menu = ttk.OptionMenu(g_input_frame, self.g_decrypt_crypter_var, crypter_options[0], *crypter_options)
        self.g_decrypt_crypter_menu.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        
        g_payload_hint = ttk.Label(g_input_frame, text="注意：对于EVAL类型，请粘贴完整的POST请求体 (e.g., pass=...&o=...)", foreground="gray")
        g_payload_hint.grid(row=2, column=1, sticky="w", padx=5, pady=(0,5))

        g_payload_label = ttk.Label(g_input_frame, text="加密载荷:")
        g_payload_label.grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.g_payload_text = ScrolledText(g_input_frame, height=8, width=60, autohide=True)
        self.g_payload_text.grid(row=3, column=1, sticky="ew", padx=5, pady=5)
        
        self.g_decrypt_button = ttk.Button(parent_tab, text="解密", command=self.perform_godzilla_decryption, bootstyle="info-outline")
        self.g_decrypt_button.pack(pady=10, fill='x', padx=10)

        g_result_frame = ttk.LabelFrame(parent_tab, text=" 解密结果 ", padding=10)
        g_result_frame.pack(expand=True, fill="both", padx=10, pady=10)
        self.g_result_text = ScrolledText(g_result_frame, wrap=tk.WORD, state=tk.DISABLED, autohide=True)
        self.g_result_text.pack(expand=True, fill="both")

    def perform_godzilla_decryption(self):
        key = self.g_decrypt_key_input.get().strip()
        payload = self.g_payload_text.get("1.0", tk.END).strip()
        crypter_map = {
            "AES_BASE64 (V4 Default)": "AES_BASE64",
            "XOR_BASE64 (V3 Default)": "XOR_BASE64",
            "PHP_EVAL_XOR_BASE64": "PHP_EVAL_XOR_BASE64"
        }
        crypter = crypter_map[self.g_decrypt_crypter_var.get()]

        self.g_result_text.text.config(state=tk.NORMAL)
        self.g_result_text.delete(1.0, tk.END)

        if not key or not payload:
            messagebox.showwarning("输入错误", "密码和载荷均不能为空。")
            return

        result = godzilla_decode(payload, key, crypter)

        self.g_result_text.text.config(state=tk.DISABLED)

if __name__ == '__main__':
    app = Suo5AnalyzerApp()
    app.mainloop() 