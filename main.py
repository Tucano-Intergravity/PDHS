import tkinter as tk
from tkinter import ttk, messagebox
import serial
import serial.tools.list_ports
import threading
import time
import struct
import binascii
import traceback
import zlib
import math

# --- Constants & Configuration ---

DEFAULT_BAUDRATE = 115200
DEFAULT_TIMEOUT = 0.1 

# Protocol Constants
PRIORITY = 0
SOURCE_ADDRESS = 6      # OBC/GSE ID (PDHS)
DEST_ADDRESS = 19       # IGNU Payload ID
DEST_PORT = 10          
SOURCE_PORT = 10        

# APIDs
APID_TC = 0x23B         # GSE (Sender) ID
APID_TM = 0x550         # IGNU (Receiver) ID

# Service & Subtypes
SVC_TEST = 1
MSG_START_TEST = 1
MSG_STOP_TEST = 2
MSG_REPORT_END = 3
MSG_SET_PARAM = 4
MSG_SEND_TPVAW = 5
MSG_REQ_DATA = 10 # Range 10~127

SVC_STATUS = 5
MSG_REQ_STATUS = 1
MSG_REP_STATUS = 1

SVC_CONN = 20
MSG_PING_REQ = 1
MSG_PING_REP = 1

# KISS Protocol
FEND  = 0xC0
FESC  = 0xDB
TFEND = 0xDC
TFESC = 0xDD

class CRC32C:
    # Castagnoli implementation
    @staticmethod
    def calc(data: bytes) -> int:
        crc = 0xFFFFFFFF
        poly = 0x82F63B78
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1: crc = (crc >> 1) ^ poly
                else: crc >>= 1
        return crc ^ 0xFFFFFFFF

class KISS:
    def __init__(self):
        self.rx_buffer = bytearray()
        self.in_frame = False
        self.escape = False

    def frame(self, data):
        frame = bytearray()
        frame.append(FEND)
        
        # [Fix] Add KISS Command Byte (0x00 - Data Frame)
        payload = bytearray([0x00]) + data
        
        for byte in payload:
            if byte == FEND:
                frame.append(FESC); frame.append(TFEND)
            elif byte == FESC:
                frame.append(FESC); frame.append(TFESC)
            else:
                frame.append(byte)
        frame.append(FEND)
        return frame

    def process_byte(self, byte):
        if byte == FEND:
            if self.in_frame:
                frame = self.rx_buffer[:]
                self.rx_buffer = bytearray()
                self.in_frame = False
                self.escape = False
                if len(frame) > 0: return frame
            else:
                self.in_frame = True
                self.rx_buffer = bytearray()
                self.escape = False
            return None
        if not self.in_frame: return None
        if self.escape:
            if byte == TFEND: self.rx_buffer.append(FEND)
            elif byte == TFESC: self.rx_buffer.append(FESC)
            else: self.rx_buffer.append(byte)
            self.escape = False
        elif byte == FESC: self.escape = True
        else: self.rx_buffer.append(byte)
        return None

class SerialManager:
    def __init__(self):
        self.serial = None
        self.is_connected = False
        self.lock = threading.Lock()
        self.kiss = KISS()

    def get_ports(self):
        return [port.device for port in serial.tools.list_ports.comports()]

    def connect(self, port, baudrate):
        try:
            self.serial = serial.Serial(port, baudrate, timeout=DEFAULT_TIMEOUT)
            self.is_connected = True
            self.kiss = KISS()
            return True, "Connected"
        except Exception as e:
            self.is_connected = False
            return False, str(e)

    def disconnect(self):
        if self.serial and self.serial.is_open:
            self.serial.close()
        self.is_connected = False
        return True, "Disconnected"

    def send_packet(self, packet_data):
        if not self.is_connected: return False, "Not connected"
        framed_data = self.kiss.frame(packet_data)
        try:
            with self.lock: self.serial.write(framed_data)
            return True, "Sent"
        except Exception as e: return False, str(e)

    def send_bytes_raw(self, raw_data):
        if not self.is_connected: return False, "Not connected"
        try:
            with self.lock: self.serial.write(raw_data)
            return True, "Sent Raw"
        except Exception as e: return False, str(e)

    def read_frames(self):
        frames = []
        raw_data = b''
        if not self.is_connected: return frames, raw_data
        try:
            chunk = self.serial.read(1024)
            if chunk:
                raw_data = chunk
                for byte in chunk:
                    frame = self.kiss.process_byte(byte)
                    if frame: frames.append(frame)
        except Exception: pass
        return frames, raw_data

class PacketBuilder:
    @staticmethod
    def create_csp_header(prio, src, dst, sport, dport):
        # CSP Header Re-structured based on ICD Figure 14
        # Bit layout per ICD:
        # Priority: Bits 31-30 (2 bits)
        # Source Address: Bits 29-25 (5 bits) - comes first
        # Destination Address: Bits 24-20 (5 bits) - comes second
        header = 0
        header |= (prio & 0x03) << 30
        header |= (src & 0x1F) << 25  # Source at bit 25
        header |= (dst & 0x1F) << 20  # Destination at bit 20
        header |= (dport & 0x3F) << 14
        header |= (sport & 0x3F) << 8
        header |= 0x01 # Enable CRC Flag (Bit 0)
        return struct.pack('>I', header)

    @staticmethod
    def create_ccsds_header(apid, seq_count, payload_len):
        target_apid = 0x550
        id_field = (0 << 13) | (1 << 12) | (1 << 11) | (target_apid & 0x7FF)
        seq_field = (3 << 14) | (seq_count & 0x3FFF)
        len_field = payload_len - 1
        return struct.pack('>HHH', id_field, seq_field, len_field)

    @staticmethod
    def create_tc_secondary_header(service, subtype):
        source_id = APID_TC
        return struct.pack('>BBH', service, subtype, source_id)

    class CRC16: # Internal CRC16 for CCSDS
        CRC_TABLE = [
            0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
            0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
            0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
            0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
            0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
            0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
            0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
            0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
            0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
            0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
            0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
            0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
            0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
            0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
            0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
            0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
            0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
            0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
            0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
            0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
            0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
            0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
            0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
            0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
            0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
            0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
            0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
            0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
            0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
            0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
            0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
            0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
        ]
        @staticmethod
        def calc(data):
            crc = 0xFFFF
            for byte in data:
                idx = ((crc >> 8) ^ byte) & 0xFF
                crc = ((crc << 8) ^ PacketBuilder.CRC16.CRC_TABLE[idx]) & 0xFFFF
            return crc

    @staticmethod
    def create_command(seq_count, service, subtype, user_data=b''):
        sec_header = PacketBuilder.create_tc_secondary_header(service, subtype)
        payload = sec_header + user_data
        
        ccsds_header = PacketBuilder.create_ccsds_header(0x550, seq_count, len(payload) + 2)
        packet_no_crc = ccsds_header + payload
        
        crc_val = PacketBuilder.CRC16.calc(packet_no_crc)
        crc_bytes = struct.pack('>H', crc_val)
        
        csp_body = packet_no_crc + crc_bytes  # CCSDS packet (Header + Payload + CRC-16)
        
        csp_header = PacketBuilder.create_csp_header(PRIORITY, SOURCE_ADDRESS, DEST_ADDRESS, SOURCE_PORT, DEST_PORT)
        
        # Calculate CSP CRC32C (Payload Only - Header excluded)
        # Match TMTC.c CspSend: Crc32Check(&ucRawPkt[CSP_HEADER_SIZE], uiLen)
        # csp_body is the payload (CCSDS packet), Header will be added separately
        crc32_val = CRC32C.calc(csp_body)
        crc32_bytes = struct.pack('>I', crc32_val)
        
        return csp_header + csp_body + crc32_bytes

    @staticmethod
    def create_tpvaw_data(roll=0.0, pitch=0.0, yaw=0.0):
        t = time.time()
        
        # Euler to Quaternion (XYZ convention)
        # Roll, Pitch, Yaw in degrees
        cy = math.cos(math.radians(yaw) * 0.5)
        sy = math.sin(math.radians(yaw) * 0.5)
        cp = math.cos(math.radians(pitch) * 0.5)
        sp = math.sin(math.radians(pitch) * 0.5)
        cr = math.cos(math.radians(roll) * 0.5)
        sr = math.sin(math.radians(roll) * 0.5)

        w = cr * cp * cy + sr * sp * sy
        x = sr * cp * cy - cr * sp * sy
        y = cr * sp * cy + sr * cp * sy
        z = cr * cp * sy - sr * sp * cy

        # 108 Bytes structure
        # Assuming 4f corresponds to qx, qy, qz, qw based on previous 0,0,0,1 value (Identity)
        return struct.pack('<8d4i4f3i', 
                           t, t, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                           0, 0, 0, 1, 
                           x, y, z, w, # Quaternion (Q_BODY_WRT_ECI)
                           0, 0, 0)

    @staticmethod
    def create_req_data(seq_num):
        return struct.pack('<HHI', seq_num, 0, 0)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("INTERGRAVITY TECHNOLOGIES / E3T-DUMMY PDHS / DEBUG MONITOR")
        self.root.geometry("1200x700")
        
        # Two Serial Managers
        self.serial_pdhs = SerialManager()
        self.serial_debug = SerialManager() # For debug monitor
        
        self.seq_count = 0
        self.stop_pdhs_thread = False
        self.stop_debug_thread = False

        self._init_ui()

    def _init_ui(self):
        # Main Layout: PanedWindow (Left: PDHS, Right: Debug Monitor)
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ==========================================
        # LEFT PANEL: PDHS Control (Protocol Aware)
        # ==========================================
        left_frame = tk.Frame(main_pane)
        main_pane.add(left_frame, minsize=500)
        
        ttk.Label(left_frame, text="[PDHS] Payload Control (KISS/CSP)", font=("Bold", 10)).pack(pady=5)

        # 1. PDHS Connection
        pdhs_conn_frame = ttk.LabelFrame(left_frame, text="PDHS Connection", padding=5)
        pdhs_conn_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(pdhs_conn_frame, text="Port:").pack(side="left", padx=5)
        self.pdhs_port_cb = ttk.Combobox(pdhs_conn_frame, values=self.serial_pdhs.get_ports(), width=10)
        self.pdhs_port_cb.pack(side="left", padx=5)
        
        ttk.Label(pdhs_conn_frame, text="Baud:").pack(side="left", padx=5)
        self.pdhs_baud_cb = ttk.Combobox(pdhs_conn_frame, values=["9600", "115200", "230400", "460800", "921600"], width=8)
        self.pdhs_baud_cb.set("115200")
        self.pdhs_baud_cb.pack(side="left", padx=5)
        
        self.btn_pdhs_connect = ttk.Button(pdhs_conn_frame, text="Connect", command=self.toggle_pdhs_connection)
        self.btn_pdhs_connect.pack(side="left", padx=5)
        ttk.Button(pdhs_conn_frame, text="Refresh", command=self.refresh_ports).pack(side="left", padx=5)

        # 2. PDHS Commands
        cmd_frame = ttk.LabelFrame(left_frame, text="Commands", padding=5)
        cmd_frame.pack(fill="x", padx=5, pady=5)

        # Test Control
        f1 = ttk.Labelframe(cmd_frame, text="Test Control")
        f1.pack(fill="x", pady=2)
        ttk.Button(f1, text="Start Test (SVC 1,1)", command=self.send_start_test).pack(side="left", padx=2)
        ttk.Button(f1, text="Stop Test (SVC 1,2)", command=self.send_stop_test).pack(side="left", padx=2)
        ttk.Button(f1, text="Set Param (SVC 1,4)", command=self.send_set_param).pack(side="left", padx=2)
        ttk.Button(f1, text="Send ICD Sample (Raw)", command=self.send_icd_sample).pack(side="left", padx=2)

        # Navigation
        f2 = ttk.Labelframe(cmd_frame, text="Navigation (TPVAW)")
        f2.pack(fill="x", pady=2)
        
        ttk.Label(f2, text="R:").pack(side="left")
        self.ent_roll = ttk.Entry(f2, width=5)
        self.ent_roll.insert(0, "0.0")
        self.ent_roll.pack(side="left")
        
        ttk.Label(f2, text="P:").pack(side="left")
        self.ent_pitch = ttk.Entry(f2, width=5)
        self.ent_pitch.insert(0, "0.0")
        self.ent_pitch.pack(side="left")
        
        ttk.Label(f2, text="Y:").pack(side="left")
        self.ent_yaw = ttk.Entry(f2, width=5)
        self.ent_yaw.insert(0, "0.0")
        self.ent_yaw.pack(side="left")

        ttk.Button(f2, text="Send TPVAW", command=self.send_tpvaw).pack(side="left", padx=5)
        
        # Data & Status
        f3 = ttk.Labelframe(cmd_frame, text="Data & Status")
        f3.pack(fill="x", pady=2)
        ttk.Label(f3, text="Seq:").pack(side="left")
        self.seq_entry = ttk.Entry(f3, width=5)
        self.seq_entry.insert(0, "0")
        self.seq_entry.pack(side="left")
        ttk.Button(f3, text="Req Data", command=self.send_req_data).pack(side="left", padx=2)
        ttk.Button(f3, text="Req Status", command=self.send_req_status).pack(side="left", padx=2)
        ttk.Button(f3, text="PING", command=self.send_ping).pack(side="left", padx=2)

        # Sample Data
        f4_sample = ttk.Labelframe(cmd_frame, text="Sample Data")
        f4_sample.pack(fill="x", pady=2)
        ttk.Button(f4_sample, text="PING (data:1)", command=self.send_sample_ping_1).pack(side="left", padx=2)
        ttk.Button(f4_sample, text="PING (data:1234)", command=self.send_sample_ping_1234).pack(side="left", padx=2)
        ttk.Button(f4_sample, text="Req Status (data:0)", command=self.send_sample_req_status).pack(side="left", padx=2)
        ttk.Button(f4_sample, text="Test Start", command=self.send_sample_test_start).pack(side="left", padx=2)
        ttk.Button(f4_sample, text="Test Stop", command=self.send_sample_test_stop).pack(side="left", padx=2)

        # Fault Injection
        f4 = ttk.Labelframe(cmd_frame, text="Fault Injection (Negative Test)")
        f4.pack(fill="x", pady=2)
        ttk.Button(f4, text="Send Bad CRC", command=self.send_bad_crc).pack(side="left", padx=2)
        ttk.Button(f4, text="Send Invalid TC (SVC=99)", command=self.send_invalid_tc).pack(side="left", padx=2)

        # 3. PDHS Log
        pdhs_log_frame = ttk.LabelFrame(left_frame, text="PDHS Protocol Log", padding=5)
        pdhs_log_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Buttons FIRST
        pdhs_btn_frame = tk.Frame(pdhs_log_frame)
        pdhs_btn_frame.pack(side="bottom", fill="x", pady=2)
        ttk.Button(pdhs_btn_frame, text="Clear Log", command=lambda: self.clear_log(self.pdhs_log_text)).pack(side="right", padx=5)

        # Text Area fills remaining
        self.pdhs_log_text = tk.Text(pdhs_log_frame, height=10, state="disabled", font=("Consolas", 9))
        self.pdhs_log_text.pack(fill="both", expand=True, side="left")
        sb1 = ttk.Scrollbar(pdhs_log_frame, command=self.pdhs_log_text.yview)
        sb1.pack(side="right", fill="y")
        self.pdhs_log_text.config(yscrollcommand=sb1.set)

        # ==========================================
        # RIGHT PANEL: Serial Debug Monitor (Raw)
        # ==========================================
        right_frame = tk.Frame(main_pane)
        main_pane.add(right_frame, minsize=400)
        
        ttk.Label(right_frame, text="[Debug] Serial Monitor (Raw ASCII/Hex)", font=("Bold", 10)).pack(pady=5)

        # 1. Debug Connection
        dbg_conn_frame = ttk.LabelFrame(right_frame, text="Debug Port Connection", padding=5)
        dbg_conn_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(dbg_conn_frame, text="Port:").pack(side="left", padx=5)
        self.debug_port_cb = ttk.Combobox(dbg_conn_frame, values=self.serial_pdhs.get_ports(), width=10)
        self.debug_port_cb.pack(side="left", padx=5)
        
        ttk.Label(dbg_conn_frame, text="Baud:").pack(side="left", padx=5)
        self.debug_baud_cb = ttk.Combobox(dbg_conn_frame, values=["9600", "115200", "230400", "460800", "921600"], width=8)
        self.debug_baud_cb.set("115200")
        self.debug_baud_cb.pack(side="left", padx=5)
        
        self.btn_debug_connect = ttk.Button(dbg_conn_frame, text="Connect", command=self.toggle_debug_connection)
        self.btn_debug_connect.pack(side="left", padx=5)
        ttk.Button(dbg_conn_frame, text="Refresh", command=self.refresh_ports).pack(side="left", padx=5)

        # 2. Debug Log
        dbg_log_frame = ttk.LabelFrame(right_frame, text="Debug Output", padding=5)
        dbg_log_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Pack Buttons FIRST at the bottom so they are always visible
        btn_frame = tk.Frame(dbg_log_frame)
        btn_frame.pack(side="bottom", fill="x", pady=2)
        self.chk_hex_var = tk.IntVar()
        ttk.Checkbutton(btn_frame, text="View as Hex", variable=self.chk_hex_var).pack(side="left")
        ttk.Button(btn_frame, text="Clear Log", command=lambda: self.clear_log(self.debug_log_text)).pack(side="right", padx=5)

        # Pack Text Area to fill remaining space
        self.debug_log_text = tk.Text(dbg_log_frame, state="disabled", font=("Consolas", 9)) # Removed bg="#f0f0f0"
        self.debug_log_text.pack(fill="both", expand=True, side="left")
        sb2 = ttk.Scrollbar(dbg_log_frame, command=self.debug_log_text.yview)
        sb2.pack(side="right", fill="y")
        self.debug_log_text.config(yscrollcommand=sb2.set)

    # --- Utilities ---
    def refresh_ports(self):
        ports = self.serial_pdhs.get_ports()
        self.pdhs_port_cb['values'] = ports
        self.debug_port_cb['values'] = ports
        if ports:
            self.pdhs_port_cb.current(0)
            if len(ports) > 1: self.debug_port_cb.current(1)
            
    def clear_log(self, text_widget):
        text_widget.config(state="normal")
        text_widget.delete(1.0, "end")
        text_widget.config(state="disabled")

    def log(self, msg, target="pdhs"):
        ts = time.strftime("%H:%M:%S")
        widget = self.pdhs_log_text if target == "pdhs" else self.debug_log_text
        widget.config(state="normal")
        widget.insert("end", f"[{ts}] {msg}\n")
        widget.see("end")
        widget.config(state="disabled")

    # --- PDHS Connection ---
    def toggle_pdhs_connection(self):
        if not self.serial_pdhs.is_connected:
            port = self.pdhs_port_cb.get()
            try: baud = int(self.pdhs_baud_cb.get())
            except: return
            if not port: return
            success, msg = self.serial_pdhs.connect(port, baud)
            if success:
                self.btn_pdhs_connect.config(text="Disconnect")
                self.log(f"PDHS Connected: {port}", "pdhs")
                self.stop_pdhs_thread = False
                threading.Thread(target=self.listen_pdhs, daemon=True).start()
            else: messagebox.showerror("Err", msg)
        else:
            self.stop_pdhs_thread = True
            self.serial_pdhs.disconnect()
            self.btn_pdhs_connect.config(text="Connect")
            self.log("PDHS Disconnected", "pdhs")

    # --- Debug Connection ---
    def toggle_debug_connection(self):
        if not self.serial_debug.is_connected:
            port = self.debug_port_cb.get()
            try: baud = int(self.debug_baud_cb.get())
            except: return
            if not port: return
            success, msg = self.serial_debug.connect(port, baud)
            if success:
                self.btn_debug_connect.config(text="Disconnect")
                self.log(f"Debug Connected: {port}", "debug")
                self.stop_debug_thread = False
                threading.Thread(target=self.listen_debug, daemon=True).start()
            else: messagebox.showerror("Err", msg)
        else:
            self.stop_debug_thread = True
            self.serial_debug.disconnect()
            self.btn_debug_connect.config(text="Connect")
            self.log("Debug Disconnected", "debug")

    # --- Command Handlers (Use self.serial_pdhs) ---
    def send_cmd(self, service, subtype, name, user_data=b''):
        packet = PacketBuilder.create_command(self.seq_count, service, subtype, user_data)
        self.seq_count = (self.seq_count + 1) % 16384
        if self.serial_pdhs.send_packet(packet)[0]:
            # Log both original packet and KISS-framed data
            framed_data = self.serial_pdhs.kiss.frame(packet)
            self.log(f"TX [{name}] (Packet): {binascii.hexlify(packet).decode().upper()}", "pdhs")
            self.log(f"TX [{name}] (KISS): {binascii.hexlify(framed_data).decode().upper()}", "pdhs")
        else:
            self.log("TX Error", "pdhs")

    def send_bytes_raw(self, raw_data): # Used by ICD Sample
        if not self.serial_pdhs.is_connected: return False, "Not connected"
        try:
            with self.serial_pdhs.lock: self.serial_pdhs.serial.write(raw_data)
            return True, "Sent Raw"
        except Exception as e: return False, str(e)

    # ... (Command Wrapper Functions: send_start_test, etc. - Keep as is, just ensure they call updated send_cmd) ...
    def send_start_test(self): self.send_cmd(SVC_TEST, MSG_START_TEST, "START_TEST")
    def send_stop_test(self): self.send_cmd(SVC_TEST, MSG_STOP_TEST, "STOP_TEST")
    def send_set_param(self): self.send_cmd(SVC_TEST, MSG_SET_PARAM, "SET_PARAM")
    def send_tpvaw(self):
        try:
            r = float(self.ent_roll.get())
            p = float(self.ent_pitch.get())
            y = float(self.ent_yaw.get())
        except:
            r, p, y = 0.0, 0.0, 0.0
            
        data = PacketBuilder.create_tpvaw_data(r, p, y)
        self.send_cmd(SVC_TEST, MSG_SEND_TPVAW, f"SEND_TPVAW(R={r},P={p},Y={y})", data)
    def send_req_data(self):
        try: seq = int(self.seq_entry.get())
        except: return
        data = PacketBuilder.create_req_data(seq)
        self.send_cmd(SVC_TEST, MSG_REQ_DATA, f"REQ_DATA(Seq={seq})", data)
    def send_req_status(self): self.send_cmd(SVC_STATUS, MSG_REQ_STATUS, "REQ_STATUS")
    def send_ping(self): self.send_cmd(SVC_CONN, MSG_PING_REQ, "PING")
    def send_icd_sample(self):
        hex_str = "c0 00 4c d2 b4 00 1d 00 db dc 00 00 09 14 01 02 3b 01 00 00 00 20 52 ba 37 46 37 c0"
        try:
            raw = bytes.fromhex(hex_str.replace(" ", ""))
            if self.send_bytes_raw(raw)[0]: self.log(f"TX [ICD Sample]: {hex_str.upper()}", "pdhs")
        except: pass

    def send_sample_ping_1(self):
        hex_str = "c0 00 4d 32 b5 00 1d 50 db dc 00 00 09 14 01 02 3b 01 00 00 00 6c 36 c3 93 2e 35 c0"
        try:
            raw = bytes.fromhex(hex_str.replace(" ", ""))
            if self.send_bytes_raw(raw)[0]: self.log(f"TX [Sample PING (data:1)]: {hex_str.upper()}", "pdhs")
        except Exception as e: self.log(f"TX [Sample PING (data:1)] Error: {e}", "pdhs")

    def send_sample_ping_1234(self):
        hex_str = "c0 00 4d 32 b6 00 1d 50 db dc 00 00 09 14 01 02 3b d2 04 00 00 83 29 17 01 a9 15 c0"
        try:
            raw = bytes.fromhex(hex_str.replace(" ", ""))
            if self.send_bytes_raw(raw)[0]: self.log(f"TX [Sample PING (data:1234)]: {hex_str.upper()}", "pdhs")
        except Exception as e: self.log(f"TX [Sample PING (data:1234)] Error: {e}", "pdhs")

    def send_sample_req_status(self):
        hex_str = "c0 00 4d 32 b7 00 1d 50 db dc 00 00 09 05 01 02 3b 00 00 00 00 60 e5 79 5d 58 ae c0"
        try:
            raw = bytes.fromhex(hex_str.replace(" ", ""))
            if self.send_bytes_raw(raw)[0]: self.log(f"TX [Sample Req Status (data:0)]: {hex_str.upper()}", "pdhs")
        except Exception as e: self.log(f"TX [Sample Req Status (data:0)] Error: {e}", "pdhs")

    def send_sample_test_start(self):
        hex_str = "c0 00 4d 32 b8 00 1d 00 db dc 00 00 05 01 01 02 3b 75 4c 07 f8 a9 3c c0"
        try:
            raw = bytes.fromhex(hex_str.replace(" ", ""))
            if self.send_bytes_raw(raw)[0]: self.log(f"TX [Sample Test Start]: {hex_str.upper()}", "pdhs")
        except Exception as e: self.log(f"TX [Sample Test Start] Error: {e}", "pdhs")

    def send_sample_test_stop(self):
        hex_str = "c0 00 4d 32 b9 00 1d 50 db dc 00 00 05 01 02 02 3b 20 3b 59 5d d9 3c c0"
        try:
            raw = bytes.fromhex(hex_str.replace(" ", ""))
            if self.send_bytes_raw(raw)[0]: self.log(f"TX [Sample Test Stop]: {hex_str.upper()}", "pdhs")
        except Exception as e: self.log(f"TX [Sample Test Stop] Error: {e}", "pdhs")

    def send_bad_crc(self):
        # Create a valid packet first (e.g. PING)
        packet = PacketBuilder.create_command(self.seq_count, SVC_CONN, MSG_PING_REQ, b'BAD_CRC')
        self.seq_count = (self.seq_count + 1) % 16384
        
        # Corrupt the last byte (CRC is at the end)
        bad_packet = bytearray(packet)
        bad_packet[-1] ^= 0xFF # Invert last byte
        
        if self.serial_pdhs.send_packet(bad_packet)[0]:
            self.log(f"TX [BAD CRC]: {binascii.hexlify(bad_packet).decode().upper()}", "pdhs")
        else:
            self.log("TX Error", "pdhs")

    def send_invalid_tc(self):
        # Send undefined Service/Subtype (SVC=99, MSG=99)
        packet = PacketBuilder.create_command(self.seq_count, 99, 99, b'INVALID_TC')
        self.seq_count = (self.seq_count + 1) % 16384
        
        if self.serial_pdhs.send_packet(packet)[0]:
            self.log(f"TX [INV TC]: {binascii.hexlify(packet).decode().upper()}", "pdhs")
        else:
            self.log("TX Error", "pdhs")

    # --- Listener Threads ---
    def listen_pdhs(self):
        while not self.stop_pdhs_thread and self.serial_pdhs.is_connected:
            frames, raw = self.serial_pdhs.read_frames()
            for frame in frames:
                self.process_rx_frame(frame)
            time.sleep(0.01)

    def listen_debug(self):
        while not self.stop_debug_thread and self.serial_debug.is_connected:
            try:
                # Read raw bytes
                data = self.serial_debug.serial.read(self.serial_debug.serial.in_waiting or 1)
                if data:
                    if self.chk_hex_var.get():
                        msg = binascii.hexlify(data).decode().upper()
                    else:
                        msg = data.decode('utf-8', errors='replace')
                    
                    self.root.after(0, self.log_debug_raw, msg)
            except: pass
            time.sleep(0.01)

    def log_debug_raw(self, msg):
        self.debug_log_text.config(state="normal")
        self.debug_log_text.insert("end", msg)
        self.debug_log_text.see("end")
        self.debug_log_text.config(state="disabled")

    def process_rx_frame(self, frame):
        # [Fix] Strip KISS Command Byte (0x00) if present
        original_frame_len = len(frame)
        if len(frame) > 0 and frame[0] == 0x00: 
            frame = frame[1:]
            self.root.after(0, self.log, f"RX [KISS Decoded] Len: {original_frame_len} -> {len(frame)} (Stripped Cmd Byte)", "pdhs")
        
        # Log raw frame data for debugging
        hex_dump = binascii.hexlify(frame).decode().upper()
        if len(hex_dump) > 80: hex_dump = hex_dump[:80] + "..."
        self.root.after(0, self.log, f"RX [Raw Frame] Len: {len(frame)} Data: {hex_dump}", "pdhs")

        # 1. Minimum Length Check
        if len(frame) < 26:
            self.root.after(0, self.log, f"RX [Err: Short Packet] Len: {len(frame)} (Min 26)", "pdhs")
            return

        # 2. CSP CRC-32C Verification
        # Match TMTC.c CspReceive: Calculate CRC over Payload Only (Header excluded)
        # TMTC.c: uiPayloadLen = siLen - CSP_CRC32_SIZE;
        #         uiCalcCrc = Crc32Check(&pPacket[CSP_HEADER_SIZE], uiPayloadLen - CSP_HEADER_SIZE);
        # This means: CRC is calculated over [Header(4) + Payload] excluding Header, i.e., Payload only
        recv_crc_bytes = frame[-4:]
        recv_crc = struct.unpack('>I', recv_crc_bytes)[0]
        
        valid_start_idx = -1
        
        # Limit search to first 500 bytes to avoid performance hit on huge garbage
        search_limit = min(len(frame) - 8, 500) 
        
        for i in range(search_limit):
            # Check if this position has a valid CSP packet
            # Payload = frame[i+4:-4] (skip Header(4) and CRC(4))
            if len(frame) - i >= 8:  # Min length: Header(4) + Payload(>=0) + CRC(4)
                candidate_payload = frame[i+4:-4]
                if len(candidate_payload) > 0:  # Payload must exist
                    calc_crc = CRC32C.calc(candidate_payload)
                    if calc_crc == recv_crc:
                        valid_start_idx = i
                        break

        if valid_start_idx != -1:
            if valid_start_idx > 0:
                pass # self.log(f"RX [Info] Sync Found at Offset {valid_start_idx}", "pdhs")
            frame = frame[valid_start_idx:]
        else:
             # If CRC32C fails, try to calculate expected CRC for logging
             if len(frame) >= 8:
                 candidate_payload = frame[4:-4]
                 calc_crc = CRC32C.calc(candidate_payload) if len(candidate_payload) > 0 else 0
             else:
                 calc_crc = 0
             hex_dump = binascii.hexlify(frame).decode().upper()
             if len(hex_dump) > 100: hex_dump = hex_dump[:100] + "..."
             
             self.root.after(0, self.log, f"RX [Err: CRC Fail] Recv:{recv_crc:08X} Calc:{calc_crc:08X} Dump:{hex_dump}", "pdhs")
             return

        # 3. Parse CSP Header before stripping
        # frame is now aligned to start of CSP Header
        csp_header_raw = frame[0:4]
        csp_header = struct.unpack('>I', csp_header_raw)[0]
        
        # Extract CSP header fields per ICD:
        # Priority: Bits 31-30
        # Source Address: Bits 29-25 (comes first)
        # Destination Address: Bits 24-20 (comes second)
        csp_prio = (csp_header >> 30) & 0x03
        csp_src_addr = (csp_header >> 25) & 0x1F  # Source at bit 25
        csp_dst_addr = (csp_header >> 20) & 0x1F   # Destination at bit 20
        csp_dport = (csp_header >> 14) & 0x3F
        csp_sport = (csp_header >> 8) & 0x3F
        
        # Log CSP header parsing for debugging
        self.root.after(0, self.log, 
            f"RX [CSP Header] 0x{csp_header:08X} Prio:{csp_prio} Src:{csp_src_addr} Dst:{csp_dst_addr} SPort:{csp_sport} DPort:{csp_dport}", 
            "pdhs")
        
        # 4. Strip CRC & CSP Header for Parsing
        # packet_content is [CCSDS Header] + [Sec Header] + [User Data] + [CRC-16]
        packet_content = frame[4:-4]
        frame = packet_content
        
        # 5. Header Parsing
        # CCSDS Header: 6 bytes
        ccsds_raw = frame[0:6]
        if len(frame) < 10:
            self.root.after(0, self.log, f"RX [Err: Too Short] Len: {len(frame)}", "pdhs")
            return
        
        try:
            ccsds_hdr = struct.unpack('>HHH', ccsds_raw)
            apid = ccsds_hdr[0] & 0x7FF
            packet_type = (ccsds_hdr[0] >> 13) & 0x01  # Type bit: 0=TM, 1=TC
            
            # Determine secondary header size: TC=4 bytes, TM=12 bytes
            # Match TMTC.c: TC uses CCSDS_TC_SEC_HEADER_SIZE (4), TM uses CCSDS_TM_SEC_HEADER_SIZE (12)
            if packet_type == 1:  # TC (Telecommand)
                sec_header_size = 4
                if len(frame) < 6 + sec_header_size + 2:  # Min: Pri(6) + Sec(4) + CRC(2)
                    self.root.after(0, self.log, f"RX [Err: TC Too Short] Len: {len(frame)}", "pdhs")
                    return
                tc_sec_raw = frame[6:10]
                svc, sub, src = struct.unpack('>BBH', tc_sec_raw)
                # Calculate User Data Length: Total - Primary Header(6) - Secondary Header(4) - CRC-16(2)
                # Match TMTC.c: uiUserDataLen = uiLen - (CCSDS_PRI_HEADER_SIZE + CCSDS_TC_SEC_HEADER_SIZE + 2)
                user_data_len = len(frame) - (6 + 4 + 2)  # Primary(6) + Secondary(4) + CRC-16(2)
                user_data = frame[10:10+user_data_len] if user_data_len > 0 else b''
            else:  # TM (Telemetry)
                sec_header_size = 12
                if len(frame) < 6 + sec_header_size + 2:  # Min: Pri(6) + Sec(12) + CRC(2)
                    self.root.after(0, self.log, f"RX [Err: TM Too Short] Len: {len(frame)}", "pdhs")
                    return
                tm_sec_raw = frame[6:18]
                svc, sub, src, t_sec, t_sub, flags, spare = struct.unpack('>BBHIHBB', tm_sec_raw)
                # Calculate User Data Length: Total - Primary Header(6) - Secondary Header(12) - CRC-16(2)
                user_data_len = len(frame) - (6 + 12 + 2)  # Primary(6) + Secondary(12) + CRC-16(2)
                user_data = frame[18:18+user_data_len] if user_data_len > 0 else b''
            
            msg_name = "Unknown"
            status_tag = ""

            if svc == SVC_CONN and sub == MSG_PING_REP: msg_name = "PONG (Ping Reply)"
            elif svc == SVC_STATUS and sub == MSG_REP_STATUS:
                msg_name = "STATUS REPLY"
                
                # 데이터가 6바이트 이상이면 구조체(6바이트, Packed)만 사용하여 디코딩
                if len(user_data) >= 6:
                    try:
                        # PayloadStatus_t Parsing (Packed: 6 bytes)
                        # UInt8(Status), SInt16(Temp), UInt8(IMU), UInt8(GPS), UInt8(Trk)
                        # unpack format '<BhBBB' consumes 6 bytes
                        p_stat, b_temp_raw, imu_st, gps_st, trk_st = struct.unpack('<BhBBB', user_data[:6])
                        
                        st_str = {0: "Idle", 1: "Testing"}.get(p_stat, f"Unknown({p_stat})")
                        temp_c = b_temp_raw * 0.1
                        imu_str = "Normal" if imu_st == 0 else "Fault"
                        gps_str = "Normal" if gps_st == 0 else "Fault"
                        
                        status_tag += f" [St:{st_str} T:{temp_c:.1f}C IMU:{imu_str} GPS:{gps_str} Trk:{trk_st}]"
                    except Exception as e:
                        status_tag += f" [Decode Err: {e}]"
                else:
                    status_tag += f" [Warn: Short Len {len(user_data)}]"

            elif svc == SVC_TEST:
                if sub == MSG_REPORT_END: msg_name = "TEST END REPORT"
                elif sub == MSG_REQ_DATA:
                    msg_name = "TEST DATA REPLY"
                    # TestData_t Parsing (Total 100 bytes)
                    # Use >= 100 check to ignore extra CRC bytes if any
                    if len(user_data) >= 100:
                        try:
                            # Format: < II dd ffff BBBx fff fff fff 5I
                            # Modified Status: mode(1), error(1), NrSV(1), align(1)
                            (gpsWeek, gpsTime, lat, lon, alt, vN, vE, vU, 
                             mode, error, nrSv, 
                             gX, gY, gZ, 
                             aX, aY, aZ, 
                             roll, pitch, yaw, 
                             r1, r2, r3, r4, r5) = struct.unpack('<IIddffffBBBxfffffffff5I', user_data[:100])
                             
                            status_tag += (f" [GPS:{gpsWeek}/{gpsTime} Pos:{lat:.6f},{lon:.6f} Alt:{alt:.1f}]"
                                           f" [Vel:{vN:.1f},{vE:.1f},{vU:.1f} Mode:{mode} Err:{error} SV:{nrSv}]"
                                           f" [Gyro:{gX:.2f},{gY:.2f},{gZ:.2f} Acc:{aX:.2f},{aY:.2f},{aZ:.2f}]"
                                           f" [Att:{roll:.1f},{pitch:.1f},{yaw:.1f}]")
                        except Exception as e:
                            status_tag += f" [Decode Err: {e}]"
                    else:
                        status_tag += f" [Warn: Short Len {len(user_data)}]"

                elif sub >= 10 and sub <= 127: msg_name = f"TEST DATA (Sub={sub})"
                elif sub in [MSG_START_TEST, MSG_STOP_TEST, MSG_SET_PARAM, MSG_SEND_TPVAW]:
                    if user_data_len == 4:
                        msg_name = "DEFAULT RESPONSE"
                        ack_data = user_data
                    elif user_data_len == 6:
                        msg_name = "DEFAULT RESPONSE"
                        ack_data = user_data[:-2] 
                    else:
                        msg_name = f"CMD REPLY (Sub={sub})"
                        ack_data = None
                        status_tag += f" [Warn: Inv Len {user_data_len}]"

                    if ack_data:
                        ack = ack_data[0]
                        code = struct.unpack('<I', ack_data[1:4] + b'\x00')[0] & 0xFFFFFF
                        ack_str = "ACK (Success)" if ack == 0xFF else f"NACK (Fail)"
                        status_tag += f" [{ack_str} Code:0x{code:06X}]"
            
            # PDHS uses APID 0x023B, IGNU sends TM with 0x023B - both are valid
            if apid != 0x550 and apid != 0x23B: status_tag += f" [Warn: APID {apid:03X}]"
            
            # Validate CSP header addresses
            # Expected: src=19 (IGNU), dst=6 (PDHS) when receiving
            if csp_src_addr != DEST_ADDRESS:  # DEST_ADDRESS=19 (IGNU is the sender)
                status_tag += f" [Warn: CSP Src Addr {csp_src_addr} != {DEST_ADDRESS}]"
            if csp_dst_addr != SOURCE_ADDRESS:  # SOURCE_ADDRESS=6 (PDHS is the receiver)
                status_tag += f" [Warn: CSP Dst Addr {csp_dst_addr} != {SOURCE_ADDRESS}]"
            
            msg = f"RX [{msg_name}] SVC:{svc}-{sub} SRC:{src} CSP:[{csp_src_addr}->{csp_dst_addr}] {status_tag}"
            if user_data:
                hex_dump = binascii.hexlify(user_data).decode().upper()
                if len(hex_dump) > 40: hex_dump = hex_dump[:40] + "..."
                msg += f" Data:{hex_dump}"

            self.root.after(0, self.log, msg, "pdhs")
            
        except Exception as e:
            self.root.after(0, self.log, f"RX [Err: Parse Fail] {str(e)}", "pdhs")

if __name__ == "__main__":
    try:
        print("[DEBUG] Starting PDHS Application...")
        root = tk.Tk()
        print("[DEBUG] Tkinter root initialized.")
        app = App(root)
        print("[DEBUG] App initialized. Entering mainloop...")
        root.mainloop()
        print("[DEBUG] Mainloop exited normally.")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Application Crashed: {e}")
        traceback.print_exc()
        print("\nPress Enter to close window...")
        input()
