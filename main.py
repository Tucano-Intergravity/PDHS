import tkinter as tk
from tkinter import ttk, messagebox
import serial
import serial.tools.list_ports
import threading
import time
import struct
import binascii

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

class CRC16:
    # CRC Lookup Table (Polynomial: 0x1021)
    # Ported from provided C code
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
        crc = 0xFFFF # Initial Seed
        for byte in data:
            # (crc << 8) ^ Table[(crc >> 8) ^ data[i]]
            # Need to mask to 16 bits to simulate uint16 behavior
            idx = ((crc >> 8) ^ byte) & 0xFF
            crc = ((crc << 8) ^ CRC16.CRC_TABLE[idx]) & 0xFFFF
        return crc

# class CRC32:
#     @staticmethod
#     def calc(data: bytes) -> int:
#         """
#         Calculate CRC-32 (IEEE 802.3)
#         Polynomial: 0xEDB88320 (Reflected) / 0x04C11DB7 (Normal)
#         Uses zlib.crc32 which implements IEEE 802.3 standard.
#         """
#         import zlib
#         return zlib.crc32(data) & 0xFFFFFFFF

class CRC32C:
    # Castagnoli implementation
    @staticmethod
    def calc(data: bytes) -> int:
        # ... (Previous implementation)
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
        # Combine Command Byte + User Data
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
        # Prio(2) | Src(5) | Dest(5) | DPort(6) | SPort(6) | Res(4) | Flags(4)
        # Offset: 30(2) | 25(5) | 20(5) | 14(6) | 8(6) | 4(4) | 0(4)
        
        header = 0
        header |= (prio & 0x03) << 30
        header |= (dst & 0x1F) << 25  # Destination이 25 bit (MSB 쪽)
        header |= (src & 0x1F) << 20  # Source가 20 bit
        header |= (dport & 0x3F) << 14
        header |= (sport & 0x3F) << 8
        # Reserved (4 bits) at 4 - Always 0
        # Flags (4 bits) at 0
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

    @staticmethod
    def create_command(seq_count, service, subtype, user_data=b''):
        sec_header = PacketBuilder.create_tc_secondary_header(service, subtype)
        payload = sec_header + user_data
        
        ccsds_header = PacketBuilder.create_ccsds_header(0x550, seq_count, len(payload) + 2)
        packet_no_crc = ccsds_header + payload
        
        crc_val = CRC16.calc(packet_no_crc)
        crc_bytes = struct.pack('>H', crc_val)
        
        # CSP Packet Body = CCSDS Packet (with CRC16)
        csp_body = packet_no_crc + crc_bytes
        
        csp_header = PacketBuilder.create_csp_header(PRIORITY, SOURCE_ADDRESS, DEST_ADDRESS, SOURCE_PORT, DEST_PORT)
        
        # Calculate CSP CRC32C (Payload Only)
        # Updated to match IGNU Firmware behavior: Header excluded from CRC calculation
        # Payload = CCSDS Packet (with CRC16)
        crc32_val = CRC32C.calc(csp_body)
        crc32_bytes = struct.pack('>I', crc32_val)
        
        # CSP Packet = Header + Payload + CRC32
        return csp_header + csp_body + crc32_bytes

    @staticmethod
    def create_tpvaw_data():
        t = time.time()
        # Reverted to 108 Bytes based on provided C struct
        # 8(time) + 8(timestamp) + 24(pos) + 24(vel) + 16(q_body) + 16(q_ecef) + 12(rate) = 108 bytes
        return struct.pack('<ddddddddiiiiffffiii', 
                           t, t,                # Time (double), Timestamp (double)
                           0.0, 0.0, 0.0,       # Pos
                           0.0, 0.0, 0.0,       # Vel
                           0, 0, 0, 1,          # Q Body
                           0.0, 0.0, 0.0, 1.0,  # Q ECEF
                           0, 0, 0              # Rate
                           )

    @staticmethod
    def create_req_data(seq_num):
        return struct.pack('<HHI', seq_num, 0, 0)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("E3T-PDHS")
        self.root.geometry("1000x700")
        
        self.serial_mgr = SerialManager()
        self.seq_count = 0
        self.stop_thread = False
        self._init_ui()

    def _init_ui(self):
        # 1. Connection Frame
        conn_frame = ttk.LabelFrame(self.root, text="Connection", padding=5)
        conn_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(conn_frame, text="Port:").pack(side="left", padx=5)
        self.port_cb = ttk.Combobox(conn_frame, values=self.serial_mgr.get_ports(), width=10)
        self.port_cb.pack(side="left", padx=5)
        self.baud_entry = ttk.Entry(conn_frame, width=8)
        self.baud_entry.insert(0, "115200")
        self.baud_entry.pack(side="left", padx=5)
        
        self.btn_connect = ttk.Button(conn_frame, text="Connect", command=self.toggle_connection)
        self.btn_connect.pack(side="left", padx=5)
        ttk.Button(conn_frame, text="Refresh", command=self.refresh_ports).pack(side="left", padx=5)

        # 2. Command Area (Split into columns)
        cmd_main_frame = tk.Frame(self.root)
        cmd_main_frame.pack(fill="x", padx=5, pady=5)

        # Col 1: Test Control
        f1 = ttk.LabelFrame(cmd_main_frame, text="Test Control", padding=5)
        f1.pack(side="left", fill="y", padx=5, anchor="n")
        
        ttk.Button(f1, text="Start Test (SVC 1,1)", command=self.send_start_test).pack(fill="x", pady=2)
        ttk.Button(f1, text="Stop Test (SVC 1,2)", command=self.send_stop_test).pack(fill="x", pady=2)
        ttk.Button(f1, text="Set Test Param (SVC 1,4)", command=self.send_set_param).pack(fill="x", pady=2)
        ttk.Button(f1, text="Send ICD Sample (Raw)", command=self.send_icd_sample).pack(fill="x", pady=2)

        # Col 2: Navigation
        f2 = ttk.LabelFrame(cmd_main_frame, text="Navigation", padding=5)
        f2.pack(side="left", fill="y", padx=5, anchor="n")
        
        ttk.Button(f2, text="Send TPVAW (SVC 1,5)", command=self.send_tpvaw).pack(fill="x", pady=2)
        ttk.Label(f2, text="(Sends Dummy Data)").pack()

        # Col 3: Data Retrieval
        f3 = ttk.LabelFrame(cmd_main_frame, text="Data Retrieval", padding=5)
        f3.pack(side="left", fill="y", padx=5, anchor="n")
        
        self.seq_entry = ttk.Entry(f3, width=10)
        self.seq_entry.insert(0, "0")
        self.seq_entry.pack(pady=2)
        ttk.Label(f3, text="Seq Num").pack()
        ttk.Button(f3, text="Request Test Data (SVC 1,10)", command=self.send_req_data).pack(fill="x", pady=2)

        # Col 4: Status & Maint
        f4 = ttk.LabelFrame(cmd_main_frame, text="Status & Maint", padding=5)
        f4.pack(side="left", fill="y", padx=5, anchor="n")
        
        ttk.Button(f4, text="PING (SVC 20,1)", command=self.send_ping).pack(fill="x", pady=2)
        ttk.Button(f4, text="Req Status (SVC 5,1)", command=self.send_req_status).pack(fill="x", pady=2)

        # 3. Log
        log_frame = ttk.LabelFrame(self.root, text="Log", padding=5)
        log_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.log_text = tk.Text(log_frame, height=15, state="disabled", font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True, side="left")
        
        sb = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        sb.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=sb.set)
        
        ttk.Button(log_frame, text="Clear", command=self.clear_log).pack(side="bottom", anchor="e")

    # --- Command Handlers ---
    def send_start_test(self):
        # User Data: Parameters (Variable). Sending empty for now as generic start
        self.send_cmd(SVC_TEST, MSG_START_TEST, "START_TEST")

    def send_stop_test(self):
        # User Data: None
        self.send_cmd(SVC_TEST, MSG_STOP_TEST, "STOP_TEST")

    def send_set_param(self):
        # User Data: Params. Sending empty or dummy
        self.send_cmd(SVC_TEST, MSG_SET_PARAM, "SET_PARAM")

    def send_icd_sample(self):
        # Raw Hex from ICD
        hex_str = "c0 00 4c d2 b4 00 1d 00 db dc 00 00 09 14 01 02 3b 01 00 00 00 20 52 ba 37 46 37 c0"
        try:
            raw_data = bytes.fromhex(hex_str.replace(" ", ""))
            if self.serial_mgr.send_bytes_raw(raw_data)[0]:
                self.log(f"TX [ICD Sample]: {hex_str.upper()}")
            else:
                self.log("TX Error")
        except Exception as e:
            self.log(f"Error parsing hex: {e}")

    def send_tpvaw(self):
        # User Data: SendTpvawData_t
        data = PacketBuilder.create_tpvaw_data()
        self.send_cmd(SVC_TEST, MSG_SEND_TPVAW, "SEND_TPVAW", data)

    def send_req_data(self):
        try:
            seq = int(self.seq_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid Seq Num")
            return
        data = PacketBuilder.create_req_data(seq)
        # Using 10 as default Subtype for Req Data
        self.send_cmd(SVC_TEST, MSG_REQ_DATA, f"REQ_DATA(Seq={seq})", data)

    def send_req_status(self):
        self.send_cmd(SVC_STATUS, MSG_REQ_STATUS, "REQ_STATUS")

    def send_ping(self):
        self.send_cmd(SVC_CONN, MSG_PING_REQ, "PING")

    # --- Utilities ---
    def refresh_ports(self):
        self.port_cb['values'] = self.serial_mgr.get_ports()
        if self.port_cb['values']: self.port_cb.current(0)
            
    def clear_log(self):
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, "end")
        self.log_text.config(state="disabled")

    def toggle_connection(self):
        if not self.serial_mgr.is_connected:
            port = self.port_cb.get()
            try: baud = int(self.baud_entry.get())
            except: return
            if not port: return
            success, msg = self.serial_mgr.connect(port, baud)
            if success:
                self.btn_connect.config(text="Disconnect")
                self.log(f"Connected to {port}")
                self.stop_thread = False
                threading.Thread(target=self.listen_serial, daemon=True).start()
            else: messagebox.showerror("Err", msg)
        else:
            self.stop_thread = True
            self.serial_mgr.disconnect()
            self.btn_connect.config(text="Connect")
            self.log("Disconnected")

    def send_cmd(self, service, subtype, name, user_data=b''):
        packet = PacketBuilder.create_command(self.seq_count, service, subtype, user_data)
        self.seq_count = (self.seq_count + 1) % 16384
        if self.serial_mgr.send_packet(packet)[0]:
            self.log(f"TX [{name}]: {binascii.hexlify(packet).decode().upper()}")
        else:
            self.log("TX Error")

    def listen_serial(self):
        while not self.stop_thread and self.serial_mgr.is_connected:
            frames, raw = self.serial_mgr.read_frames()
            if raw:
                # Optional: Uncomment to see too much data
                # self.root.after(0, self.log, f"RAW RX: {binascii.hexlify(raw).decode().upper()}")
                pass
            for frame in frames:
                self.process_rx_frame(frame)
            time.sleep(0.01)

    def process_rx_frame(self, frame):
        # [Fix] Strip KISS Command Byte (0x00) if present
        if len(frame) > 0 and frame[0] == 0x00:
            frame = frame[1:]

        # 1. Minimum Length Check
        # CSP Header(4) + CSP CRC(4) = 8 bytes min
        if len(frame) < 8:
            self.root.after(0, self.log, f"RX [Err: Short Packet] Len: {len(frame)} (Min 8)")
            return

        # 2. CSP CRC-32C Verification
        # Checksum covers Header + Payload (Header Included) based on RX debug result
        # frame structure: [CSP Header(4)] [CCSDS(6) + TM(12) + Data] [CRC32(4)]
        
        packet_content = frame[:-4] # Header + Payload
        # payload_only = packet_content[4:] # Skip Header (4 bytes)
        
        recv_crc_bytes = frame[-4:]
        recv_crc = struct.unpack('>I', recv_crc_bytes)[0]
        
        # Calculate with Header Included
        calc_crc = CRC32C.calc(packet_content)
        
        if calc_crc != recv_crc:
             self.root.after(0, self.log, f"RX [Err: CRC32C Fail] Calc:{calc_crc:08X} Recv:{recv_crc:08X}")
             # We return here to avoid processing bad packet
             return
             # We might return here to drop invalid packets, but for debugging let's continue or return?
             # Strictly we should return.
             return

        # 3. Strip CRC
        frame = packet_content
        
        # Now frame contains: [CSP Header(4)] + [CCSDS Primary(6)] + [TM Secondary(12)] + [User Data + (Opt)CCSDS CRC16]
        
        # 4. Header Parsing
        # 4.1 CSP Header
        if len(frame) < 4: return # Should be covered by min length check above
        csp_raw = frame[:4]
        # (Optional: Parse CSP Header if needed, e.g. check Dest/Src)
        
        # 4.2 CCSDS Primary (6 bytes) -> Index 4:10
        if len(frame) < 10:
             self.root.after(0, self.log, f"RX [Err: Short CCSDS] Len: {len(frame)}")
             return
             
        ccsds_raw = frame[4:10]
        
        # 4.3 TM Secondary (12 bytes) -> Index 10:22
        if len(frame) < 22:
             self.root.after(0, self.log, f"RX [Err: Short TM] Len: {len(frame)}")
             return

        tm_sec_raw = frame[10:22]
        
        try:
            ccsds_hdr = struct.unpack('>HHH', ccsds_raw)
            apid = ccsds_hdr[0] & 0x7FF
            pkt_len = ccsds_hdr[2] 
            
            svc, sub, src, t_sec, t_sub, flags, spare = struct.unpack('>BBHIHBB', tm_sec_raw)
            
            # 5. Identification & Data Extraction
            msg_name = "Unknown"
            status_tag = ""
            
            # User Data: From 22 to end.
            # Note: The remaining part might include CCSDS CRC-16 (2 bytes) at the very end.
            # If we want to verify CCSDS CRC, we can do it here. 
            # For now, let's treat everything after header as data, but be aware of the trailing 2 bytes.
            user_data = frame[22:]
            user_data_len = len(user_data)
            
            # Heuristic to detect if last 2 bytes are CRC16:
            # Usually User Data Length in Header (pkt_len) = len(payload) - 1.
            # CCSDS Payload = TM Sec(12) + User Data + CRC16(2)
            # frame len = 4 + 6 + Payload.
            # Let's assume User Data includes CRC16 for raw view.

            if svc == SVC_CONN and sub == MSG_PING_REP: msg_name = "PONG (Ping Reply)"
            elif svc == SVC_STATUS and sub == MSG_REP_STATUS: msg_name = "STATUS REPLY"
            elif svc == SVC_TEST:
                if sub == MSG_REPORT_END: msg_name = "TEST END REPORT"
                elif sub == MSG_REQ_DATA: msg_name = "TEST DATA REPLY"
                elif sub >= 10 and sub <= 127: msg_name = f"TEST DATA (Sub={sub})"
                
                # Default Response Check
                # Expecting 4 bytes of Actual Data (Ack+Code). 
                # If CCSDS CRC16 is present, total len would be 4 + 2 = 6.
                # If no CCSDS CRC16, total len is 4.
                elif sub in [MSG_START_TEST, MSG_STOP_TEST, MSG_SET_PARAM, MSG_SEND_TPVAW]:
                    # Check for 4 bytes (Pure) or 6 bytes (With CRC16)
                    if user_data_len == 4:
                        msg_name = "DEFAULT RESPONSE"
                        ack_data = user_data
                    elif user_data_len == 6:
                        msg_name = "DEFAULT RESPONSE"
                        ack_data = user_data[:-2] # Strip CRC16
                    else:
                        msg_name = f"CMD REPLY (Sub={sub})"
                        ack_data = None
                        status_tag += f" [Warn: Inv Len {user_data_len}]"

                    if ack_data:
                        ack = ack_data[0]
                        code_bytes = ack_data[1:4] + b'\x00' 
                        code = struct.unpack('<I', code_bytes)[0] & 0xFFFFFF
                        ack_str = "ACK (Success)" if ack == 0xFF else f"NACK (Fail)"
                        status_tag += f" [{ack_str} Code:0x{code:06X}]"
            
            if apid != 0x550: 
                 status_tag += f" [Warn: APID {apid:03X}]"
            
            msg = f"RX [{msg_name}] SVC:{svc}-{sub} SRC:{src} {status_tag}"
            
            if user_data:
                # Show Hex Dump (Limit length)
                # Maybe strip CRC16 from display if likely present?
                hex_dump = binascii.hexlify(user_data).decode().upper()
                if len(hex_dump) > 40: hex_dump = hex_dump[:40] + "..."
                msg += f" Data:{hex_dump}"

            self.root.after(0, self.log, msg)
            
        except Exception as e:
            self.root.after(0, self.log, f"RX [Err: Parse Fail] {str(e)}")

    def log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{ts}] {msg}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
