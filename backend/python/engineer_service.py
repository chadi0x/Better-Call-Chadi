import os
import hashlib
import json
import logging
import re
import zipfile

try:
    import yara
except ImportError:
    yara = None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EngineerService:
    def __init__(self, upload_folder='./uploads'):
        self.upload_folder = upload_folder
        if not os.path.exists(self.upload_folder):
            os.makedirs(self.upload_folder)
            
        # Load Malware Hashes
        self.hashes = {}
        try:
            with open('malware_hashes.json', 'r') as f:
                self.hashes = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load malware_hashes.json: {e}")

        # Load YARA Rules
        self.rules = None
        try:
            if yara:
                self.rules = yara.compile(filepath='rules.yar')
                logger.info(f"YARA rules compiled successfully. Rules found: {len(list(self.rules)) if hasattr(self.rules, '__iter__') else 'Loaded'}")
            else:
                logger.warning("YARA module NOT FOUND. Rule scanning disabled. Ensure yara-python is installed.")
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")

        # Byte Patterns (Suspicious Signatures)
        self.byte_patterns = {
            b'MZ': "Windows PE Header (EXE/DLL)",
            b'\x7fELF': "Linux ELF Binary",
            b'PK\x03\x04': "ZIP Archive",
            b'#!/bin/bash': "Bash Script",
            b'#!/bin/sh': "Shell Script",
            b'TVqQ': "Base64 Encoded Windows PE (MZ)",
            b'UEsDB': "Base64 Encoded ZIP/JAR (PK)",
            b'UPX!': "UPX Packer Signature",
            b'eval(base64_decode': "PHP Obfuscation",
            b'powershell -enc': "Encoded PowerShell",
            b'cmd.exe /c': "Windows Command Shell",
            b'EVIL_TEST_STRING': "Test Signature (For Verification)"
        }

    def scan_file(self, file_storage):
        filename = file_storage.filename
        filepath = os.path.join(self.upload_folder, filename)
        file_storage.save(filepath)
        
        # Base result structure
        full_report = {
            "filename": filename,
            "status": "clean",
            "file_type": "Unknown",
            "file_hash": "", 
            "detection_source": None,
            "findings": [],
            "files_scanned": 1,
            "recommendation": "File appears safe."
        }

        try:
            # Check if ZIP
            if zipfile.is_zipfile(filepath):
                full_report['file_type'] = "ZIP Archive"
                self._scan_zip(filepath, full_report)
            else:
                self._scan_single_file(filepath, full_report)

        except Exception as e:
            logger.error(f"File scan failed: {e}")
            full_report['error'] = str(e)
        finally:
             if os.path.exists(filepath):
                os.remove(filepath)

        return full_report

    def _scan_zip(self, zip_path, report):
        temp_extract_dir = os.path.join(self.upload_folder, f"extract_{os.path.basename(zip_path)}_{int(os.urandom(4).hex(), 16)}")
        os.makedirs(temp_extract_dir, exist_ok=True)
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_extract_dir)
            
            report['files_scanned'] = 0
            
            for root, dirs, files in os.walk(temp_extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    report['files_scanned'] += 1
                    
                    # Create a mini-report for this file
                    file_report = {"findings": [], "status": "clean"}
                    self._scan_single_file(file_path, file_report, original_filename=file)
                    
                    # Merge findings if malicious/suspicious
                    if file_report['status'] != 'clean':
                        if report['status'] == 'clean': report['status'] = file_report['status']
                        if file_report['status'] == 'malicious': report['status'] = 'malicious' # Upgrade to malicious
                        
                        report['detection_source'] = file_report.get('detection_source', 'Archive Scan')
                        for finding in file_report['findings']:
                            report['findings'].append(f"[{file}] {finding}")
                            
        except Exception as e:
            logger.error(f"ZIP Extraction failed: {e}")
            report['findings'].append(f"Failed to extract archive: {str(e)}")
        finally:
            import shutil
            if os.path.exists(temp_extract_dir):
                shutil.rmtree(temp_extract_dir)

    def _scan_single_file(self, filepath, result, original_filename=None):
        try:
            # 1. Calculate SHA256 (Only for the main file if it's not a zip, otherwise we skip hash for subfiles to save time? Or check DB?)
            # Let's check DB for everything.
            sha256_hash = self._calculate_sha256(filepath)
            if 'file_hash' in result and result['file_hash'] == "": result['file_hash'] = sha256_hash # Set main hash
            
            # 2. Check Hash DB
            if sha256_hash in self.hashes:
                result['status'] = "malicious"
                result['detection_source'] = "Threat Intelligence DB"
                result['findings'].append(f"Known Malware: {self.hashes[sha256_hash]}")
                result['recommendation'] = "DELETE IMMEDIATELY. Known malicious file."
                return

            # 3. Byte Pattern Scanning
            with open(filepath, 'rb') as f:
                content = f.read()
            
            for pattern, desc in self.byte_patterns.items():
                if original_filename is None: # Only set file_type for the main file
                    if content.startswith(pattern) or pattern in content[:50]:
                        result['file_type'] = desc

                if pattern in content:
                    if pattern in [b'MZ', b'\x7fELF', b'PK\x03\x04']: continue # Skip headers
                    
                    result['status'] = "suspicious" if result['status'] != "malicious" else "malicious"
                    if result.get('detection_source') is None: result['detection_source'] = "Heuristic Pattern"
                    result['findings'].append(f"Suspicious Pattern: {desc}")

            # 4. YARA Scanning
            if self.rules:
                try:
                    matches = self.rules.match(filepath)
                    if matches:
                        result['status'] = "malicious"
                        result['detection_source'] = "YARA Rule"
                        for match in matches:
                            result['findings'].append(f"Rule Match: {match.rule}")
                        result['recommendation'] = "High threat detected by behavioral rules."
                except Exception as yara_e:
                    logger.error(f"YARA scan error on {filepath}: {yara_e}")

            # 4. ClamAV Scanning
            self._scan_clamav(filepath, result)

            # Finalize Status
            if result['status'] == 'suspicious':
                 result['recommendation'] = "Proceed with caution. Suspicious elements found."
            
        except Exception as e:
            logger.error(f"Single file scan failed: {e}")


    def _scan_clamav(self, filepath, result):
        try:
            import pyclamd
            # Connect to ClamAV daemon
            cd = pyclamd.ClamdNetworkSocket(host='chadi_clamav', port=3310, timeout=10)
            
            if cd.ping():
                # Scan stream (avoids mounting volumes)
                with open(filepath, 'rb') as f:
                    scan_result = cd.scan_stream(f.read())
                
                if scan_result:
                    # scan_result is dict like { 'stream': ('FOUND', 'Win.Test.EICAR_HDB-1') }
                    result['status'] = "malicious"
                    result['detection_source'] = "ClamAV"
                    for key, val in scan_result.items():
                        virus_name = val[1]
                        result['findings'].append(f"ClamAV: {virus_name}")
                    result['recommendation'] = "Quarantine or Delete. Detected by Antivirus."
            else:
                logger.warning("ClamAV daemon not responding to ping.")
                
        except ImportError:
            logger.warning("pyclamd not installed.")
        except Exception as e:
            logger.warning(f"ClamAV scan failed: {e}")

    def _calculate_sha256(self, filepath):
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
