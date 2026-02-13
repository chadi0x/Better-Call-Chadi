import os
import json
import zipfile
import subprocess
import shutil
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ForensicsService:
    def __init__(self, upload_folder='./uploads'):
        self.upload_folder = upload_folder
        if not os.path.exists(self.upload_folder):
            os.makedirs(self.upload_folder)

    def analyze_apk(self, file_storage):
        """
        Analyzes an APK file using Androguard.
        Extracts permissions, activities, services, code secrets, and security configs.
        """
        filename = file_storage.filename
        filepath = os.path.join(self.upload_folder, filename)
        file_storage.save(filepath)

        report = {
            "filename": filename,
            "timestamp": datetime.now().isoformat(),
            "package_name": "Unknown",
            "version_name": "Unknown",
            "version_code": "Unknown",
            "min_sdk": "Unknown",
            "target_sdk": "Unknown",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "dangerous_permissions": [],
            "findings": [],
            "secrets": [],
            "urls": [],
            "trackers": [],
            "security_config": {},
            "risk_score": 0
        }

        try:
            from androguard.core.apk import APK
            import re

            a = APK(filepath)
            
            logger.info(f"Analyzing APK: {filepath}, Size: {os.path.getsize(filepath)} bytes")
            logger.info(f"Files in APK: {a.get_files()[:5]}... (total {len(a.get_files())})")

            if not a.is_valid_APK():
                 logger.error("is_valid_APK() returned False. AndroidManifest.xml missing?")
                 raise Exception("Invalid APK: Missing AndroidManifest.xml or corrupted file.")
            
            report['package_name'] = a.get_package() or "Unknown"

            try:
                report['version_name'] = a.get_androidversion_name()
            except Exception as e:
                logger.warning(f"Failed to get version name: {e}")
                report['version_name'] = "Unknown"
                
            try:
                report['version_code'] = a.get_androidversion_code()
            except Exception as e:
                logger.warning(f"Failed to get version code: {e}")
                report['version_code'] = "Unknown"
                
            report['min_sdk'] = a.get_min_sdk_version() or "Unknown"
            report['target_sdk'] = a.get_target_sdk_version() or "Unknown"
            
            # Manifest extraction
            report['permissions'] = sorted(list(a.get_permissions()))
            report['activities'] = sorted(list(a.get_activities()))
            report['services'] = sorted(list(a.get_services()))
            report['receivers'] = sorted(list(a.get_receivers()))
            report['providers'] = sorted(list(a.get_providers()))

            # --- Deep Analysis ---
            
            # 1. Permissions Analysis
            dangerous_perms = {
                "android.permission.READ_SMS": "Can read SMS messages (MFA stealing risk)",
                "android.permission.SEND_SMS": "Can send SMS messages (Cost/Spam risk)",
                "android.permission.RECEIVE_SMS": "Can intercept SMS messages",
                "android.permission.READ_CONTACTS": "Can harvest user contacts",
                "android.permission.ACCESS_FINE_LOCATION": "Precise GPS location tracking",
                "android.permission.RECORD_AUDIO": "Can record ambient audio",
                "android.permission.CAMERA": "Can take photos/videos without consent",
                "android.permission.READ_CALL_LOG": "Can expose communication history",
                "android.permission.WRITE_EXTERNAL_STORAGE": "Can modify/delete shared files",
                "android.permission.SYSTEM_ALERT_WINDOW": "Overlay capabilities (Cloaking/Phishing)",
                "android.permission.GET_ACCOUNTS": "Can access account lists",
                "android.permission.READ_PHONE_STATE": "Can track device ID (IMEI)",
                "android.permission.PROCESS_OUTGOING_CALLS": "Can monitor/redirect calls"
            }
            
            detected_dangerous = []
            for perm in report['permissions']:
                for dp, desc in dangerous_perms.items():
                    if dp in perm:
                        detected_dangerous.append({"permission": perm, "description": desc})
                        if any(x['title'] == f"Dangerous Permission: {perm.split('.')[-1]}" for x in report['findings']): continue
                        report['findings'].append({
                            "title": f"Dangerous Permission: {perm.split('.')[-1]}",
                            "severity": "High" if "SMS" in perm or "AUDIO" in perm else "Medium",
                            "desc": desc
                        })
            report['dangerous_permissions'] = detected_dangerous

            # 2. Security Config Analysis
            # Check debuggable
            is_debuggable = False
            try:
                # androguard method usually returns string "true"/"false" or bool
                app_elem = a.get_element("application", "android:debuggable")
                is_debuggable = str(app_elem).lower() == 'true' if app_elem else False
            except:
                pass
                
            report['security_config']['debuggable'] = is_debuggable
            if is_debuggable:
                report['findings'].append({
                    "title": "App is Debuggable",
                    "severity": "Critical",
                    "desc": "The app can be attached to by a debugger. Attackers can dump memory and hook methods easily."
                })

            # Check allowBackup
            allow_backup = True
            try:
                app_elem = a.get_element("application", "android:allowBackup")
                allow_backup = str(app_elem).lower() != 'false' # Default is true
            except:
                pass
            
            report['security_config']['allow_backup'] = allow_backup
            if allow_backup:
                report['findings'].append({
                    "title": "Backup Allowed",
                    "severity": "Medium",
                    "desc": "App data can be backed up and extracted via ADB, potentially leaking sensitive data."
                })
                
            # Check Cleartext Traffic
            uses_cleartext = True # Default true for older android
            try:
                app_elem = a.get_element("application", "android:usesCleartextTraffic")
                uses_cleartext = str(app_elem).lower() == 'true'
            except:
                pass
                
            report['security_config']['uses_cleartext_traffic'] = uses_cleartext
            if uses_cleartext:
                report['findings'].append({
                    "title": "Cleartext Traffic Allowed",
                    "severity": "High",
                    "desc": "App permits HTTP (unencrypted) traffic. Vulnerable to MITM attacks."
                })

            # 3. Code & String Analysis (DEX)
            # We iterate over all strings in the DEX files
            
            # Common Secret Patterns (Simple Regex)
            bg_patterns = {
                "AWS Key": r"AKIA[0-9A-Z]{16}",
                "Google Key": r"AIza[0-9A-Za-z\\-_]{35}",
                "Generic Auth Bearer": r"Bearer [a-zA-Z0-9\\-_=]+\.[a-zA-Z0-9\\-_=]+\.?[a-zA-Z0-9\\-_.+/=]*",
                "Private Key": r"-----BEGIN PRIVATE KEY-----",
                "Hardcoded URL": r"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\"\s]*)?",
                "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            }
            
            # Known Trackers (Class/Package names)
            tracker_signatures = {
                "Google Analytics": "com.google.android.gms.analytics",
                "Firebase Analytics": "com.google.firebase.analytics",
                "Facebook SDK": "com.facebook.appevents",
                "AppsFlyer": "com.appsflyer",
                "Adjust": "com.adjust.sdk",
                "Crashlytics": "com.crashlytics",
                "Flurry": "com.flurry.android",
                "Mixpanel": "com.mixpanel",
                "OneSignal": "com.onesignal",
                "Segment": "com.segment.analytics"
            }
            
            # Analyzing strings
            found_secrets = []
            found_urls = set()
            found_trackers = set()
            
            # Analyzing classes for trackers & strings
            # Note: Androguard v4 - getting all strings can be done via get_dex() iterators
            
            from androguard.core.dex import DEX
            
            for i, dex_content in enumerate(a.get_all_dex()):
                try:
                    logger.info(f"Processing DEX #{i}, type: {type(dex_content)}, length: {len(dex_content)}")
                    d = DEX(dex_content)
                    logger.info(f"DEX object created: {type(d)}")
                except Exception as e:
                    logger.warning(f"Failed to parse DEX file: {e}")
                    import traceback
                    logger.warning(traceback.format_exc())
                    continue

                try:
                    for s in d.get_strings():
                        # Check for URLs
                        if "http" in s:
                            match = re.search(bg_patterns["Hardcoded URL"], s)
                            if match and len(s) < 120: # valid url likely
                                found_urls.add(match.group(0))
                                
                        # Check for IPs
                        # match = re.search(bg_patterns["IP Address"], s) # Too noisy often
                        
                        # Check for Secrets
                        for label, pattern in bg_patterns.items():
                            if label == "Hardcoded URL" or label == "IP Address": continue
                            if re.search(pattern, s):
                                # Redact actual key for report if sensitive
                                masked = s[:4] + "***" + s[-4:] if len(s) > 10 else "***"
                                found_secrets.append({"type": label, "value": masked})
                                report['findings'].append({
                                    "title": f"Hardcoded Secret: {label}", 
                                    "severity": "Critical", 
                                    "desc": f"Found potential {label} in code strings."
                                })
                except Exception as e:
                     logger.error(f"Error analyzing strings in DEX #{i}: {e}")
                     import traceback
                     logger.error(traceback.format_exc())

                try:
                    for c in d.get_classes():
                        c_name = c.get_name() # returns 'Lcom/example/MyClass;'
                        # Convert to java style: com.example.MyClass
                        java_name = c_name[1:-1].replace('/', '.')
                        
                        for t_name, t_sig in tracker_signatures.items():
                            if t_sig in java_name:
                                found_trackers.add(t_name)
                except Exception as e:
                     logger.error(f"Error analyzing classes in DEX #{i}: {e}")
            
            report['secrets'] = list(found_secrets) # allow duplicates if context differs? no, set for unique logic earlier but list for JSON
            report['urls'] = sorted(list(found_urls))
            report['trackers'] = sorted(list(found_trackers))
            
            if len(report['trackers']) > 3:
                 report['findings'].append({
                    "title": "Aggressive Tracking", 
                    "severity": "Medium", 
                    "desc": f"Found {len(report['trackers'])} tracking libraries."
                })

            # 4. Risk Scoring
            # Base logic
            score = 0
            
            # Critical findings
            img_crit = len([f for f in report['findings'] if f['severity'] == 'Critical'])
            score += img_crit * 25
            
            # High findings
            img_high = len([f for f in report['findings'] if f['severity'] == 'High'])
            score += img_high * 15
            
            # Medium findings
            img_med = len([f for f in report['findings'] if f['severity'] == 'Medium'])
            score += img_med * 5
            
            # Dangerous permissions count
            score += len(detected_dangerous) * 2

            report['risk_score'] = min(score, 100)

        except Exception as e:
            logger.error(f"APK Analysis failed: {e}")
            report['error'] = str(e)
            import traceback
            traceback.print_exc()
        finally:
            # Cleanup
            if os.path.exists(filepath):
                os.remove(filepath)

        return report

    def get_triage_script(self, os_type):
        """
        Returns the path to the triage script for the specified OS.
        """
        # Docker path: /app/scripts/
        # Local path during dev might differ, so we use relative to this file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        script_dir = os.path.join(base_dir, 'scripts')
        
        logger.info(f"Looking for scripts in: {script_dir}")
        
        if os_type == 'windows':
            return os.path.join(script_dir, 'triage_win.bat')
        elif os_type == 'linux':
            return os.path.join(script_dir, 'triage_linux.sh')
        return None

    def parse_triage_data(self, file_storage):
        """
        Parses a triage zip/log dump to extract forensic artifacts.
        Simulated parsing for now as we define the output format.
        """
        filename = file_storage.filename
        filepath = os.path.join(self.upload_folder, filename)
        file_storage.save(filepath)
        
        report = {
            "filename": filename,
            "os_type": "Unknown",
            "processes": [],
            "connections": [],
            "autoruns": [],
            "risk_score": 0,
            "anomalies": []
        }
        
        try:
             # Basic text parsing if it's a log file
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                
            if "Microsoft Windows" in content or "tasklist" in content:
                report['os_type'] = "Windows"
                # Fake parsing logic for demo purposes until we have real structured output
                if "powershell.exe -enc" in content:
                    report['anomalies'].append({"title": "Encoded PowerShell", "severity": "Critical", "desc": "Suspicious encoded PowerShell command found."})
                    report['risk_score'] += 40
                if "nc.exe" in content or "ncat" in content:
                    report['anomalies'].append({"title": "Netcat Detected", "severity": "High", "desc": "Potential reverse shell tool detected."})
                    report['risk_score'] += 30

            elif "Linux" in content or "uid=" in content:
                report['os_type'] = "Linux"
                if "ncat" in content:
                     report['anomalies'].append({"title": "Netcat Connection", "severity": "High", "desc": "Netcat process found in logs."})
                     report['risk_score'] += 30
            
            # If zip, we would unzip and parse individual files
            
        except Exception as e:
            logger.error(f"Triage parsing failed: {e}")
            report['error'] = str(e)
        finally:
             if os.path.exists(filepath):
                os.remove(filepath)
                
        return report
