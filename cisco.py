import csv
from netmiko import ConnectHandler
from getpass import getpass
import sys
import re

# Devices to audit
DEVICES = [
    {'ip': '192.168.1.10', 'username': 'admin'},
    {'ip': '192.168.1.11', 'username': 'admin'},
]

# SECURITY COMMANDS FOR CISCO ASA
SECURITY_AUDIT_COMMANDS = [
    "show running-config ssh",
    "show running-config telnet",
    "show running-config http",
    "show running-config ssl",
    "show running-config logging",
    "show run | include threat-detection",
    "show run access-list",
    "show run object",
    "show run object-group",
    "show version"
]

WEAK_SERVICES = ("telnet", "ftp", "tftp", "rsh", "finger")

def analyze_acls_and_objects(output):
    """
    Analyze ACLs and object usage:
    - Detect ANY/ANY rules
    - Detect weak services (telnet, ftp, tftp, rsh, finger)
    - Detect duplicate ACL entries
    - Detect unused objects
    """

    acl_lines = []
    object_names = set()
    object_references = set()

    # Split into lines for easier processing
    lines = output.splitlines()

    for line in lines:
        line = line.strip()

        # Collect ACL lines
        if line.startswith("access-list "):
            acl_lines.append(line)

        # Collect object definitions
        # e.g. "object network OBJ-SERVER1"
        m_obj = re.match(r"object\s+(network|service)\s+(\S+)", line)
        if m_obj:
            object_names.add(m_obj.group(2))

        # Collect object-group definitions
        # e.g. "object-group network OG-SERVERS"
        m_og = re.match(r"object-group\s+\S+\s+(\S+)", line)
        if m_og:
            object_names.add(m_og.group(1))

        # Track references to objects/object-groups
        # e.g. "object OBJ-SERVER1" or "object-group OG-SERVERS"
        m_ref = re.search(r"\bobject(?:-group)?\s+(\S+)", line)
        if m_ref:
            object_references.add(m_ref.group(1))

    # ANY/ANY and weak services
    any_any_found = False
    weak_service_found = False

    # Duplicate ACL detection
    seen_acls = set()
    duplicate_found = False

    for acl in acl_lines:
        # Normalize ACL line for duplicate detection
        norm = " ".join(acl.split())
        if norm in seen_acls:
            duplicate_found = True
        else:
            seen_acls.add(norm)

        # ANY/ANY detection (permit ip any any or similar)
        # Very simple heuristic
        if re.search(r"\bpermit\b\s+\S*\s+any\s+any\b", acl):
            any_any_found = True

        # Weak services detection
        for svc in WEAK_SERVICES:
            if re.search(rf"\b{svc}\b", acl, re.IGNORECASE):
                weak_service_found = True
                break

    # Unused objects = defined but never referenced
    unused_objects = object_names - object_references
    unused_objects_flag = "Yes" if unused_objects else "No"

    return {
        "Any_Any_Rule": "Yes" if any_any_found else "No",
        "Weak_Service_Rule": "Yes" if weak_service_found else "No",
        "Duplicate_ACL_Rule": "Yes" if duplicate_found else "No",
        "Unused_Objects": unused_objects_flag,
        "Unused_Object_Count": len(unused_objects)
    }


def parse_asa_output(output):
    """
    Extract key security posture metrics from Cisco ASA output.
    """

    data = {
        'ASA_Version': 'N/A',
        'SSH_Encryption': 'N/A',
        'SSH_KEX': 'N/A',
        'Telnet_Enabled': 'No',
        'TLS_Version': 'N/A',
        'Logging_Enabled': 'No',
        'Threat_Detection': 'No',
        'Weak_VPN_Crypto': 'No',
        'Any_Any_Rule': 'No',
        'Weak_Service_Rule': 'No',
        'Duplicate_ACL_Rule': 'No',
        'Unused_Objects': 'No',
        'Unused_Object_Count': 0,
    }

    # ASA Version
    ver = re.search(r"Cisco Adaptive Security Appliance Software Version ([\d\.]+)", output)
    if ver:
        data["ASA_Version"] = ver.group(1)

    # SSH encryption ciphers
    ssh_enc = re.search(r"ssh cipher encryption (.+)", output)
    if ssh_enc:
        data["SSH_Encryption"] = ssh_enc.group(1).strip()

    # SSH KEX
    ssh_kex = re.search(r"ssh key-exchange group (.+)", output)
    if ssh_kex:
        data["SSH_KEX"] = ssh_kex.group(1).strip()

    # Telnet detection
    if "telnet " in output:
        data["Telnet_Enabled"] = "Yes"

    # TLS/SSL version
    ssl_ver = re.search(r"ssl server-version (.+)", output)
    if ssl_ver:
        data["TLS_Version"] = ssl_ver.group(1).strip()

    # Logging
    if "logging enable" in output:
        data["Logging_Enabled"] = "Yes"

    # Threat Detection
    if "threat-detection" in output:
        data["Threat_Detection"] = "Enabled"

    # Weak crypto detection (3DES, MD5, DH2)
    if re.search(r"3des|md5|group2", output, re.IGNORECASE):
        data["Weak_VPN_Crypto"] = "Yes"

    # ACL / object analysis
    acl_obj_results = analyze_acls_and_objects(output)
    data.update(acl_obj_results)

    return data


def run_compliance_check():
    print("\n--- Enter credentials ---")
    try:
        password = getpass("SSH Password: ")
        enable_secret = getpass("Enable Secret (if needed): ")
    except EOFError:
        print("\nInput error. Exiting.")
        sys.exit(1)

    all_results = []

    for device in DEVICES:
        print(f"\n--- Connecting to ASA {device['ip']} ---")

        asa_conn = {
            "device_type": "cisco_asa",
            "ip": device['ip'],
            "username": device['username'],
            "password": password,
            "secret": enable_secret
        }

        device_data = {"Device_IP": device['ip']}

        try:
            net_connect = ConnectHandler(**asa_conn)
            net_connect.enable()

            # Run all commands in one combined string
            output = net_connect.send_command("\n".join(SECURITY_AUDIT_COMMANDS))
            net_connect.disconnect()

            parsed = parse_asa_output(output)
            device_data.update(parsed)
            device_data["Audit_Status"] = "SUCCESS"
            all_results.append(device_data)

        except Exception as e:
            print(f"FAILED on {device['ip']} → {e}")
            device_data.update({
                "Audit_Status": "FAILED",
                "ASA_Version": "N/A",
                "SSH_Encryption": "N/A",
                "SSH_KEX": "N/A",
                "Telnet_Enabled": "N/A",
                "TLS_Version": "N/A",
                "Logging_Enabled": "N/A",
                "Threat_Detection": "N/A",
                "Weak_VPN_Crypto": "N/A",
                "Any_Any_Rule": "N/A",
                "Weak_Service_Rule": "N/A",
                "Duplicate_ACL_Rule": "N/A",
                "Unused_Objects": "N/A",
                "Unused_Object_Count": 0,
            })
            all_results.append(device_data)

    # Write CSV output
    filename = "asa_security_audit_results.csv"
    with open(filename, "w", newline="") as csvfile:
        fieldnames = [
            "Device_IP",
            "Audit_Status",
            "ASA_Version",
            "SSH_Encryption",
            "SSH_KEX",
            "Telnet_Enabled",
            "TLS_Version",
            "Logging_Enabled",
            "Threat_Detection",
            "Weak_VPN_Crypto",
            "Any_Any_Rule",
            "Weak_Service_Rule",
            "Duplicate_ACL_Rule",
            "Unused_Objects",
            "Unused_Object_Count",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)

    print(f"\n✔ Audit complete. CSV saved as: {filename}")


if __name__ == "__main__":
    run_compliance_check()
