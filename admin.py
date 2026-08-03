"""
admin.py
--------
Simple command-line admin tool for the honeypot lab.
Lists blocked IPs / usernames and lets you unblock them.

Usage:
    python3 admin.py                     # interactive menu
    python3 admin.py list                # show blocked IPs + usernames
    python3 admin.py unblock-ip <ip>
    python3 admin.py unblock-username <username>
    python3 admin.py block-ip <ip>
    python3 admin.py block-username <username>
"""

import sys
import database


def list_blocked():
    ips = database.get_blocked_ips()
    users = database.get_blocked_usernames()

    print("\n=== Blocked IPs ===")
    if not ips:
        print("  (none)")
    else:
        for b in ips:
            print(f"  {b['ip']:<18} reason: {b['reason']:<30} at: {b['blocked_at']}")

    print("\n=== Blocked Usernames ===")
    if not users:
        print("  (none)")
    else:
        for b in users:
            print(f"  {b['username']:<18} reason: {b['reason']:<30} at: {b['blocked_at']}")
    print()


def unblock_ip(ip):
    if not database.is_ip_blocked(ip):
        print(f"IP {ip} is not currently blocked.")
        return
    database.unblock_ip(ip)
    print(f"IP {ip} unblocked.")


def unblock_username(username):
    if not database.is_username_blocked(username):
        print(f"Username '{username}' is not currently blocked.")
        return
    database.unblock_username(username)
    print(f"Username '{username}' unblocked.")


def block_ip(ip):
    database.block_ip(ip, reason="manual block via admin.py")
    print(f"IP {ip} blocked.")


def block_username(username):
    database.block_username(username, reason="manual block via admin.py")
    print(f"Username '{username}' blocked.")


def interactive_menu():
    while True:
        print("\n--- Honeypot Admin ---")
        print("1) List blocked IPs & usernames")
        print("2) Unblock an IP")
        print("3) Unblock a username")
        print("4) Block an IP")
        print("5) Block a username")
        print("0) Exit")
        choice = input("Choose: ").strip()

        if choice == "1":
            list_blocked()
        elif choice == "2":
            unblock_ip(input("IP to unblock: ").strip())
        elif choice == "3":
            unblock_username(input("Username to unblock: ").strip())
        elif choice == "4":
            block_ip(input("IP to block: ").strip())
        elif choice == "5":
            block_username(input("Username to block: ").strip())
        elif choice == "0":
            break
        else:
            print("Invalid choice.")


def main():
    args = sys.argv[1:]

    if not args:
        interactive_menu()
        return

    cmd = args[0]

    if cmd == "list":
        list_blocked()
    elif cmd == "unblock-ip" and len(args) == 2:
        unblock_ip(args[1])
    elif cmd == "unblock-username" and len(args) == 2:
        unblock_username(args[1])
    elif cmd == "block-ip" and len(args) == 2:
        block_ip(args[1])
    elif cmd == "block-username" and len(args) == 2:
        block_username(args[1])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
