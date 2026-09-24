"""QSafeShare Application Startup Script."""

import sys
import uvicorn

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def main():
    print("=" * 70)
    print("  QSafeShare — Post-Quantum Secure Multi-Agent File Sharing")
    print("  Standard: NIST FIPS 203 ML-KEM + AES-256-GCM")
    print("  Architecture: SenderAgent + PolicyAgent + CoordinatorAgent + AuditAgent")
    print("=" * 70)
    print("\nStarting Web Application Server at: http://127.0.0.1:8000")
    print("To stop the server, press Ctrl+C.\n")

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
