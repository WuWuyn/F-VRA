"""
VFArCHE - Vulnerable Function Locator for Python
=================================================
Phiên bản: 2.0.0  |  Kiến trúc: User-Driven Input

CÁCH SỬ DỤNG:
  1. Tạo folder input, đặt tên tùy ý (vd: ./my_case/)
  2. Tạo file JSON tên theo CVE-ID: CVE-2023-24329.json
     Schema:
       {
         "cve_id":      "CVE-2023-24329",
         "description": "...",
         "cwe_ids":     ["CWE-20"],          <- tùy chọn
         "patch_urls":  ["https://github.com/..."]  <- tùy chọn
       }
  3. Đặt file .py của thư viện bị ảnh hưởng vào cùng folder.
  4. Chạy:
       python vfarche_tool.py --input ./my_case/ --cve CVE-2023-24329
       python vfarche_tool.py --demo     (chạy thử ngay)

ĐỊNH DẠNG ĐẦU RA: package.module.Class.method
KẾT QUẢ: vfarche_results.json (trong folder input)

CÀI ĐẶT:
  pip install requests scikit-learn numpy pandas nltk gitpython openai
"""

import sys, argparse, textwrap, logging
from .demo_setup import DemoSetup
from .orchestrator import VFArCHE

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger = logging.getLogger("VFArCHE")

def main():
    parser = argparse.ArgumentParser(
        description="VFArCHE v2.0 - Vulnerable Function Locator for Python",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Vi du:
          python vfarche_tool.py --demo
          python vfarche_tool.py --input ./my_case/ --cve CVE-2023-24329
          python vfarche_tool.py --input ./my_case/ --cve CVE-2023-24329 \\
              --llm-key sk-... --llm-model gpt-4o-mini

        Cau truc folder input:
          my_case/
            CVE-2023-24329.json    <- bat buoc (CVE-ID.json)
            affected_lib.py        <- bat buoc (file .py cua thu vien)
            fix.patch              <- tuy chon (neu co patch)
        """)
    )
    parser.add_argument("--input",     type=str, help="Folder chua JSON + .py")
    parser.add_argument("--cve",       type=str, help="CVE ID (vd: CVE-2023-24329)")
    parser.add_argument("--demo",      action="store_true", help="Chay demo tu dong")
    parser.add_argument("--cwe-db",    type=str, default="cwe_database.csv",
                        help="CSV cua CWE-1000 database (mac dinh: cwe_database.csv)")
    parser.add_argument("--llm-key",   type=str, default="",
                        help="OpenAI API key (hoac dat OPENAI_API_KEY env)")
    parser.add_argument("--llm-model", type=str, default="gpt-4o-mini")
    parser.add_argument("--package",   type=str, default="lib",
                        help="Ten package cua thu vien (mac dinh: lib)")
    parser.add_argument("--top-k",     type=int, default=100)
    parser.add_argument("--top-out",   type=int, default=10)
    args = parser.parse_args()

    if args.demo:
        print("\n" + "="*60)
        print("  VFArCHE v2.0 — DEMO MODE")
        print("="*60)
        demo_folder = DemoSetup.create("/tmp/vfarche_demo")
        print(f"  Demo folder: {demo_folder}")

        vfa = VFArCHE(
            input_folder=demo_folder,
            cwe_db_path=args.cwe_db,
            llm_api_key=args.llm_key,
            llm_model=args.llm_model,
            package_name="demo"
        )

        print("\n[Demo 1/2] CVE-2023-24329 — co CWE (QE mode)")
        vfa.analyze("CVE-2023-24329", top_k_candidates=20, top_k_output=5)

        print("\n[Demo 2/2] CVE-2022-42919 — khong co CWE (PRF+BM25 mode)")
        vfa.analyze("CVE-2022-42919", top_k_candidates=20, top_k_output=5)

        print(f"\n[Demo Complete] Ket qua: {demo_folder}/vfarche_results.json")
        return

    if not args.input or not args.cve:
        parser.print_help()
        print("\n[!] Can --input va --cve, hoac dung --demo")
        sys.exit(1)

    vfa = VFArCHE(
        input_folder=args.input,
        cwe_db_path=args.cwe_db,
        llm_api_key=args.llm_key,
        llm_model=args.llm_model,
        package_name=args.package
    )
    result = vfa.analyze(args.cve, top_k_candidates=args.top_k, top_k_output=args.top_out)

    if result.top_function:
        print(f"\n[+] TOP-1 VF: {result.top_function.full_name}")
        print(f"    Confidence: {result.confidence:.2%}")
    else:
        print("\n[-] Khong tim thay Vulnerable Function")


if __name__ == "__main__":
    main()