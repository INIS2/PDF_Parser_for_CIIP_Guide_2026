import re
import csv
from pathlib import Path
import traceback

import fitz  # PyMuPDF
import pandas as pd

import tkinter as tk
from tkinter import filedialog, messagebox


SECTION_HEADERS = {"개요", "점검 대상 및 판단 기준"}
LABELS = {"점검 내용", "점검 목적", "보안 위협", "참고", "대상", "판단 기준", "조치 방법", "조치 시 영향"}

GOOD_RE = re.compile(r"^\s*양호\s*[:：]\s*(.+)\s*$")
BAD_RE  = re.compile(r"^\s*취약\s*[:：]\s*(.+)\s*$")


def norm(s: str) -> str:
    s = s.replace("\u00a0", " ")
    s = re.sub(r"[ \t]{2,}", " ", s)
    return s.strip()


def extract_pages(pdf_path: str):
    """
    페이지별 텍스트를 (page_no_1based, text) 리스트로 반환
    """
    doc = fitz.open(pdf_path)
    pages = []
    for i in range(len(doc)):
        t = doc[i].get_text("text") or ""
        if t.strip():
            pages.append((i + 1, t))
        else:
            pages.append((i + 1, ""))  # 텍스트 없는 페이지도 인덱스 유지
    doc.close()
    return pages


def detect_code_prefixes_from_toc(text: str):
    idx = text.find("항목코드")
    window = text[idx: idx + 12000] if idx != -1 else text[:20000]

    codes = re.findall(r"\b([A-Z]{1,6})-(\d{2})\b", window)
    codes += re.findall(r"\b([A-Z]{1,6})-(\d{2})\b", text)

    if not codes:
        raise ValueError("항목코드에서 코드 접두어를 찾지 못했습니다. (예: S-01 / WEB-01)")

    freq = {}
    for prefix, _ in codes:
        freq[prefix] = freq.get(prefix, 0) + 1
    # most frequent first
    return [p for p, _ in sorted(freq.items(), key=lambda x: x[1], reverse=True)]


def split_items_with_page(pages, prefix: str):
    """
    항목 블록을 분리하면서, '항목 시작 페이지'도 같이 기록.
    시작 패턴:
      PREFIX-01
      (상|중|하)
    """
    # 페이지 결합(페이지 경계는 유지하되, 검색은 전체 텍스트에서)
    # 전체 텍스트 인덱스 -> 페이지 매핑을 위해 각 페이지 누적 길이를 기록
    page_offsets = []
    full = []
    pos = 0
    for pno, txt in pages:
        full.append(txt + "\n")
        page_offsets.append((pno, pos))
        pos += len(full[-1])
    full_text = "".join(full)

    start_pat = re.compile(rf"(?m)^({re.escape(prefix)}-\d{{2}})\s*\n\((상|중|하)\)")
    starts = list(start_pat.finditer(full_text))
    if not starts:
        raise ValueError(f"항목 시작 패턴을 찾지 못했습니다: {prefix}-01 형태가 PDF에 있는지 확인")

    def pos_to_page(char_pos: int) -> int:
        # 가장 큰 offset <= char_pos 인 페이지를 찾음
        # page_offsets = [(pno, start_pos), ...]
        lo, hi = 0, len(page_offsets) - 1
        ans = page_offsets[0][0]
        while lo <= hi:
            mid = (lo + hi) // 2
            pno, st = page_offsets[mid]
            if st <= char_pos:
                ans = pno
                lo = mid + 1
            else:
                hi = mid - 1
        return ans

    items = {}
    for i, m in enumerate(starts):
        code = m.group(1)
        s = m.start()
        e = starts[i + 1].start() if i + 1 < len(starts) else len(full_text)
        block = full_text[s:e].strip()
        start_page = pos_to_page(s)
        items[code] = {"text": block, "page": start_page}

    return items


def split_items_with_page_all(pages, prefixes):
    """
    모든 접두어를 한 번에 감지해서 문서 순서대로 항목 블록을 분리.
    시작 패턴:
      {PREFIX}-01
      (상|중|하)
    """
    page_offsets = []
    full = []
    pos = 0
    for pno, txt in pages:
        full.append(txt + "\n")
        page_offsets.append((pno, pos))
        pos += len(full[-1])
    full_text = "".join(full)

    prefix_alt = "|".join(re.escape(p) for p in prefixes)
    start_pat = re.compile(rf"(?m)^(({prefix_alt})-\d{{2}})\s*\n\((상|중|하)\)")
    starts = list(start_pat.finditer(full_text))
    if not starts:
        raise ValueError("항목 시작 패턴을 찾지 못했습니다.")

    def pos_to_page(char_pos: int) -> int:
        lo, hi = 0, len(page_offsets) - 1
        ans = page_offsets[0][0]
        while lo <= hi:
            mid = (lo + hi) // 2
            pno, st = page_offsets[mid]
            if st <= char_pos:
                ans = pno
                lo = mid + 1
            else:
                hi = mid - 1
        return ans

    items = []
    for i, m in enumerate(starts):
        code = m.group(1)
        s = m.start()
        e = starts[i + 1].start() if i + 1 < len(starts) else len(full_text)
        block = full_text[s:e].strip()
        start_page = pos_to_page(s)
        items.append((code, {"text": block, "page": start_page}))

    return items


def parse_meta(item_text: str):
    lines = [norm(x) for x in item_text.splitlines() if norm(x)]
    code = lines[0] if lines else ""
    importance = ""
    big = ""       # ✅ 대분류(플랫폼명)
    middle = ""    # 중분류(01. 계정관리)
    item_name = ""

    for i, ln in enumerate(lines[:30]):
        m = re.match(r"^\((상|중|하)\)$", ln)
        if m:
            importance = m.group(1)

            # (상) 다음 줄들에서 "플랫폼 > n. 중분류" 라인을 찾는다
            for j in range(i + 1, min(i + 20, len(lines))):
                if ">" in lines[j]:
                    # 예: "UNIX > 1. 계정 관리"
                    parts = [p.strip() for p in lines[j].split(">", 1)]
                    if len(parts) == 2:
                        big = parts[0]  # ✅ "UNIX"

                    m2 = re.search(r">\s*(\d)\.\s*([^\n]+)", lines[j])
                    if m2:
                        num = m2.group(1)
                        name = m2.group(2).replace(" ", "")
                        middle = f"0{num}. {name}"
                        if j + 1 < len(lines):
                            item_name = lines[j + 1]
                    break
            break

    return code, importance, big, middle, item_name


# 목차 기반 대분류 표기 매핑
TOC_BIG_MAP = {
    "UNIX": "I. Unix 서버",
    "Windows 서버": "II. Windows 서버",
    "웹 서비스": "III. 웹 서비스",
    "보안 장비": "IV. 보안 장비",
    "네트워크 장비": "Ⅴ. 네트워크 장비",
    "제어시스템": "Ⅵ. 제어시스템",
    "PC": "Ⅶ. PC",
    "DBMS": "Ⅷ. DBMS",
    "이동통신": "IX. 이동통신",
    "Web Application(웹)": "X. Web Application(웹)",
    "가상화 장비": "XI. 가상화 장비",
    "클라우드": "XII. 클라우드",
}



def parse_remediation_cases(item_text: str):
    """
    '점검 및 조치 사례' 섹션을
      l SOLARIS
      ...
      l LINUX
      ...
    이런 덩어리로 나눠서 [(title, body), ...] 반환

    * title 라인은 보통 "l SOLARIS" 형태. (PDF에 따라 'l'이 'I'/'|'/'·'로 깨질 수 있어 완화)
    """
    lines = [norm(x) for x in item_text.splitlines() if norm(x)]

    # 사례 시작 위치 (OCR 노이즈 허용)
    start_idx = None
    for i, ln in enumerate(lines):
        if ("점검" in ln and "조치" in ln and "사례" in ln) or ln.startswith("점검 및 조치 사례"):
            start_idx = i + 1
            break
    if start_idx is None:
        return []  # 사례 없음

    case_lines = lines[start_idx:]

    def extract_title(line: str):
        # footer-like lines
        if re.match(r"^\d+\|", line):
            return None
        # remove bullet-like prefixes
        s = re.sub(r"^(?:[lI|•·]|[\u2022\u25A0\u25CF]|[-])\s*", "", line).strip()
        # skip step-like lines
        if re.match(r"^step\s*\d+\)", s, flags=re.IGNORECASE):
            return None
        if len(s) < 2 or len(s) > 60:
            return None
        # bracket style like [syslog]
        if re.fullmatch(r"\[[A-Za-z0-9 _-]{2,}\]", s):
            return s
        # allow mixed case titles (Apache, Tomcat, Nginx, WebtoB, IIS, JEUS, etc.)
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9 ,&/()\-_.+]{1,60}", s):
            return s
        # allow Korean titles (공통 등)
        if re.fullmatch(r"[가-힣0-9][가-힣0-9 ,&/()\-_.+]{1,60}", s):
            return s
        return None

    cases = []
    current_title = None
    buf = []

    def flush():
        nonlocal current_title, buf
        if current_title is None:
            buf = []
            return
        body = "\n".join(buf).strip()
        # body 안에 흔히 들어오는 페이지/푸터 같은 잡문 제거(원하면 규칙 더 추가 가능)
        # 예: "13| 한국인터넷진흥원 |", "| 한국인터넷진흥원 | 46" 같은 것
        body = re.sub(r"\b\d{1,3}\|.*한국인터넷진흥원.*\|", "", body)
        body = re.sub(r"\|\s*한국인터넷진흥원\s*\|\s*\d{1,3}\b", "", body)
        # 예: "302026 주요정보통신기반시설 ... 상세가이드"
        body = re.sub(r"\b\d{1,4}\s*2026\s*주요정보통신.*상세가이드.*", "", body)
        # 예: "페이지 / 2026 주요정보통신..."
        body = re.sub(r"페이지\s*/\s*2026\s*주요정보통신.*", "", body)
        # 예: "01. Unix 서버 2026 주요정보통신... 49" (본문 중간 포함)
        body = re.sub(
            r"(?:\b\d{2}\.\s*[A-Za-z가-힣\s]{2,40})?\s*2026\s*주요정보통신[^\n]{0,120}상세가이드\s*\d{1,3}\b",
            "",
            body,
        )
        body = body.strip()
        cases.append((current_title.strip(), body))
        buf = []

    for ln in case_lines:
        title = extract_title(ln)
        if title:
            flush()
            current_title = title
            continue
        # 제목 시작 전이면 버림
        if current_title is None:
            continue
        buf.append(ln)

    flush()
    # 빈 body인 케이스 제거
    cases = [(t, b) for (t, b) in cases if t and b]
    return cases


def parse_fields(item_text: str) -> dict:
    """
    - '점검 및 조치 사례' 이전까지만 일반 필드로 파싱
    - 양호/취약은 별도 필드
    """
    lines = [norm(x) for x in item_text.splitlines() if norm(x)]

    # 사례 시작 전까지만 사용
    cut = len(lines)
    for i, ln in enumerate(lines):
        if ln.startswith("점검 및 조치 사례"):
            cut = i
            break
    lines = lines[:cut]

    out = {
        "점검 내용": "",
        "점검 목적": "",
        "보안 위협": "",
        "참고": "",
        "대상": "",
        "양호판단": "",
        "취약판단": "",
        "조치방법": "",
        "조치 시 영향": "",
    }

    current = None
    buf = []

    def flush():
        nonlocal current, buf
        if not current:
            buf = []
            return

        if current in ("대상", "판단 기준"):
            for ln2 in buf:
                m1 = GOOD_RE.match(ln2)
                m2 = BAD_RE.match(ln2)
                if m1:
                    out["양호판단"] = m1.group(1).strip()
                elif m2:
                    out["취약판단"] = m2.group(1).strip()
                else:
                    if current == "대상":
                        out["대상"] = (out["대상"] + " " + ln2).strip()
        else:
            key_map = {
                "점검 내용": "점검 내용",
                "점검 목적": "점검 목적",
                "보안 위협": "보안 위협",
                "참고": "참고",
                "조치 방법": "조치방법",
                "조치 시 영향": "조치 시 영향",
            }
            if current in key_map:
                out[key_map[current]] = " ".join(buf).strip()

        buf = []

    for ln in lines:
        if ln in SECTION_HEADERS:
            flush()
            current = None
            continue

        if ln in LABELS:
            flush()
            current = ln
            continue

        m1 = GOOD_RE.match(ln)
        m2 = BAD_RE.match(ln)
        if m1:
            out["양호판단"] = m1.group(1).strip()
            continue
        if m2:
            out["취약판단"] = m2.group(1).strip()
            continue

        if current:
            buf.append(ln)

    flush()
    return out


def excel_safe(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for col in out.columns:
        out[col] = (
            out[col].astype(str)
            .str.replace("\r\n", "\n")
            .str.replace("\r", "\n")
            .str.replace("\n", " ")
            .str.replace(r"\s{2,}", " ", regex=True)
            .str.strip()
        )
        out[col] = out[col].replace("nan", "")
    return out


def run_gui():
    root = tk.Tk()
    root.withdraw()

    messagebox.showinfo("CIIP PDF 파서", "PDF 파일을 선택하세요.")
    pdf_path = filedialog.askopenfilename(
        title="PDF 선택",
        filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
    )
    if not pdf_path:
        return

    pdf_path_obj = Path(pdf_path)
    default_name = f"{pdf_path_obj.stem}_parsed.csv"

    messagebox.showinfo("CIIP PDF 파서", "저장할 CSV 위치를 선택하세요.")
    out_path = filedialog.asksaveasfilename(
        title="CSV 저장",
        defaultextension=".csv",
        initialfile=default_name,
        filetypes=[("CSV files", "*.csv")]
    )
    if not out_path:
        return

    try:
        대분류명 = pdf_path_obj.stem

        pages = extract_pages(pdf_path)
        full_text = "\n".join([t for _, t in pages])

        prefixes = detect_code_prefixes_from_toc(full_text)
        items = split_items_with_page_all(pages, prefixes)

        # 1) 먼저 모든 항목에서 사례 개수 최대치를 구해 컬럼을 확정
        all_cases = {}
        max_case_n = 0
        for code, obj in items:
            cases = parse_remediation_cases(obj["text"])
            all_cases[code] = cases
            max_case_n = max(max_case_n, len(cases))

        # 2) 행 생성
        rows = []
        for code, obj in items:
            block = obj["text"]
            page_no = obj["page"]

            code2, imp, big, mid, name = parse_meta(block)
            fields = parse_fields(block)

            big_norm = TOC_BIG_MAP.get(big, big)
            row = {
                "대분류": big_norm,          # ✅ 목차 기반 대분류 표기
                "중분류": mid,
                "점검항목": name,
                "중요도": imp,
                "항목코드": code2,
                "페이지": page_no,
                **fields,
            }

            # ✅ 사례 컬럼: 있는 만큼만 채우고 나머진 빈칸
            cases = all_cases.get(code, [])
            for i in range(1, max_case_n + 1):
                t_col = f"점검조치 {i} 제목"
                c_col = f"점검조치 {i} 내용"
                if i <= len(cases):
                    row[t_col] = cases[i - 1][0]
                    row[c_col] = cases[i - 1][1]
                else:
                    row[t_col] = ""
                    row[c_col] = ""

            rows.append(row)

        # 3) 컬럼 순서 구성
        base_cols = [
            "대분류", "중분류", "점검항목", "중요도", "항목코드", "페이지",
            "점검 내용", "점검 목적", "보안 위협", "참고", "대상",
            "양호판단", "취약판단", "조치방법", "조치 시 영향",
        ]
        case_cols = []
        for i in range(1, max_case_n + 1):
            case_cols += [f"점검조치 {i} 제목", f"점검조치 {i} 내용"]

        df = pd.DataFrame(rows, columns=base_cols + case_cols)
        df = excel_safe(df)
        df.to_csv(out_path, index=False, encoding="utf-8-sig", quoting=csv.QUOTE_ALL)

        messagebox.showinfo(
            "완료",
            f"CSV 생성 완료!\n\n"
            f"- 저장경로: {out_path}\n"
            f"- 감지된 코드 접두어: {', '.join(prefixes)}\n"
            f"- 항목 수: {len(df)}\n"
            f"- 최대 점검조치 개수: {max_case_n}"
        )

    except Exception as e:
        messagebox.showerror(
            "오류",
            f"처리 중 오류가 발생했습니다.\n\n{e}\n\n상세:\n{traceback.format_exc()}"
        )


if __name__ == "__main__":
    run_gui()
