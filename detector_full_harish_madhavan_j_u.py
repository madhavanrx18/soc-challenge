import csv
import json
import re
from typing import Dict, Any


class PersonalInfoFinder:
    def __init__(self):
        self.phone_re = re.compile(r"^\d{10}$")
        self.aadhar_re = re.compile(r"^\d{4}\s?\d{4}\s?\d{4}$")
        self.passport_re = re.compile(r"^[A-Z]\d{7}$")
        self.email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

        self.upi_domains = {
            "abcdicici", "apl", "yapl", "rapl", "abfspay", "bpunity", "jarunity",
            "axisb", "yescred", "yescurie", "yesfam", "fifederal", "fkaxis",
            "freoicici", "okaxis", "okhdfcbank", "okicici", "oksbi", "yesg",
            "inhdfc", "jupiteraxis", "goaxb", "kbaxis", "kphdfc", "ikwik",
            "mvhdfc", "naviaxis", "niyoicici", "oneyes", "paytm", "ptyes",
            "ptaxis", "pthdfc", "ptsbi", "ybl", "ibl", "axl", "yespop", "rmrbl",
            "pingpay", "seyes", "shriramhdfcbank", "superyes", "tapicici",
            "timecosmos", "axisbank", "yestp", "idfcbank", "waicici", "icici",
            "waaxis", "wahdfcbank", "wasbi"
        }

        self.group_fields = {
            "names": ["name", "first_name", "last_name"],
            "emails": ["email"],
            "addresses": ["address", "city", "pin_code", "state"],
        }


    def check_single(self, record: Dict[str, Any]) -> Dict[str, bool]:
        found = {}

        for field, value in record.items():
            if not value:
                continue

            text = str(value).strip()

            if field == "phone" or self.phone_re.fullmatch(text):
                found[field] = True

            elif field == "aadhar" or self.aadhar_re.fullmatch(text):
                found[field] = True

            elif field == "passport" or self.passport_re.fullmatch(text):
                found[field] = True

            elif field == "email" or self.email_re.fullmatch(text):
                found[field] = True

            elif "@" in text:
                user_domain = text.split("@")
                if len(user_domain) == 2 and user_domain[1].lower() in self.upi_domains:
                    found[field] = True

            else:
                found[field] = False

        return found


    def check_combined(self, record: Dict[str, Any]) -> bool:
        groups = set()

        for field, value in record.items():
            if not value or not str(value).strip():
                continue

            if field in self.group_fields["names"]:
                if field == "name" and self._is_full_name(value):
                    groups.add("name")

                elif field in ["first_name", "last_name"] and self._has_both_names(record):
                    groups.add("name")

            elif field in self.group_fields["emails"]:
                if self.email_re.fullmatch(str(value)):
                    groups.add("email")

            elif field in self.group_fields["addresses"]:
                if self._is_full_address(record):
                    groups.add("address")

        return len(groups) >= 2


    def detect_pii(self, record: Dict[str, Any]) -> bool:
        if any(self.check_single(record).values()):
            return True

        return self.check_combined(record)


    def _is_full_name(self, name: str) -> bool:
        parts = str(name).strip().split()
        return len(parts) >= 2 and all(p.isalpha() for p in parts)


    def _has_both_names(self, record: Dict[str, Any]) -> bool:
        return bool(record.get("first_name") and record.get("last_name"))


    def _is_full_address(self, record: Dict[str, Any]) -> bool:
        count = sum(1 for f in ["address", "city", "pin_code"] if record.get(f))
        return count >= 2



class PersonalInfoHider:
    def __init__(self):
        self.finder = PersonalInfoFinder()


    def hide_value(self, field: str, value: Any) -> str:
        if not value:
            return value

        text = str(value).strip()

        if field == "phone" or self.finder.phone_re.fullmatch(text):
            return text[:2] + "X" * (len(text) - 4) + text[-2:]

        if field == "aadhar" or self.finder.aadhar_re.fullmatch(text):
            return "XXXX XXXX " + text[-4:]

        if field == "passport":
            return "XXXXXXX"

        if self.finder.email_re.fullmatch(text):
            user, domain = text.split("@", 1)
            return user[:2] + "X" * (len(user) - 2) + "@" + domain

        if "@" in text:
            user, domain = text.split("@", 1)
            if domain.lower() in self.finder.upi_domains:
                return user[:2] + "X" * (len(user) - 2) + "@" + domain

        if field in ["name", "first_name", "last_name"]:
            return text[0] + "X" * (len(text) - 1)

        if field in ["address", "city", "pin_code", "state"]:
            return "[REDACTED_ADDRESS]"

        return value


    def hide_record(self, record: Dict[str, Any], has_pii: bool) -> Dict[str, Any]:
        if not has_pii:
            return record

        single_flags = self.finder.check_single(record)
        hidden = {}

        for field, value in record.items():
            if single_flags.get(field) or self.finder.check_combined(record):
                hidden[field] = self.hide_value(field, value)
            else:
                hidden[field] = value

        return hidden



def process_file(input_file: str, output_file: str):
    finder = PersonalInfoFinder()
    hider = PersonalInfoHider()
    results = []

    with open(input_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        print("Columns:", reader.fieldnames)

        for i, row in enumerate(reader, 1):
            try:
                record_id = row.get("record_id") or str(i)

                json_data = None
                for key in ["Data_json", "data_json", "json_data"]:
                    if row.get(key):
                        json_data = row[key].strip()
                        break

                if not json_data:
                    print(f"Row {i} has no JSON data")
                    continue

                if json_data.startswith('"') and json_data.endswith('"'):
                    json_data = json_data[1:-1]

                json_data = json_data.replace('""', '"')

                try:
                    data = json.loads(json_data)
                except json.JSONDecodeError:
                    print(f"Row {i}: bad JSON, using raw row")
                    data = {k: v for k, v in row.items() if k not in ["record_id", "data_json"]}

                has_pii = finder.detect_pii(data)
                hidden = hider.hide_record(data, has_pii)

                results.append({
                    "record_id": record_id,
                    "redacted_data_json": json.dumps(hidden, ensure_ascii=False),
                    "is_pii": has_pii,
                })

            except Exception as e:
                print(f"Row {i} failed: {e}")
                continue


    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["record_id", "redacted_data_json", "is_pii"])
        writer.writeheader()
        writer.writerows(results)

    print(f"Processed {len(results)} records → {output_file}")



if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python detector.py input.csv")
        sys.exit(1)

    inp = sys.argv[1]
    out = inp.replace(".csv", "_redacted.csv")

    process_file(inp, out)
