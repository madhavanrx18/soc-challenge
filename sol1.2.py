import csv
import json
import re
from typing import Dict, List, Tuple, Any

class PIIDetector:
    def __init__(self):
        # Regex patterns for standalone PII
        self.phone_pattern = re.compile(r'\b\d{10}\b')
        self.aadhar_pattern = re.compile(r'\b\d{4}\s*\d{4}\s*\d{4}\b')
        self.passport_pattern = re.compile(r'\b[A-Z]\d{7}\b')
        self.upi_pattern = re.compile(r'\b[\w\d]+@[\w\d]+\b')
        
        # Email pattern
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
        # Combinatorial PII fields
        self.combinatorial_fields = {
            'name_fields': ['name', 'first_name', 'last_name'],
            'email_fields': ['email'],
            'address_fields': ['address', 'city', 'pin_code', 'state']
        }
    
    def detect_standalone_pii(self, data: Dict[str, Any]) -> Dict[str, bool]:
        """Detect standalone PII that's PII on its own"""
        pii_found = {}
        
        for field, value in data.items():
            if value is None:
                continue
                
            value_str = str(value)
            
            # Phone number detection
            if field == 'phone' or self.phone_pattern.search(value_str):
                pii_found[field] = True
            
            # Aadhar detection
            elif field == 'aadhar' or self.aadhar_pattern.search(value_str):
                pii_found[field] = True
            
            # Passport detection
            elif field == 'passport' or self.passport_pattern.search(value_str):
                pii_found[field] = True
            
            # UPI ID detection
            elif field == 'upi_id' or (self.upi_pattern.search(value_str) and '@' in value_str):
                pii_found[field] = True
            
            else:
                pii_found[field] = False
        
        return pii_found
    
    def detect_combinatorial_pii(self, data: Dict[str, Any]) -> bool:
        """Detect combinatorial PII (needs 2+ fields from specific groups)"""
        present_groups = set()
        
        for field, value in data.items():
            if value is None or str(value).strip() == '':
                continue
            
            # Check if field belongs to combinatorial PII groups
            if field in self.combinatorial_fields['name_fields']:
                # Only count as name if it's a full name (first + last) or explicit 'name' field
                if field == 'name' or self._is_full_name(str(value)):
                    present_groups.add('name')
                elif field in ['first_name', 'last_name']:
                    # Check if both first and last name are present
                    if self._has_both_names(data):
                        present_groups.add('name')
            
            elif field in self.combinatorial_fields['email_fields']:
                if self.email_pattern.search(str(value)):
                    present_groups.add('email')
            
            elif field in self.combinatorial_fields['address_fields']:
                if self._is_complete_address(data):
                    present_groups.add('address')
        
        # PII if 2 or more groups are present
        return len(present_groups) >= 2
    
    def _is_full_name(self, name: str) -> bool:
        """Check if a name string contains both first and last name"""
        parts = name.strip().split()
        return len(parts) >= 2 and all(part.isalpha() for part in parts)
    
    def _has_both_names(self, data: Dict[str, Any]) -> bool:
        """Check if both first_name and last_name are present"""
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        return (first_name and str(first_name).strip() and 
                last_name and str(last_name).strip())
    
    def _is_complete_address(self, data: Dict[str, Any]) -> bool:
        """Check if address is complete (has street + city + pin)"""
        address_components = 0
        
        if data.get('address') and str(data['address']).strip():
            address_components += 1
        if data.get('city') and str(data['city']).strip():
            address_components += 1
        if data.get('pin_code') and str(data['pin_code']).strip():
            address_components += 1
        
        return address_components >= 2
    
    def detect_pii(self, data: Dict[str, Any]) -> bool:
        """Main PII detection function"""
        # Check for standalone PII
        standalone_results = self.detect_standalone_pii(data)
        if any(standalone_results.values()):
            return True
        
        # Check for combinatorial PII
        return self.detect_combinatorial_pii(data)

class PIIRedactor:
    def __init__(self):
        self.detector = PIIDetector()
    
    def redact_value(self, field: str, value: Any) -> str:
        """Redact a specific field value based on its type"""
        if value is None:
            return value
        
        value_str = str(value)
        
        # Phone number redaction
        if field == 'phone' or self.detector.phone_pattern.search(value_str):
            if len(value_str) >= 10:
                return value_str[:2] + 'X' * (len(value_str) - 4) + value_str[-2:]
        
        # Email redaction
        elif '@' in value_str and self.detector.email_pattern.search(value_str):
            parts = value_str.split('@')
            if len(parts[0]) > 2:
                masked_user = parts[0][:2] + 'X' * (len(parts[0]) - 2)
                return f"{masked_user}@{parts[1]}"
        
        # Name redaction
        elif field in ['name', 'first_name', 'last_name']:
            if len(value_str) > 1:
                return value_str[0] + 'X' * (len(value_str) - 1)
        
        # Address redaction
        elif field == 'address':
            return '[REDACTED_ADDRESS]'
        
        # Aadhar redaction
        elif field == 'aadhar':
            return '[REDACTED_AADHAR]'
        
        # Passport redaction
        elif field == 'passport':
            return '[REDACTED_PASSPORT]'
        
        # UPI redaction
        elif field == 'upi_id':
            return '[REDACTED_UPI]'
        
        return value
    
    def redact_record(self, data: Dict[str, Any], is_pii: bool) -> Dict[str, Any]:
        """Redact PII from a record if it contains PII"""
        if not is_pii:
            return data
        
        redacted_data = {}
        standalone_pii = self.detector.detect_standalone_pii(data)
        
        for field, value in data.items():
            # Redact if it's standalone PII
            if standalone_pii.get(field, False):
                redacted_data[field] = self.redact_value(field, value)
            # Redact if it's part of combinatorial PII and record has combinatorial PII
            elif (field in self.detector.combinatorial_fields['name_fields'] or
                  field in self.detector.combinatorial_fields['email_fields'] or
                  field in self.detector.combinatorial_fields['address_fields']):
                if self.detector.detect_combinatorial_pii(data):
                    redacted_data[field] = self.redact_value(field, value)
                else:
                    redacted_data[field] = value
            else:
                redacted_data[field] = value
        
        return redacted_data

def process_csv(input_file: str, output_file: str):
    """Main function to process CSV file"""
    detector = PIIDetector()
    redactor = PIIRedactor()
    
    results = []
    
    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        # Debug: Print column names to identify correct column
        print("Available columns:", reader.fieldnames)
        
        for row_num, row in enumerate(reader, 1):
            try:
                # Handle different possible column names
                record_id = row.get('record_id') or row.get('Record_ID') or str(row_num)
                
                # Try different JSON column names
                json_data = None
                for col_name in ['Data_json', 'data_json', 'Data_JSON', 'json_data']:
                    if col_name in row and row[col_name]:
                        json_data = row[col_name]
                        break
                
                if not json_data:
                    print(f"Warning: No JSON data found in row {row_num}")
                    continue
                
                # Clean and parse JSON - handle CSV escaped quotes
                json_data = json_data.strip()
                
                # Remove outer quotes if present (CSV format)
                if json_data.startswith('"') and json_data.endswith('"'):
                    json_data = json_data[1:-1]
                
                # Handle escaped quotes in CSV format
                json_data = json_data.replace('""', '"')  # Convert "" to "
                
                # Ensure it's properly formatted JSON
                if not json_data.startswith('{'):
                    json_data = '{' + json_data
                if not json_data.endswith('}'):
                    json_data = json_data + '}'
                
                try:
                    data_json = json.loads(json_data)
                except json.JSONDecodeError as json_err:
                    print(f"JSON parsing error in row {row_num}: {json_err}")
                    print(f"Problematic JSON: {json_data[:100]}...")
                    # Try to create a simple dict from the row data
                    data_json = {k: v for k, v in row.items() if k not in ['record_id', 'Record_ID', 'Data_json', 'data_json']}
                
                # Detect PII
                is_pii = detector.detect_pii(data_json)
                
                # Redact if PII found
                redacted_data = redactor.redact_record(data_json, is_pii)
                
                results.append({
                    'record_id': record_id,
                    'redacted_data_json': json.dumps(redacted_data),
                    'is_pii': is_pii
                })
                
            except Exception as e:
                print(f"Error processing row {row_num}: {e}")
                continue
    
    # Write output
    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print(f"Processed {len(results)} records successfully")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python detector.py input_file.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = input_file.replace('.csv', '_redacted.csv')
    
    process_csv(input_file, output_file)
    print(f"Processing complete. Output saved to {output_file}")