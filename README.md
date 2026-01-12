# Torq IP Reputation Steps

## Overview

This application analyzes IP addresses using the [AbuseIPDB](https://www.abuseipdb.com/) service to identify whether they have been flagged for suspicious or harmful behavior.

- **Step 1:** Check the reputation of a single IP address.
- **Step 2:** Check the reputation of multiple IP addresses in batch mode, with summary reporting.

Both steps output results in a clear, structured JSON format suitable for automation, reporting, or manual review.

---

## Getting Started

### 1. AbuseIPDB API Key

- **For interview/demo convenience only:**

  > **API Key:** `db624c41f015c4c8036fa8a086dfba678dc8bbcb5939af71e8089fb995444e4199823bc2336364ba`

  ⚠️ **Warning:** This key is public for demonstration/interview purposes only. In real projects, always store API keys in secrets or environment variables, never in code or documentation.

- To use your own key, sign up at [AbuseIPDB](https://www.abuseipdb.com/) and get your API key from the dashboard (Account → API).

### 2. Clone & Set Up the Project

```bash
git clone https://github.com/omriza5/ip-reputation-steps
cd ip-reputation-steps
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Step 1: Check a Single IP

### Usage

#### Via Python CLI

```bash
export ABUSEIPDB_API_KEY="your-key-here"
export IP_ADDRESS="118.25.6.39"
# Optional: export CONFIDENCE_THRESHOLD="50"  # Default is 70
python check_ip/main.py
```

#### Via Docker

```bash
docker build -t check-ip .
docker run --rm \
	-e ABUSEIPDB_API_KEY="your-key-here" \
	-e IP_ADDRESS="118.25.6.39" \
	check-ip check_ip/main.py
```

### Success Output Example

```json
{
  "step_status": { "code": 0, "message": "success" },
  "api_object": {
    "ip": "118.25.6.39",
    "risk_level": "HIGH",
    "abuse_confidence_score": 87,
    "total_reports": 1542,
    "country_code": "CN",
    "isp": "Tencent Cloud Computing",
    "is_public": true
  }
}
```

### Status Codes

| Code | Message | When                                        |
| ---- | ------- | ------------------------------------------- |
| 0    | success | IP checked successfully                     |
| 1    | failed  | Input validation error (missing/invalid IP) |
| 2    | failed  | API/network/auth/rate limit error           |

## Step 2: Check Multiple IPs (Batch)

### Usage

#### Via Python CLI

```bash
export ABUSEIPDB_API_KEY="your-key-here"
export IP_ADDRESSES="118.25.6.39,8.8.8.8,invalid-ip,1.1.1.1"
# Optional: export CONFIDENCE_THRESHOLD="50"  # Default is 70
python check_ip_batch/main.py
```

#### Via Docker

```bash
docker build -t check-ip-batch .
docker run --rm \
	-e ABUSEIPDB_API_KEY="your-key-here" \
	-e IP_ADDRESSES="118.25.6.39,8.8.8.8,invalid-ip,1.1.1.1" \
	check-ip-batch check-ip-batch/main.py
```

### Success Output Example

```json
{
  "step_status": { "code": 0, "message": "success" },
  "api_object": {
    "summary": {
      "total": 4,
      "successful": 3,
      "failed": 1,
      "risk_counts": { "HIGH": 1, "MEDIUM": 0, "LOW": 2 }
    },
    "results": {
      "118.25.6.39": {
        "risk_level": "HIGH",
        "abuse_confidence_score": 87,
        "total_reports": 1542,
        "country_code": "CN",
        "isp": "Tencent Cloud Computing"
      },
      "8.8.8.8": {
        "risk_level": "LOW",
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "country_code": "US",
        "isp": "Google LLC"
      },
      "1.1.1.1": {
        "risk_level": "LOW",
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "country_code": "AU",
        "isp": "Cloudflare, Inc."
      }
    },
    "errors": {
      "invalid-ip": "Invalid IP address format"
    }
  }
}
```

### Status Codes

| Code | Message         | When                                  |
| ---- | --------------- | ------------------------------------- |
| 0    | success         | All IPs checked successfully          |
| 0    | partial_success | Some IPs succeeded, some failed       |
| 1    | failed          | Input validation error (no valid IPs) |
| 2    | failed          | All API requests failed               |

## Test IPs

| IP            | Expected Result       |
| ------------- | --------------------- |
| 118.25.6.39   | LOW risk              |
| 185.220.101.1 | HIGH risk (Tor exit)  |
| 8.8.8.8       | LOW risk (Google DNS) |
| 1.1.1.1       | LOW risk (Cloudflare) |

---

## Error Response Examples

1. **Validation Error Example**

   ```json
   {
     "step_status": { "code": 1, "message": "failed" },
     "error": "IP_ADDRESS environment variable is required"
   }
   ```

2. **API Error Example**

   ```json
   {
     "step_status": { "code": 2, "message": "failed" },
     "error": "API request failed: Invalid API key or rate limit exceeded"
   }
   ```

## Project Structure

```
ip-reputation-steps/
├── check_ip/
│   ├── __init__.py
│   └── main.py
├── check_ip_batch/
│   ├── __init__.py
│   └── main.py
├── src/
│   └── ip_reputation/
│       ├── __init__.py
│       ├── constants.py
│       ├── exceptions.py
│       ├── models.py
│       ├── api/
│       │   ├── __init__.py
│       │   └── client.py
│       ├── services/
│       │   ├── __init__.py
│       │   └── reputation_service.py
│       └── utils/
│           ├── __init__.py
│           ├── error_handling.py
│           └── validators.py
├── tests/
│   ├── __init__.py
│   └── unit/
│       ├── __init__.py
│       ├── test_check_ip_batch.py
│       ├── test_check_ip.py
│       ├── test_client.py
│       ├── test_reputation_service.py
│       └── test_validators.py
├── Dockerfile
├── pytest.ini
├── README.md
├── requirements-dev.txt
├── requirements.txt
```

---

## Development & Testing

This project follows **PEP 8** conventions and uses **Ruff** for linting and **Black** for code formatting.

To check and fix code style:

```bash
ruff check . --fix
black .
```

To run tests and contribute to development, install the development requirements:

```bash
pip install -r requirements-dev.txt
pytest
```

To generate and view an Allure HTML report locally:

```bash
# Run tests and collect Allure results
pytest --alluredir=allure-results

# Generate the HTML report
allure generate allure-results -o allure-report --clean

# Open the report in your browser
allure open allure-report
```
