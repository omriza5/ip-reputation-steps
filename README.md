# Torq IP Reputation Steps

## Overview

This repository contains two robust, containerized Python command-line tools ("steps") for checking the reputation of IP addresses using the [AbuseIPDB](https://www.abuseipdb.com/) threat intelligence API.

- **Step 1:** Check the reputation of a single IP address.
- **Step 2:** Check the reputation of multiple IP addresses in batch mode, with summary reporting.

Both steps output results in a clear, structured JSON format suitable for automation, reporting, or manual review.

---

## Getting Started

### 1. Get an AbuseIPDB API Key

- Sign up for a free account at [AbuseIPDB](https://www.abuseipdb.com/)
- Go to your dashboard (Account → API) and copy your API key

### 2. Clone & Set Up the Project

```bash
git clone <your-repo-url>
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

### Output Example

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

### Risk Level Logic

- **HIGH:** abuse_confidence_score >= CONFIDENCE_THRESHOLD
- **MEDIUM:** 25 <= abuse_confidence_score < CONFIDENCE_THRESHOLD
- **LOW:** abuse_confidence_score < 25

---

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

### Output Example

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

### Partial Failure Handling

- If some IPs fail and others succeed:
  - `message` is set to `partial_success`
  - Successful results are in `results`
  - Failures are in `errors`
  - Summary counts are updated accordingly

---

## Test IPs

| IP            | Expected Result       |
| ------------- | --------------------- |
| 118.25.6.39   | HIGH risk (malicious) |
| 185.220.101.1 | HIGH risk (Tor exit)  |
| 8.8.8.8       | LOW risk (Google DNS) |
| 1.1.1.1       | LOW risk (Cloudflare) |

---

## Project Structure

```
check_ip/           # Single IP check CLI tool
check_ip_batch/     # Batch IP check CLI tool
src/ip_reputation/  # Core logic, API client, services, utils
Dockerfile          # Docker build instructions
requirements.txt    # Python dependencies
tests/              # Unit tests
```

---

## Development & Testing

- All code is type-annotated and modular for maintainability.
- Unit tests are provided in the `tests/` directory.
- To run tests:
  ```bash
  pip install -r requirements-dev.txt
  pytest
  ```

---

## Support & Contributions

- For questions, open an issue or contact the project maintainer.
- Contributions are welcome! Please fork the repo and submit a pull request.

---

## License

This project is provided for educational and demonstration purposes. See LICENSE for details.
