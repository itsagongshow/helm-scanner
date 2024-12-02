# **Helm Chart Vulnerability Scanner**

## **Project Description**

The Helm Chart Vulnerability Scanner is a Python-based tool designed to identify and report vulnerabilities in container images defined within Helm charts. It supports both **online charts from Helm repositories** and **local Helm chart packages** (`.tgz`). The scanner uses **Trivy** to analyze container images and generates a CSV report listing vulnerabilities with severities of **Medium** or higher.

---

## **Features**

- Automatically renders Helm charts (local `.tgz` or repository-based) to extract container images.
- Uses Trivy to perform vulnerability scans on each image.
- Outputs scan results in a CSV format with columns:
  - `image:tag`
  - `component/library`
  - `vulnerability`
  - `severity`
- Automatically cleans up temporary files and directories created during execution.

---

## **Setup Instructions**

### **Prerequisites**

1. **Python**:
   - Version 3.6 or later.
   - Install necessary Python libraries:
     ```bash
     pip install pyyaml
     ```

2. **Helm**:
   - Install Helm CLI:
     ```bash
     brew install helm  # macOS
     sudo apt-get install helm  # Linux
     ```

3. **Trivy**:
   - Install Trivy for vulnerability scanning:
     ```bash
     brew install aquasecurity/trivy  # macOS
     sudo apt install trivy          # Linux
     ```

---

### **Assumptions**

- The **Helm CLI** and **Trivy** are pre-installed on the system or Docker container running the scanner.
- The user has access to either:
  - Helm chart repositories for online charts.
  - Packaged `.tgz` files for local charts.
- Images in the Helm chart are defined under `containers` or `initContainers` in Kubernetes manifests rendered by `helm template`.
- The output CSV file is saved to the current working directory or the specified output location in the mounted volume (when using Docker).

---


### **Running the Script**

#### **Clone the Repository**
```bash
git clone https://github.com/itsagongshow/helm-scanner.git
cd helm-scanner
