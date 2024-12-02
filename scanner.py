import os
import subprocess
import yaml
import csv
from datetime import datetime
import argparse
import json
import shutil


def render_online_chart(chart_name, chart_version):
    """
    Render an online Helm chart to plain Kubernetes YAML files.
    """
    temp_dir = f"helm_chart_{chart_name.replace('/', '_')}"
    os.makedirs(temp_dir, exist_ok=True)

    try:
        command = [
            "helm", "template",
            chart_name,
            "--version", chart_version,
            "--output-dir", temp_dir
        ]
        print(f"Rendering Helm chart '{chart_name}' (version: {chart_version}) from repository...")
        subprocess.run(command, check=True)
        print(f"Rendered chart saved to: {temp_dir}")
        return temp_dir
    except subprocess.CalledProcessError as e:
        print(f"Error rendering Helm chart: {e}")
        raise


def render_local_chart(chart_path):
    """
    Render a local Helm chart package (.tgz) to plain Kubernetes YAML files.
    """
    if not os.path.isfile(chart_path):
        raise FileNotFoundError(f"Chart file {chart_path} does not exist.")

    temp_dir = f"helm_chart_{os.path.basename(chart_path).split('.')[0]}"
    os.makedirs(temp_dir, exist_ok=True)

    try:
        command = [
            "helm", "template",
            chart_path,
            "--output-dir", temp_dir
        ]
        print(f"Rendering Helm chart from local path '{chart_path}'...")
        subprocess.run(command, check=True)
        print(f"Helm chart rendered to: {temp_dir}")
        return temp_dir
    except subprocess.CalledProcessError as e:
        print(f"Error rendering Helm chart: {e}")
        raise


def extract_images(chart_dir):
    """
    Extract container images from rendered Helm chart templates.
    """
    images = []

    for root, _, files in os.walk(chart_dir):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                with open(os.path.join(root, file), 'r') as f:
                    try:
                        content = yaml.safe_load(f)
                        if isinstance(content, dict):
                            for key in ["containers", "initContainers"]:
                                containers = (
                                    content.get("spec", {})
                                    .get("template", {})
                                    .get("spec", {})
                                    .get(key, [])
                                )
                                if containers:
                                    for container in containers:
                                        images.append(container["image"])
                    except yaml.YAMLError:
                        continue
    return images


def scan_images_with_trivy(images):
    """
    Scan container images using Trivy and collect results.
    """
    results = []
    for image in images:
        try:
            command = [
                "trivy", "image",
                "--severity=MEDIUM,HIGH,CRITICAL",
                "--format=json",
                image
            ]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            results.append(json.loads(result.stdout))
        except subprocess.CalledProcessError:
            print(f"Error scanning image: {image}")
    return results


def save_to_csv(scan_results):
    """
    Save the scan results to a CSV file.
    """
    date_prefix = datetime.now().strftime("%Y-%m-%d")
    output_file = f"{date_prefix}_vulnerabilities.csv"
    with open(output_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["image:tag", "component/library", "vulnerability", "severity"])

        for result in scan_results:
            for vuln in result.get("Results", []):
                for finding in vuln.get("Vulnerabilities", []):
                    csvwriter.writerow([
                        vuln.get("Target"),
                        finding.get("PkgName"),
                        finding.get("VulnerabilityID"),
                        finding.get("Severity")
                    ])
    print(f"Results saved to {output_file}")
    return output_file


def clean_up(temp_dir):
    """
    Clean up temporary directories.
    """
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Reporting Tool for Helm Charts")
    parser.add_argument("chart_path_or_name", help="Path to the local Helm chart package (.tgz) or chart name (e.g., repo/chart)")
    parser.add_argument("--version", help="Chart version (required for repository charts)", default=None)
    args = parser.parse_args()

    temp_dir = None

    try:
        # Determine whether input is a local chart or a repository chart
        if args.chart_path_or_name.endswith(".tgz"):
            print("Detected local Helm chart package.")
            temp_dir = render_local_chart(args.chart_path_or_name)
        else:
            if not args.version:
                raise ValueError("Chart version is required for repository charts.")
            print("Detected repository Helm chart.")
            temp_dir = render_online_chart(args.chart_path_or_name, args.version)

        images = extract_images(temp_dir)
        print(f"Images found: {images}")

        if not images:
            print("No images found in the Helm chart.")
            return

        scan_results = scan_images_with_trivy(images)
        save_to_csv(scan_results)
    finally:
        if temp_dir:
            clean_up(temp_dir)


if __name__ == "__main__":
    main()
