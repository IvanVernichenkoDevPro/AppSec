# AppSec, DevSecOps

## Infrastructure scans and review for misconfigurations:

### IaC:
- KICS https://github.com/Checkmarx/kics
- TerraScan https://github.com/tenable/terrascan
- Checkov https://www.checkov.io/
- Tfsec https://github.com/aquasecurity/tfsec
- Snyk, Sempgrep, Synopsys - commercial SASTs with IaC support 

### Cloud:
- AWS Security Hub Standarts
- CloudSuite https://github.com/nccgroup/ScoutSuite
- Cloudsploit https://github.com/aquasecurity/cloudsploit
- Commercial CSPM tools

### GitHub:
- Legitify https://github.com/Legit-Labs/legitify

## SCA:
- ODC https://github.com/jeremylong/DependencyCheck
- ODT https://github.com/DependencyTrack
- Checkmarx CxSCA https://checkmarx.com/product/cxsca-open-source-scanning/
- Synopsys Black Buck https://www.synopsys.com/software-integrity/security-testing/software-composition-analysis.html
- Snyk SCA https://github.com/snyk/cli
- Veracode SCA https://www.veracode.com/products/software-composition-analysis

## SAST:
- Semgrep https://semgrep.dev/
- CodeQL https://codeql.github.com/
- Checkmarx https://checkmarx.com/product/cxsast-source-code-scanning/
- SonarQube https://www.sonarqube.org/features/security/
- Synopsys Coverity https://www.synopsys.com/software-integrity/security-testing/static-analysis-sast.html
- Microfocus Fortify https://www.microfocus.com/en-us/cyberres/application-security/static-code-analyzer
- Veracode SAST https://www.veracode.com/products/binary-static-analysis-sast
- Snyk Code https://snyk.io/product/snyk-code/

## DAST:
- OWASP ZAP https://github.com/zaproxy/zaproxy
- Nuclei https://github.com/projectdiscovery/nuclei
- Fuzzers: ffuf https://github.com/ffuf/ffuf
- Burp https://portswigger.net/burp/enterprise
- Detectify https://detectify.com/
- Rapid7 InsightAppSec https://www.rapid7.com/products/insightappsec/
- Teenable https://www.tenable.com/products/tenable-io/web-application-scanning
- Veracode DAST https://www.veracode.com/products/dynamic-analysis-dast

## Kubernetes security (good list: https://github.com/magnologan/awesome-k8s-security):

### Networking & mTLS:
- Calico https://www.tigera.io/tigera-products/calico/
- Istio https://istio.io/

### Secure settings and hardening:
- Kube-bench https://github.com/aquasecurity/kube-bench
- Kube-hunter https://github.com/aquasecurity/kube-hunter
- KubiScan https://github.com/cyberark/KubiScan
- Kubeaudit https://github.com/Shopify/kubeaudit

### Auditing:
- Falco https://github.com/falcosecurity/falco

### Workload/container security
- Trivy https://github.com/aquasecurity/trivy
- Clair https://github.com/quay/clair

### K8s security platforms and aggregators:
- Starboard https://github.com/aquasecurity/starboard
- Stackrox https://github.com/stackrox/stackrox
- Aqua https://www.aquasec.com/aqua-cloud-native-security-platform/

### Policy enforcement:
- OPA https://www.openpolicyagent.org/
- Gatekeeper https://github.com/open-policy-agent/gatekeeper
- Kyverno https://kyverno.io/
