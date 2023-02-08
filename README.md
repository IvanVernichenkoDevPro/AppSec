# AppSec, DevSecOps

## Threat modelling:
- OWASP Threat Dragon https://github.com/OWASP/threat-dragon 
- Drawio-threat-modelling https://github.com/michenriksen/drawio-threatmodeling
- PyTM https://github.com/izar/pytm
- Threagile https://github.com/Threagile/threagile, https://christian-schneider.net/slides/DEF-CON-2020-Threagile.pdf
- IriusRisk CE https://github.com/iriusrisk/Community
- SecurityCompass https://www.securitycompass.com/sdelements/threat-modeling/

## Infrastructure scans and review for misconfigurations:

### IaC:
- KICS https://github.com/Checkmarx/kics
- TerraScan https://github.com/tenable/terrascan
- Checkov https://www.checkov.io/
- Tfsec https://github.com/aquasecurity/tfsec
- Semgrep (rules for IaC) https://semgrep.dev/
- Snyk, Synopsys, other commercial SASTs with IaC support 

### Cloud:
- AWS Security Hub Standarts
- ScoutSuite https://github.com/nccgroup/ScoutSuite
- Prowler https://github.com/prowler-cloud/prowler
- Cloudsploit https://github.com/aquasecurity/cloudsploit
- Cloud Custodian https://github.com/cloud-custodian/cloud-custodian/
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
- Google's OSV-scanner https://github.com/google/osv-scanner

## Secrets scanners:
- gitLeaks: https://github.com/zricethezav/gitleaks
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- git-secrets: https://github.com/awslabs/git-secrets
- repo-supervisor: https://github.com/auth0/repo-supervisor

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
- Tenable https://www.tenable.com/products/tenable-io/web-application-scanning
- Veracode DAST https://www.veracode.com/products/dynamic-analysis-dast

## Mobile security:
- MobSF https://github.com/MobSF/Mobile-Security-Framework-MobSF
- frida https://frida.re/docs/home/

## Kubernetes security (good list: https://github.com/magnologan/awesome-k8s-security):

### Networking & mTLS:
- Calico https://www.tigera.io/tigera-products/calico/
- Istio https://istio.io/

### Secure settings and hardening:
- Kube-bench https://github.com/aquasecurity/kube-bench
- Kube-hunter https://github.com/aquasecurity/kube-hunter
- KubiScan https://github.com/cyberark/KubiScan
- Kubeaudit https://github.com/Shopify/kubeaudit
- kubescape https://github.com/kubescape/kubescape

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
