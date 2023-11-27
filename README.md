# Fancy AppSec, DevSecOps tools list

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
- regex patterns collection: https://github.com/mazen160/secrets-patterns-db

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
- API fuzzer framework: schemathesis https://github.com/schemathesis/schemathesis
- API scanner/fuzzer: restler https://github.com/microsoft/restler-fuzzer
- Burp https://portswigger.net/burp/enterprise (BSCP exam study: https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- DOMDig - SPA crawler + XSS scanner: https://github.com/fcavallarin/domdig (+burp plugin https://github.com/fcavallarin/burp-dom-scanner)
- Katana project (SPA crawler): https://github.com/projectdiscovery/katana
- Detectify https://detectify.com/
- Acunetix https://www.acunetix.com/product/
- Rapid7 InsightAppSec https://www.rapid7.com/products/insightappsec/
- Qualys WAS (+Community Edition) https://www.qualys.com/apps/web-app-scanning/
- Tenable https://www.tenable.com/products/tenable-io/web-application-scanning
- Veracode DAST https://www.veracode.com/products/dynamic-analysis-dast

## Mobile security:
- MobSF https://github.com/MobSF/Mobile-Security-Framework-MobSF
- frida https://frida.re/docs/home/
- appmon https://github.com/dpnishant/appmon
- qark, drozer (abandoned) https://github.com/linkedin/qark, https://github.com/WithSecureLabs/drozer

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
- Tetragon https://github.com/cilium/tetragon

### Images vulnerability scanners
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

## Pentest reporting
- https://github.com/Syslifters/sysreptor
- https://github.com/1modm/petereport
- Faction engine https://github.com/factionsecurity/faction

## Offensive sectools
- Mythic C2 https://github.com/its-a-feature/Mythic

## Misc
- How to register and publish CVE: https://infosecwriteups.com/how-to-register-and-publish-a-cve-for-your-awesome-vulnerability-e68a6a5f748f
