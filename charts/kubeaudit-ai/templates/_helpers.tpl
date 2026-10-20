{{/*
Expand the name of the chart.
*/}}
{{- define "kubeaudit-ai.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kubeaudit-ai.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Generate unified, cached TLS certificates for webhook and secret
*/}}
{{- define "kubeaudit-ai.certs" -}}
{{- if not (hasKey . "KubeAuditCerts") -}}
  {{- $serviceName := printf "%s.%s.svc" (include "kubeaudit-ai.fullname" .) .Release.Namespace -}}
  {{- $altNames := list $serviceName (printf "%s.%s.svc.cluster.local" (include "kubeaudit-ai.fullname" .) .Release.Namespace) -}}
  {{- $ca := genCA "kubeaudit-ca" 3650 -}}
  {{- $cert := genSignedCert $serviceName nil $altNames 365 $ca -}}
  {{- $certMap := dict "tlsCrt" ($cert.Cert | b64enc) "tlsKey" ($cert.Key | b64enc) "caCrt" ($ca.Cert | b64enc) -}}
  {{- $_ := set . "KubeAuditCerts" $certMap -}}
{{- end -}}
{{- toYaml .KubeAuditCerts -}}
{{- end -}}
