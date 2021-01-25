{{/*
Expand the name of the chart.
*/}}
{{- define "sandbox-assignment-api.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "sandbox-assignment-api.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if (eq .Release.Name "RELEASE-NAME") }}
{{- $name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "sandbox-assignment-api.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sandbox-assignment-api.labels" -}}
helm.sh/chart: {{ include "sandbox-assignment-api.chart" . }}
{{ include "sandbox-assignment-api.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sandbox-assignment-api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sandbox-assignment-api.name" . }}
{{- if (ne .Release.Name "RELEASE-NAME") }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- end }}
