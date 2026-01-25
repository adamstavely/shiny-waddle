{{/*
Expand the name of the chart.
*/}}
{{- define "heimdall.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "heimdall.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "heimdall.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "heimdall.labels" -}}
helm.sh/chart: {{ include "heimdall.chart" . }}
{{ include "heimdall.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "heimdall.selectorLabels" -}}
app.kubernetes.io/name: {{ include "heimdall.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
API labels
*/}}
{{- define "heimdall.api.labels" -}}
helm.sh/chart: {{ include "heimdall.chart" . }}
{{ include "heimdall.api.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: api
{{- end }}

{{/*
API selector labels
*/}}
{{- define "heimdall.api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "heimdall.name" . }}-api
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Frontend labels
*/}}
{{- define "heimdall.frontend.labels" -}}
helm.sh/chart: {{ include "heimdall.chart" . }}
{{ include "heimdall.frontend.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Frontend selector labels
*/}}
{{- define "heimdall.frontend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "heimdall.name" . }}-frontend
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "heimdall.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "heimdall.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
API image
*/}}
{{- define "heimdall.api.image" -}}
{{- if .Values.global.imageRegistry }}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.api.image.repository .Values.api.image.tag }}
{{- else }}
{{- printf "%s:%s" .Values.api.image.repository .Values.api.image.tag }}
{{- end }}
{{- end }}

{{/*
Frontend image
*/}}
{{- define "heimdall.frontend.image" -}}
{{- if .Values.global.imageRegistry }}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.frontend.image.repository .Values.frontend.image.tag }}
{{- else }}
{{- printf "%s:%s" .Values.frontend.image.repository .Values.frontend.image.tag }}
{{- end }}
{{- end }}

{{/*
API CORS origin from ingress
*/}}
{{- define "heimdall.api.corsOrigin" -}}
{{- if .Values.ingress.enabled }}
{{- $protocol := "https" }}
{{- if not .Values.ingress.tls }}
{{- $protocol = "http" }}
{{- end }}
{{- range .Values.ingress.hosts }}
{{- printf "%s://%s" $protocol .host }}
{{- break }}
{{- end }}
{{- else }}
{{- .Values.api.env.CORS_ORIGIN }}
{{- end }}
{{- end }}

{{/*
Frontend API URL from ingress
*/}}
{{- define "heimdall.frontend.apiUrl" -}}
{{- if .Values.ingress.enabled }}
{{- $protocol := "https" }}
{{- if not .Values.ingress.tls }}
{{- $protocol = "http" }}
{{- end }}
{{- range .Values.ingress.hosts }}
{{- printf "%s://%s/api" $protocol .host }}
{{- break }}
{{- end }}
{{- else }}
{{- printf "http://%s-api:3001" (include "heimdall.fullname" .) }}
{{- end }}
{{- end }}
