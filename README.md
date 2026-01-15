# 🕵️ DNS Forensic Analyzer - Detector de Exfiltración DNS

## 📋 Descripción

**DNS Forensic Analyzer** es una herramienta avanzada de análisis forense de red diseñada para detectar y analizar actividades de exfiltración de datos a través de consultas DNS. Este script analiza archivos PCAP para identificar:

- 🔍 **Equipos infectados** que envían datos mediante DNS
- 🔴 **Dominios maliciosos** utilizados como servidores de comando y control (C2)
- 📁 **Archivos exfiltrados** con análisis de completitud y tipo
- 🔗 **Relaciones IP-DNS** y patrones de comunicación
- 🛡️ **Técnicas de evasión** utilizadas por atacantes

## ✨ Características Principales

### 🔍 **Detección Avanzada**

- Análisis heurístico de consultas DNS sospechosas
- Detección de múltiples técnicas de exfiltración
- Identificación de codificaciones (Base32, Base64, Hexadecimal)
- Análisis de patrones de seriado y distribución

### 📊 **Análisis Forense**

- Clasificación automática de IPs (infectadas/maliciosas/sospechosas)
- Cálculo de confianza y scores de comportamiento
- Reconstrucción de archivos exfiltrados
- Análisis temporal de actividades

### 📁 **Reportes Profesionales**

- Generación de reportes HTML ejecutivos
- Visualización interactiva de resultados
- Estadísticas detalladas y métricas
- Recomendaciones de respuesta inmediata

### 🔧 **Técnicas Detectadas**

- DNS Tunneling
- Subdomain Exfiltration
- TXT Record Exfil
- Chunked Transfer
- Long Query Exfiltration
- Encoding-based Exfiltration

## 🚀 Instalación

### Prerrequisitos
```bash
Python 3.8 o superior
pip install pyshark
```

### Instalación de Dependencias
```bash
pip install pyshark
```

## 🎯 Uso

### Ejecución Básica
```bash
python hunter.py captura_trafico.pcap
python hunter.py C:\capturas\malware.pcap
```

### Salida

El script generará:

1. **Análisis en consola** en tiempo real
2. **Reporte HTML** (`dns_exfil_report.html`)
3. **Log de detección** detallado



