#!/usr/bin/env python3
import pyshark
import base64
import re
from collections import Counter, defaultdict
import os
import sys
import json
from datetime import datetime, timedelta
import math

class DNSExfilIPDetector:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.detected_files = []
        self.exfil_sessions = defaultdict(lambda: {
            'domain': '',
            'technique': '',
            'technique_description': '',
            'encoding_type': '',
            'confidence': 0,
            'files': defaultdict(lambda: {
                'filename': '',
                'file_type': '',
                'file_extension': '',
                'file_size': 0,
                'total_chunks': 0,
                'chunks_received': 0,
                'chunks': {},
                'status': 'INCOMPLETE',
                'start_time': None,
                'end_time': None,
                'source_ip': '',
                'transfer_time': 0,
                'completeness': 0,
                'unique_id': ''
            }),
            'src_ip': '',
            'dst_ip': '',
            'total_queries': 0,
            'first_seen': None,
            'last_seen': None,
            'encoding_stats': defaultdict(int)
        })
        
        # Estadísticas de IPs
        self.ip_stats = defaultdict(lambda: {
            'type': 'UNKNOWN',
            'dns_queries': 0,
            'exfil_queries': 0,
            'domains_queried': set(),
            'files_exfiltrated': [],
            'total_data': 0,
            'actual_exfiltrated_data': 0,
            'first_seen': None,
            'last_seen': None,
            'query_frequency': 0,
            'confidence_score': 0,
            'role': '',
            'techniques_used': set(),
            'encodings_used': set()
        })
        
        # Listas finales
        self.malicious_ips = []
        self.infected_ips = []
        self.suspicious_ips = []
        self.exfiltrated_files = []
        
        # Relaciones IP-DNS
        self.ip_dns_relationships = {}
        
        # Estadísticas para el reporte
        self.detection_log = []
        self.technique_details = []
        
        # Estadísticas generales
        self.analysis_summary = {
            'total_packets': 0,
            'exfil_packets': 0,
            'techniques_detected': set(),
            'encodings_detected': set(),
            'total_domains': set(),
            'time_range': {'start': None, 'end': None},
            'total_files_detected': 0,
            'total_files_completed': 0,
            'total_actual_data': 0
        }

    def check_file_exists(self):
        """Verifica que el archivo PCAP exista"""
        if not os.path.exists(self.pcap_file):
            print(f"❌ Archivo no encontrado: {self.pcap_file}")
            return False
        return True

    def detect_encoding_type(self, data_part):
        """Detecta el tipo de codificación utilizado - MEJORADO Y PRECISO"""
        try:
            # Limpiar y preparar datos
            clean_data = data_part.replace('.', '').replace('-', '').replace('_', '')
            
            if not clean_data:
                return 'Unknown'
            
            # Verificar Base64 con validación estricta
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', clean_data):
                try:
                    if len(clean_data) % 4 == 0:
                        decoded = base64.b64decode(clean_data, validate=True)
                        if len(decoded) > 0:
                            return 'Base64'
                except:
                    pass
            
            # Verificar Base32 con validación estricta
            if re.match(r'^[A-Z2-7]*=*$', clean_data):
                try:
                    padded = clean_data + '=' * (8 - len(clean_data) % 8)
                    decoded = base64.b32decode(padded, casefold=True)
                    if len(decoded) > 0:
                        return 'Base32'
                except:
                    pass
            
            # Verificar Hexadecimal estricto
            if re.match(r'^[A-F0-9]+$', clean_data, re.IGNORECASE):
                try:
                    if len(clean_data) % 2 == 0:
                        decoded = bytes.fromhex(clean_data)
                        if len(decoded) > 0:
                            return 'Hexadecimal'
                except:
                    pass
            
            # Detección heurística mejorada
            if len(clean_data) >= 10:
                base64_chars = len(re.findall(r'[A-Za-z0-9+/]', clean_data))
                base32_chars = len(re.findall(r'[A-Z2-7]', clean_data))
                hex_chars = len(re.findall(r'[A-F0-9]', clean_data, re.IGNORECASE))
                
                total_chars = len(clean_data)
                
                # Calcular porcentajes
                base64_ratio = base64_chars / total_chars
                base32_ratio = base32_chars / total_chars
                hex_ratio = hex_chars / total_chars
                
                # Determinar el tipo más probable
                if base64_ratio > 0.9 and '+' in clean_data or '/' in clean_data:
                    return 'Base64_Like'
                elif base32_ratio > 0.9:
                    return 'Base32_Like'
                elif hex_ratio > 0.9:
                    return 'Hex_Like'
                    
        except Exception as e:
            self.detection_log.append(f"❌ Error en detección de codificación: {e}")
        
        return 'Unknown'

    def detect_exfiltration_technique(self, query, chunk_num, data_length):
        """Detecta y describe en detalle la técnica de exfiltración - MÁS PRECISO"""
        
        # Primero detectar codificación PRECISA
        encoding_type = self.detect_encoding_type(query)
        
        techniques = []
        descriptions = []
        
        # Análisis preciso de patrones
        query_parts = query.split('.')
        subdomain_count = len(query_parts) - 2  # Excluir dominio principal y TLD
        
        # Registrar detección para el reporte
        detection_info = {
            'query': query[:100] + '...' if len(query) > 100 else query,
            'chunk': chunk_num,
            'subdomains': subdomain_count,
            'encoding': encoding_type,
            'length': len(query)
        }
        self.detection_log.append(f"🔍 Analizando: {query[:80]}... | Chunks: {chunk_num} | Subdominios: {subdomain_count} | Encoding: {encoding_type}")
        
        # DNS Tunneling - Consultas largas con múltiples chunks y subdominios
        if data_length > 40 and chunk_num > 0 and subdomain_count > 3:
            techniques.append('DNS_Tunneling')
            descriptions.append(f'Tunelización DNS continua usando {subdomain_count} subdominios organizados en {chunk_num+1} segmentos numerados')
        
        # TXT Record Exfiltration - Específico para registros TXT
        elif 'txt' in query.lower() or any(part.lower() in ['txt', 'text'] for part in query_parts):
            techniques.append('TXT_Record_Exfil')
            descriptions.append('Exfiltración especializada mediante registros TXT DNS para evadir firewalls')
        
        # Subdomain Exfiltration - Fragmentación en múltiples niveles
        elif subdomain_count >= 4:
            techniques.append('Subdomain_Exfil')
            descriptions.append(f'Fragmentación de datos distribuida en {subdomain_count} niveles jerárquicos de subdominios')
        
        # Chunked Transfer - Transferencia secuencial numerada
        elif chunk_num > 0 and re.search(r'\.\d+\.', query):
            techniques.append('Chunked_Transfer')
            descriptions.append(f'Transferencia secuencial segmentada en partes numeradas (segmento {chunk_num})')
        
        # Long Query Exfiltration - Consultas anormalmente largas
        elif len(query) > 120:
            techniques.append('Long_Query_Exfil')
            descriptions.append(f'Consulta DNS de longitud anómala ({len(query)} caracteres) maximizando límites de protocolo')
        
        # Data Encoding Patterns - Basado en codificación detectada
        elif encoding_type != 'Unknown':
            if encoding_type == 'Base32':
                techniques.append('Base32_Encoded_Exfil')
                descriptions.append('Exfiltración utilizando codificación Base32 para ofuscar datos y evitar detección')
            elif encoding_type == 'Base64':
                techniques.append('Base64_Encoded_Exfil')
                descriptions.append('Exfiltración utilizando codificación Base64 estándar para embeber datos binarios')
            elif encoding_type == 'Hexadecimal':
                techniques.append('Hex_Encoded_Exfil')
                descriptions.append('Exfiltración mediante codificación Hexadecimal simple para transferir datos crudos')
            else:
                techniques.append(f'{encoding_type}_Encoded')
                descriptions.append(f'Exfiltración con datos ofuscados usando esquema {encoding_type}')
        
        # Default - Exfiltración básica
        else:
            if data_length > 20:
                techniques.append('Standard_DNS_Exfil')
                descriptions.append('Exfiltración DNS estándar con datos embebidos en consultas convencionales')
            else:
                return 'Unknown', 'No se detectó técnica de exfiltración clara', 'Unknown'
        
        primary_technique = techniques[0] if techniques else 'Unknown'
        technique_description = " | ".join(descriptions) if descriptions else 'Técnica no identificada'
        
        # Guardar detalles de técnica para el reporte
        if primary_technique != 'Unknown':
            self.technique_details.append({
                'technique': primary_technique,
                'encoding': encoding_type,
                'description': technique_description,
                'query_sample': query[:80] + '...' if len(query) > 80 else query,
                'chunk_num': chunk_num,
                'subdomain_count': subdomain_count
            })
        
        return primary_technique, technique_description, encoding_type

    def analyze_ip_dns_relationships(self):
        """Analiza la relación entre IPs y dominios maliciosos"""
        self.detection_log.append("🔗 Analizando relaciones IP-DNS...")
        
        self.ip_dns_relationships = {}
        
        for session_key, session_data in self.exfil_sessions.items():
            src_ip = session_data['src_ip']
            domain = session_data['domain']
            
            if src_ip not in self.ip_dns_relationships:
                self.ip_dns_relationships[src_ip] = {
                    'domains': set(),
                    'total_queries': 0,
                    'first_seen': None,
                    'last_seen': None,
                    'techniques': set(),
                    'files_exfiltrated': []
                }
            
            self.ip_dns_relationships[src_ip]['domains'].add(domain)
            self.ip_dns_relationships[src_ip]['total_queries'] += session_data['total_queries']
            self.ip_dns_relationships[src_ip]['techniques'].add(session_data['technique'])
            
            # Agregar archivos
            for filename, file_info in session_data['files'].items():
                if filename and file_info['file_size'] > 0:
                    file_data = {
                        'filename': filename,
                        'file_size': file_info['file_size'],
                        'completeness': file_info['completeness']
                    }
                    if file_data not in self.ip_dns_relationships[src_ip]['files_exfiltrated']:
                        self.ip_dns_relationships[src_ip]['files_exfiltrated'].append(file_data)
            
            # Actualizar timestamps
            if not self.ip_dns_relationships[src_ip]['first_seen'] or session_data['first_seen'] < self.ip_dns_relationships[src_ip]['first_seen']:
                self.ip_dns_relationships[src_ip]['first_seen'] = session_data['first_seen']
            if not self.ip_dns_relationships[src_ip]['last_seen'] or session_data['last_seen'] > self.ip_dns_relationships[src_ip]['last_seen']:
                self.ip_dns_relationships[src_ip]['last_seen'] = session_data['last_seen']
        
        # Calcular relación de seriado
        for ip, relationship in self.ip_dns_relationships.items():
            relationship['is_serialized'] = len(relationship['domains']) == 1
            relationship['relationship_strength'] = min(relationship['total_queries'] / 10, 100)

    def analyze_ip_behavior(self):
        """Analiza el comportamiento de las IPs para clasificarlas CORRECTAMENTE"""
        self.detection_log.append("🔍 Analizando comportamiento de IPs...")
        
        for session_key, session_data in self.exfil_sessions.items():
            src_ip = session_data['src_ip']  # IP que hace la consulta
            domain = session_data['domain']  # DOMINIO malicioso
            
            if src_ip != 'N/A':
                # CORRECCIÓN: La IP de origen es la INFECTADA (hace consultas DNS)
                self.ip_stats[src_ip]['type'] = 'INFECTED'
                self.ip_stats[src_ip]['role'] = 'infected_client'
                self.ip_stats[src_ip]['exfil_queries'] += session_data['total_queries']
                
                # Agregar archivos exfiltrados por esta IP INFECTADA
                for filename, file_info in session_data['files'].items():
                    if filename and file_info['file_size'] > 0:
                        file_data = {
                            'filename': filename,
                            'file_type': file_info['file_type'],
                            'file_size': file_info['file_size'],
                            'actual_size': file_info['file_size'] * (file_info['completeness'] / 100),
                            'status': file_info['status'],
                            'completeness': file_info['completeness']
                        }
                        self.ip_stats[src_ip]['files_exfiltrated'].append(file_data)
                        self.ip_stats[src_ip]['actual_exfiltrated_data'] += file_data['actual_size']
                
                self.ip_stats[src_ip]['domains_queried'].add(domain)
                self.ip_stats[src_ip]['techniques_used'].add(session_data['technique'])
                if session_data['encoding_type']:
                    self.ip_stats[src_ip]['encodings_used'].add(session_data['encoding_type'])
                
                # El DOMINIO es el servidor malicioso, no la IP de destino
                if domain not in self.ip_stats:
                    self.ip_stats[domain] = {
                        'type': 'MALICIOUS_DOMAIN',
                        'role': 'malicious_domain',
                        'dns_queries': 0,
                        'exfil_queries': 0,
                        'domains_queried': set(),
                        'files_exfiltrated': [],
                        'total_data': 0,
                        'actual_exfiltrated_data': 0,
                        'first_seen': None,
                        'last_seen': None,
                        'query_frequency': 0,
                        'confidence_score': 0,
                        'techniques_used': set(),
                        'encodings_used': set()
                    }
                
                self.ip_stats[domain]['exfil_queries'] += session_data['total_queries']
                self.ip_stats[domain]['domains_queried'].add(domain)
                self.ip_stats[domain]['techniques_used'].add(session_data['technique'])
                if session_data['encoding_type']:
                    self.ip_stats[domain]['encodings_used'].add(session_data['encoding_type'])
                
                # Actualizar timestamps
                if not self.ip_stats[src_ip]['first_seen'] or session_data['first_seen'] < self.ip_stats[src_ip]['first_seen']:
                    self.ip_stats[src_ip]['first_seen'] = session_data['first_seen']
                if not self.ip_stats[src_ip]['last_seen'] or session_data['last_seen'] > self.ip_stats[src_ip]['last_seen']:
                    self.ip_stats[src_ip]['last_seen'] = session_data['last_seen']
                
                if not self.ip_stats[domain]['first_seen'] or session_data['first_seen'] < self.ip_stats[domain]['first_seen']:
                    self.ip_stats[domain]['first_seen'] = session_data['first_seen']
                if not self.ip_stats[domain]['last_seen'] or session_data['last_seen'] > self.ip_stats[domain]['last_seen']:
                    self.ip_stats[domain]['last_seen'] = session_data['last_seen']

        # Recalcular scores
        self.calculate_ip_scores_fixed()
        
        # Reclasificar IPs
        self.classify_ips_fixed()
        
        # Recolectar archivos exfiltrados
        self.collect_exfiltrated_files()
        
        # Analizar relaciones IP-DNS
        self.analyze_ip_dns_relationships()
        
        # Calcular estadísticas generales
        self.calculate_global_stats()

    def calculate_ip_scores_fixed(self):
        """Calcula scores de confianza CORREGIDOS para PCAP desde infectado"""
        for ip, stats in self.ip_stats.items():
            if stats['first_seen'] and stats['last_seen']:
                duration = (stats['last_seen'] - stats['first_seen']).total_seconds()
                if duration > 0:
                    stats['query_frequency'] = stats['exfil_queries'] / (duration / 60)
            
            confidence_score = 0
            
            if stats['role'] == 'infected_client':
                # Puntos para IPs INFECTADAS (envían consultas DNS)
                if len(stats['files_exfiltrated']) > 0:
                    confidence_score += 60
                if stats['actual_exfiltrated_data'] > 1024 * 1024:
                    confidence_score += 30
                if stats['exfil_queries'] > 50:
                    confidence_score += 25
                if len(stats['domains_queried']) > 1:
                    confidence_score += 15
                    
            elif stats['role'] == 'malicious_domain':
                # Puntos para DOMINIOS MALICIOSOS
                suspicious_keywords = ['exfil', 'data', 'tunnel', 'leak', 'secret', 'malware', 'steal']
                domain_lower = ' '.join(stats['domains_queried']).lower()
                if any(keyword in domain_lower for keyword in suspicious_keywords):
                    confidence_score += 70
                if stats['exfil_queries'] > 50:
                    confidence_score += 40
                if len(stats['techniques_used']) > 1:
                    confidence_score += 20
            
            stats['confidence_score'] = min(confidence_score, 100)

    def classify_ips_fixed(self):
        """Clasifica las IPs CORRECTAMENTE para PCAP desde infectado"""
        self.malicious_ips = []
        self.infected_ips = []
        self.suspicious_ips = []
        
        for ip, stats in self.ip_stats.items():
            if stats['confidence_score'] >= 50:
                if stats['role'] == 'malicious_domain':
                    self.malicious_ips.append({
                        'ip': ip,
                        'confidence': stats['confidence_score'],
                        'domains': list(stats['domains_queried']),
                        'total_queries': stats['exfil_queries'],
                        'first_seen': stats['first_seen'],
                        'last_seen': stats['last_seen'],
                        'query_frequency': stats['query_frequency'],
                        'role': 'Dominio Malicioso',
                        'files_received': len(stats['files_exfiltrated']),
                        'techniques': list(stats['techniques_used']),
                        'encodings': list(stats['encodings_used'])
                    })
                elif stats['role'] == 'infected_client':
                    self.infected_ips.append({
                        'ip': ip,
                        'confidence': stats['confidence_score'],
                        'files_exfiltrated': stats['files_exfiltrated'],
                        'total_data': stats['total_data'],
                        'actual_exfiltrated_data': stats['actual_exfiltrated_data'],
                        'domains_queried': list(stats['domains_queried']),
                        'first_seen': stats['first_seen'],
                        'last_seen': stats['last_seen'],
                        'query_frequency': stats['query_frequency'],
                        'role': 'Cliente Infectado',
                        'techniques': list(stats['techniques_used']),
                        'encodings': list(stats['encodings_used'])
                    })
            elif stats['confidence_score'] >= 20:
                self.suspicious_ips.append({
                    'ip': ip,
                    'type': stats['type'],
                    'role': stats['role'],
                    'confidence': stats['confidence_score'],
                    'reason': 'Comportamiento sospechoso detectado'
                })

    def collect_exfiltrated_files(self):
        """Recolecta todos los archivos exfiltrados (ÚNICOS y con datos reales)"""
        seen_files = set()
        
        for session_key, session_data in self.exfil_sessions.items():
            for filename, file_info in session_data['files'].items():
                if filename and file_info['file_size'] > 0:
                    file_id = f"{filename}_{file_info['file_size']}_{file_info['source_ip']}"
                    
                    if file_id not in seen_files:
                        seen_files.add(file_id)
                        
                        file_extension = filename.split('.')[-1].lower() if '.' in filename else 'sin_ext'
                        transfer_time = 0
                        if file_info['start_time'] and file_info.get('end_time'):
                            transfer_time = (file_info['end_time'] - file_info['start_time']).total_seconds()
                        
                        completeness = 0
                        if file_info['total_chunks'] > 0:
                            completeness = (file_info['chunks_received'] / file_info['total_chunks']) * 100
                        else:
                            completeness = 100
                        
                        if completeness >= 50:
                            self.exfiltrated_files.append({
                                'filename': filename,
                                'file_type': file_info['file_type'],
                                'file_extension': file_extension,
                                'file_icon': file_info.get('file_icon', '📁'),
                                'file_size': file_info['file_size'],
                                'actual_size': file_info['file_size'] * (completeness / 100),
                                'source_ip': file_info['source_ip'],
                                'destination_domain': session_data['domain'],
                                'status': 'COMPLETADO' if completeness >= 95 else 'PARCIAL',
                                'start_time': file_info['start_time'],
                                'transfer_time': transfer_time,
                                'chunks_received': file_info['chunks_received'],
                                'total_chunks': file_info['total_chunks'],
                                'technique': session_data['technique'],
                                'encoding': session_data['encoding_type'],
                                'completeness': completeness,
                                'unique_id': file_id,
                                'is_duplicate': False
                            })

    def calculate_global_stats(self):
        """Calcula estadísticas globales del análisis"""
        if self.exfiltrated_files:
            self.analysis_summary['time_range']['start'] = min(f['start_time'] for f in self.exfiltrated_files)
            self.analysis_summary['time_range']['end'] = max(f.get('end_time', f['start_time']) for f in self.exfiltrated_files)
        
        for session in self.exfil_sessions.values():
            self.analysis_summary['techniques_detected'].add(session['technique'])
            if session['encoding_type']:
                self.analysis_summary['encodings_detected'].add(session['encoding_type'])
            self.analysis_summary['total_domains'].add(session['domain'])
        
        unique_files = set()
        completed_files = 0
        total_actual_data = 0
        
        for file_info in self.exfiltrated_files:
            file_id = file_info['unique_id']
            if file_id not in unique_files:
                unique_files.add(file_id)
                if file_info['completeness'] >= 95:
                    completed_files += 1
                total_actual_data += file_info['file_size'] * (file_info['completeness'] / 100)
        
        self.analysis_summary['total_files_detected'] = len(unique_files)
        self.analysis_summary['total_files_completed'] = completed_files
        self.analysis_summary['total_actual_data'] = total_actual_data

    def analyze_dns_queries(self):
        """Analiza consultas DNS para detectar exfiltración - MEJORADO"""
        if not self.check_file_exists():
            return False
        
        self.detection_log.append("🔍 Analizando tráfico DNS para exfiltración...")
        self.detection_log.append(f"📁 Archivo: {self.pcap_file}")
        self.detection_log.append("🎯 Identificando IPs infectadas y dominios maliciosos...")
        
        try:
            # Usar display_filter más amplio para capturar más tráfico DNS
            capture = pyshark.FileCapture(self.pcap_file, display_filter='dns')
            
            packet_count = 0
            exfil_packets = 0
            
            for packet in capture:
                packet_count += 1
                
                try:
                    if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                        query = packet.dns.qry_name
                        src_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
                        dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
                        timestamp = packet.sniff_time
                        
                        if not self.analysis_summary['time_range']['start'] or timestamp < self.analysis_summary['time_range']['start']:
                            self.analysis_summary['time_range']['start'] = timestamp
                        if not self.analysis_summary['time_range']['end'] or timestamp > self.analysis_summary['time_range']['end']:
                            self.analysis_summary['time_range']['end'] = timestamp
                        
                        # EXTRAER DATOS MEJORADO - Buscar patrones más flexibles
                        session_id, chunk_num, chunk_data, encoding_type = self.extract_exfil_data_improved(query)
                        
                        if session_id and chunk_data:
                            exfil_packets += 1
                            self.process_exfil_packet(session_id, chunk_num, chunk_data, encoding_type, src_ip, dst_ip, timestamp, query)
                        else:
                            # Intentar detección más agresiva
                            session_id, chunk_num, chunk_data, encoding_type = self.aggressive_exfil_detection(query)
                            if session_id and chunk_data:
                                exfil_packets += 1
                                self.process_exfil_packet(session_id, chunk_num, chunk_data, encoding_type, src_ip, dst_ip, timestamp, query)
                
                except Exception as e:
                    if packet_count % 1000 == 0:  # Solo mostrar cada 1000 paquetes para no saturar
                        self.detection_log.append(f"⚠️ Error en paquete {packet_count}: {e}")
                    continue
            
            capture.close()
            
            self.analysis_summary['total_packets'] = packet_count
            self.analysis_summary['exfil_packets'] = exfil_packets
            
            self.detection_log.append(f"📊 Procesados {packet_count} paquetes, {exfil_packets} paquetes de exfiltración")
            
            if exfil_packets == 0:
                self.detection_log.append("⚠️ No se detectaron paquetes de exfiltración. Revisando con método agresivo...")
                self.aggressive_analysis()
            
            self.analyze_ip_behavior()
            return True
            
        except Exception as e:
            self.detection_log.append(f"❌ Error analizando PCAP: {e}")
            return False

    def extract_exfil_data_improved(self, query):
        """Extrae datos de exfiltración de consultas DNS - MEJORADO"""
        try:
            # Patrones más flexibles para diferentes técnicas
            patterns = [
                # Patrón: session.chunk.data.domain
                r'([a-f0-9]{6,16})\.(\d+)\.([A-Za-z0-9+/=_-]{10,})\.',
                # Patrón: data.chunk.session.domain  
                r'([A-Za-z0-9+/=_-]{15,})\.(\d+)\.([a-f0-9]{6,16})\.',
                # Patrón: chunk.data.domain (sin session)
                r'(\d+)\.([A-Za-z0-9+/=_-]{15,})\.',
                # Solo datos largos
                r'([A-Za-z0-9+/=_-]{20,})\.',
                # Patrones hexadecimales
                r'([A-F0-9]{20,})\.(\d+)\.',
                # Patrones con guiones y underscores
                r'([A-Za-z0-9_-]{20,})\.(\d+)\.([a-f0-9]{6,12})\.',
                # Patrón simple para datos codificados
                r'([A-Za-z0-9+/=]{15,})\.'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, query, re.IGNORECASE)
                if match:
                    groups = match.groups()
                    if len(groups) == 3:
                        session_id, chunk_num, data_part = groups[0], int(groups[1]), groups[2]
                    elif len(groups) == 2:
                        if groups[0].isdigit():
                            session_id, chunk_num, data_part = "default", int(groups[0]), groups[1]
                        else:
                            session_id, chunk_num, data_part = groups[0], 0, groups[1]
                    else:
                        session_id, chunk_num, data_part = "default", 0, groups[0]
                    
                    encoding_type = self.detect_encoding_type(data_part)
                    
                    decoded_data = self.decode_data(data_part, encoding_type)
                    if decoded_data:
                        self.detection_log.append(f"✅ Datos extraídos: Session={session_id}, Chunk={chunk_num}, Encoding={encoding_type}")
                        return session_id, chunk_num, decoded_data, encoding_type
                    else:
                        # Si no se puede decodificar, usar los datos crudos
                        return session_id, chunk_num, data_part.encode('utf-8'), encoding_type
        
        except Exception as e:
            self.detection_log.append(f"⚠️ Error en extract_exfil_data: {e}")
        
        return None, None, None, None

    def aggressive_exfil_detection(self, query):
        """Detección agresiva de exfiltración para consultas difíciles"""
        try:
            # Buscar cualquier dato que parezca codificado
            patterns = [
                r'([A-Za-z0-9+/=_-]{15,})',
                r'([A-F0-9]{20,})',
                r'([A-Z2-7]{15,})'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, query, re.IGNORECASE)
                for match in matches:
                    if len(match) >= 15:  # Mínimo longitud para considerar datos
                        encoding_type = self.detect_encoding_type(match)
                        if encoding_type != 'Unknown':
                            session_id = f"agg_{hash(match) % 10000:04d}"
                            self.detection_log.append(f"🔄 Detección agresiva: {match[:30]}... | Encoding: {encoding_type}")
                            return session_id, 0, match.encode('utf-8'), encoding_type
        
        except Exception as e:
            self.detection_log.append(f"⚠️ Error en detección agresiva: {e}")
        
        return None, None, None, None

    def aggressive_analysis(self):
        """Análisis agresivo para encontrar exfiltración oculta"""
        self.detection_log.append("🔄 Ejecutando análisis agresivo...")
        try:
            capture = pyshark.FileCapture(self.pcap_file, display_filter='dns')
            
            for packet in capture:
                try:
                    if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                        query = packet.dns.qry_name
                        src_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
                        dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
                        timestamp = packet.sniff_time
                        
                        # Buscar cualquier consulta larga o con patrones sospechosos
                        if len(query) > 80:
                            # Detectar técnica directamente desde la consulta
                            technique, description, encoding = self.detect_exfiltration_technique(query, 0, len(query))
                            if technique != 'Unknown':
                                session_id = f"agg_{hash(query) % 10000:04d}"
                                self.process_exfil_packet(session_id, 0, query.encode('utf-8'), encoding, src_ip, dst_ip, timestamp, query)
                                self.detection_log.append(f"🔍 Consulta sospechosa detectada: {technique} - {query[:60]}...")
                
                except Exception:
                    continue
            
            capture.close()
            
        except Exception as e:
            self.detection_log.append(f"❌ Error en análisis agresivo: {e}")

    def decode_data(self, encoded_data, encoding_type):
        """Decodifica datos de diferentes codificaciones"""
        try:
            if encoding_type == 'Base32':
                padded = encoded_data.upper().ljust(8 * ((len(encoded_data) + 7) // 8), '=')
                return base64.b32decode(padded)
            elif encoding_type == 'Base64':
                # Añadir padding si es necesario
                padded = encoded_data + '=' * (4 - len(encoded_data) % 4)
                return base64.b64decode(padded)
            elif encoding_type == 'Hexadecimal':
                return bytes.fromhex(encoded_data)
            elif encoding_type in ['Base64_Like', 'Base32_Like', 'Hex_Like']:
                # Intentar decodificaciones automáticas
                try:
                    padded = encoded_data.upper().ljust(8 * ((len(encoded_data) + 7) // 8), '=')
                    return base64.b32decode(padded)
                except:
                    try:
                        padded = encoded_data + '=' * (4 - len(encoded_data) % 4)
                        return base64.b64decode(padded)
                    except:
                        try:
                            return bytes.fromhex(encoded_data)
                        except:
                            return None
            else:
                return None
        except:
            return None

    def process_exfil_packet(self, session_id, chunk_num, chunk_data, encoding_type, src_ip, dst_ip, timestamp, query):
        """Procesa un paquete de exfiltración - ACTUALIZADO"""
        session_key = f"{src_ip}_{dst_ip}_{session_id}"
        
        if session_key not in self.exfil_sessions:
            # Usar la nueva función que retorna 3 valores
            primary_technique, technique_description, detected_encoding = self.detect_exfiltration_technique(query, chunk_num, len(chunk_data))
            
            # Usar la codificación detectada en la función, no la pasada como parámetro
            actual_encoding = detected_encoding if detected_encoding != 'Unknown' else encoding_type
            
            self.exfil_sessions[session_key].update({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'domain': self.extract_domain(query),
                'technique': primary_technique,
                'technique_description': technique_description,
                'encoding_type': actual_encoding,
                'first_seen': timestamp,
                'last_seen': timestamp
            })
        
        self.exfil_sessions[session_key]['total_queries'] += 1
        self.exfil_sessions[session_key]['last_seen'] = timestamp
        self.exfil_sessions[session_key]['encoding_stats'][encoding_type] += 1
        
        if chunk_num == 0:
            filename, total_chunks, file_size = self.extract_file_metadata(chunk_data)
            if filename:
                file_type, file_icon, file_extension = self.get_file_type(filename)
                
                self.exfil_sessions[session_key]['files'][filename].update({
                    'filename': filename,
                    'file_type': file_type,
                    'file_extension': file_extension,
                    'file_icon': file_icon,
                    'file_size': file_size,
                    'total_chunks': total_chunks,
                    'source_ip': src_ip,
                    'start_time': timestamp,
                    'completeness': 0
                })
                self.detection_log.append(f"📁 Detectado archivo: {file_icon} {filename} ({file_type}) - {file_size} bytes")
        else:
            for filename, file_info in self.exfil_sessions[session_key]['files'].items():
                if file_info['total_chunks'] > 0:
                    self.exfil_sessions[session_key]['files'][filename]['chunks'][chunk_num] = chunk_data
                    self.exfil_sessions[session_key]['files'][filename]['chunks_received'] += 1
                    self.exfil_sessions[session_key]['files'][filename]['end_time'] = timestamp
                    
                    current_completeness = (self.exfil_sessions[session_key]['files'][filename]['chunks_received'] / file_info['total_chunks']) * 100
                    self.exfil_sessions[session_key]['files'][filename]['completeness'] = current_completeness

    def extract_domain(self, query):
        """Extrae el dominio de la consulta DNS"""
        try:
            parts = query.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
        except:
            pass
        return 'unknown'

    def extract_file_metadata(self, decoded_data):
        """Extrae metadatos de archivo"""
        try:
            # Intentar decodificar como texto
            if isinstance(decoded_data, bytes):
                metadata_str = decoded_data.decode('utf-8', errors='ignore')
            else:
                metadata_str = str(decoded_data)
            
            # Buscar diferentes formatos de metadatos
            if '|' in metadata_str:
                parts = metadata_str.split('|')
                if len(parts) >= 3:
                    return parts[0], int(parts[1]), int(parts[2])
            elif ',' in metadata_str:
                parts = metadata_str.split(',')
                if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
                    return parts[0], int(parts[1]), int(parts[2])
            elif ':' in metadata_str:
                parts = metadata_str.split(':')
                if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
                    return parts[0], int(parts[1]), int(parts[2])
            
        except Exception as e:
            self.detection_log.append(f"⚠️ Error extrayendo metadatos: {e}")
        
        # Si no se pueden extraer metadatos, generar unos por defecto
        filename = f"file_{hash(str(decoded_data)) % 10000:04d}.dat"
        return filename, 10, len(decoded_data) * 2  # Valores por defecto

    def get_file_type(self, filename):
        """Determina el tipo de archivo"""
        file_types = {
            'txt': ('Texto', '📄', 'txt'),
            'doc': ('Word', '📝', 'doc'),
            'docx': ('Word', '📝', 'docx'),
            'pdf': ('PDF', '📕', 'pdf'),
            'xls': ('Excel', '📊', 'xls'),
            'xlsx': ('Excel', '📊', 'xlsx'),
            'ppt': ('PowerPoint', '📑', 'ppt'),
            'pptx': ('PowerPoint', '📑', 'pptx'),
            'jpg': ('Imagen', '🖼️', 'jpg'),
            'jpeg': ('Imagen', '🖼️', 'jpeg'),
            'png': ('Imagen', '🖼️', 'png'),
            'zip': ('Comprimido', '📦', 'zip'),
            'config': ('Configuración', '⚙️', 'config'),
            'json': ('JSON', '📋', 'json'),
            'xml': ('XML', '📋', 'xml'),
            'log': ('Log', '📋', 'log'),
            'dat': ('Datos', '📁', 'dat'),
            'bin': ('Binario', '💾', 'bin')
        }
        ext = filename.split('.')[-1].lower() if '.' in filename else 'unknown'
        return file_types.get(ext, ('Desconocido', '📁', ext))

    def generate_html_report(self, output_file="dns_exfil_report.html"):
        """Genera un reporte HTML ejecutivo profesional - COMPLETAMENTE MEJORADO"""
        
        total_actual_data_mb = self.analysis_summary['total_actual_data'] / (1024 * 1024)
        total_files_unique = self.analysis_summary['total_files_detected']
        total_files_completed = self.analysis_summary['total_files_completed']
        
        unique_files = []
        seen_ids = set()
        for file_info in self.exfiltrated_files:
            if file_info['unique_id'] not in seen_ids:
                seen_ids.add(file_info['unique_id'])
                unique_files.append(file_info)

        # Análisis detallado de técnicas por sesión
        technique_stats = {}
        for session_id, session_data in self.exfil_sessions.items():
            technique = session_data['technique']
            encoding = session_data['encoding_type']
            domain = session_data['domain']
            
            if technique not in technique_stats:
                technique_stats[technique] = {
                    'encoding': encoding,
                    'domains': set(),
                    'sessions': 0,
                    'queries': 0,
                    'description': session_data.get('technique_description', '')
                }
            
            technique_stats[technique]['domains'].add(domain)
            technique_stats[technique]['sessions'] += 1
            technique_stats[technique]['queries'] += session_data['total_queries']

        html_content = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte Forense DNS - Análisis de Exfiltración</title>
    <style>
        :root {{
            --dark-bg: #0a0f1c;
            --card-bg: #111827;
            --accent: #1e40af;
            --accent-hover: #1e3a8a;
            --danger: #dc2626;
            --warning: #d97706;
            --success: #059669;
            --purple: #7c3aed;
            --blue-light: #3b82f6;
            --blue-dark: #1e3a8a;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --border: #1f2937;
            --shadow: rgba(0, 0, 0, 0.4);
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--dark-bg);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, var(--card-bg), var(--blue-dark));
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 12px 30px var(--shadow);
            margin-bottom: 30px;
            border: 1px solid var(--border);
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, var(--accent), var(--blue-light));
        }}
        
        .header h1 {{
            color: var(--text-primary);
            font-size: 2.8em;
            margin-bottom: 10px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        
        .header .subtitle {{
            color: var(--text-secondary);
            font-size: 1.3em;
            opacity: 0.9;
            font-weight: 400;
        }}
        
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 24px;
            margin-bottom: 40px;
        }}
        
        .dashboard-card {{
            background: var(--card-bg);
            padding: 30px;
            border-radius: 16px;
            box-shadow: 0 8px 25px var(--shadow);
            border: 1px solid var(--border);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        
        .dashboard-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent), var(--blue-light));
        }}
        
        .dashboard-card:hover {{
            transform: translateY(-8px);
            box-shadow: 0 15px 35px var(--shadow);
        }}
        
        .metric-value {{
            font-size: 3em;
            font-weight: 800;
            margin-bottom: 10px;
            background: linear-gradient(135deg, var(--text-primary), var(--blue-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .metric-label {{
            color: var(--text-secondary);
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        
        .metric-description {{
            color: var(--text-secondary);
            font-size: 0.9em;
            opacity: 0.8;
            line-height: 1.4;
        }}
        
        .techniques-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .technique-card {{
            background: var(--card-bg);
            padding: 25px;
            border-radius: 12px;
            border: 1px solid var(--border);
            transition: all 0.3s ease;
        }}
        
        .technique-card:hover {{
            border-color: var(--accent);
            transform: translateY(-2px);
        }}
        
        .technique-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .technique-name {{
            font-size: 1.2em;
            font-weight: 700;
            color: var(--text-primary);
            background: linear-gradient(135deg, var(--accent), var(--blue-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .encoding-badge {{
            background: linear-gradient(135deg, var(--success), #10b981);
            color: white;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            margin-left: 12px;
        }}
        
        .encoding-badge.base32 {{
            background: linear-gradient(135deg, #d97706, #f59e0b);
        }}
        
        .encoding-badge.base64 {{
            background: linear-gradient(135deg, #059669, #10b981);
        }}
        
        .encoding-badge.hex {{
            background: linear-gradient(135deg, #7c3aed, #8b5cf6);
        }}
        
        .technique-description {{
            color: var(--text-secondary);
            font-size: 0.95em;
            line-height: 1.5;
            margin-bottom: 12px;
        }}
        
        .technique-stats {{
            display: flex;
            gap: 15px;
            font-size: 0.9em;
            color: var(--text-secondary);
        }}
        
        .stat-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .section {{
            background: var(--card-bg);
            padding: 35px;
            border-radius: 16px;
            box-shadow: 0 8px 25px var(--shadow);
            margin-bottom: 30px;
            border: 1px solid var(--border);
            position: relative;
        }}
        
        .section::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, var(--accent), var(--blue-light));
            border-radius: 16px 16px 0 0;
        }}
        
        .section-title {{
            color: var(--text-primary);
            font-size: 1.8em;
            margin-bottom: 25px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        .section-title::before {{
            content: '';
            width: 4px;
            height: 24px;
            background: linear-gradient(135deg, var(--accent), var(--blue-light));
            border-radius: 2px;
        }}
        
        .relationship-section {{
            background: linear-gradient(135deg, var(--card-bg), #1e293b);
            border-left: 4px solid var(--accent);
        }}
        
        .ip-dns-relationship {{
            background: rgba(30, 41, 59, 0.5);
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 18px;
            border: 1px solid var(--border);
            transition: all 0.3s ease;
        }}
        
        .ip-dns-relationship:hover {{
            border-color: var(--accent);
        }}
        
        .relationship-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
        }}
        
        .relationship-strength {{
            background: linear-gradient(135deg, var(--accent), var(--blue-light));
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
        }}
        
        .serialization-badge {{
            background: var(--success);
            color: white;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.8em;
            margin-left: 12px;
            font-weight: 600;
        }}
        
        .serialization-badge.not-serialized {{
            background: var(--warning);
        }}
        
        .ip-list, .file-list {{
            display: grid;
            gap: 18px;
        }}
        
        .ip-item, .file-item {{
            background: rgba(30, 41, 59, 0.5);
            padding: 24px;
            border-radius: 12px;
            border-left: 4px solid;
            border: 1px solid var(--border);
            transition: all 0.3s ease;
        }}
        
        .ip-item:hover, .file-item:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px var(--shadow);
        }}
        
        .ip-item.malicious {{ border-left-color: var(--danger); }}
        .ip-item.infected {{ border-left-color: var(--warning); }}
        .file-item {{ border-left-color: var(--purple); }}
        
        .ip-header, .file-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .ip-address, .file-name {{
            font-weight: 700;
            font-size: 1.3em;
            color: var(--text-primary);
        }}
        
        .confidence {{
            background: linear-gradient(135deg, var(--accent), var(--blue-light));
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
        }}
        
        .ip-details, .file-details {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            margin-top: 15px;
        }}
        
        .detail-item {{
            background: rgba(255, 255, 255, 0.05);
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 0.9em;
            border: 1px solid var(--border);
        }}
        
        .detail-label {{
            color: var(--text-secondary);
            font-weight: 600;
            margin-bottom: 4px;
        }}
        
        .detail-value {{
            color: var(--text-primary);
            font-weight: 600;
        }}
        
        .file-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 25px;
            background: var(--card-bg);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 15px var(--shadow);
        }}
        
        .file-table th {{
            background: linear-gradient(135deg, var(--accent), var(--blue-dark));
            color: white;
            padding: 18px 16px;
            text-align: left;
            font-weight: 700;
            font-size: 0.95em;
        }}
        
        .file-table td {{
            padding: 16px;
            border-bottom: 1px solid var(--border);
            color: var(--text-primary);
            font-size: 0.9em;
        }}
        
        .file-table tr:hover {{
            background: rgba(255, 255, 255, 0.03);
        }}
        
        .tech-badge {{
            background: linear-gradient(135deg, var(--warning), #f59e0b);
            color: white;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.8em;
            margin-right: 8px;
            font-weight: 600;
        }}
        
        .recommendations {{
            background: linear-gradient(135deg, var(--danger), #991b1b);
            color: white;
            padding: 35px;
            border-radius: 16px;
            margin-top: 35px;
            border: 1px solid var(--border);
        }}
        
        .recommendations h3 {{
            margin-bottom: 25px;
            font-size: 1.6em;
            font-weight: 700;
        }}
        
        .recommendations ul {{
            list-style: none;
        }}
        
        .recommendations li {{
            padding: 14px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            font-size: 1.05em;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        .recommendations li:last-child {{
            border-bottom: none;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 45px;
            color: var(--text-secondary);
            opacity: 0.8;
            font-size: 0.9em;
            padding: 25px;
            border-top: 1px solid var(--border);
        }}
        
        .role-badge {{
            background: linear-gradient(135deg, var(--accent), var(--blue-light));
            color: white;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.8em;
            margin-left: 12px;
            font-weight: 600;
        }}
        
        .file-icon {{
            font-size: 1.3em;
            margin-right: 12px;
        }}
        
        .completeness-bar {{
            background: var(--border);
            border-radius: 10px;
            height: 8px;
            margin-top: 8px;
            overflow: hidden;
        }}
        
        .completeness-fill {{
            background: linear-gradient(90deg, var(--success), #10b981);
            height: 100%;
            border-radius: 10px;
            transition: width 0.3s ease;
        }}
        
        .completeness-fill.partial {{
            background: linear-gradient(90deg, var(--warning), #f59e0b);
        }}
        
        .completeness-fill.low {{
            background: linear-gradient(90deg, var(--danger), #ef4444);
        }}
        
        .duplicate-warning {{
            background: var(--warning);
            color: var(--dark-bg);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.8em;
            margin-left: 10px;
            font-weight: 600;
        }}
        
        .detection-log {{
            background: rgba(30, 41, 59, 0.5);
            padding: 20px;
            border-radius: 12px;
            margin-top: 20px;
            border: 1px solid var(--border);
            max-height: 400px;
            overflow-y: auto;
        }}
        
        .log-entry {{
            padding: 8px 12px;
            margin-bottom: 5px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            background: rgba(255, 255, 255, 0.05);
        }}
        
        .log-entry.info {{
            border-left: 3px solid var(--accent);
        }}
        
        .log-entry.warning {{
            border-left: 3px solid var(--warning);
        }}
        
        .log-entry.error {{
            border-left: 3px solid var(--danger);
        }}
        
        .log-entry.success {{
            border-left: 3px solid var(--success);
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{ font-size: 2.2em; }}
            .dashboard {{ grid-template-columns: 1fr; }}
            .techniques-grid {{ grid-template-columns: 1fr; }}
            .ip-details, .file-details {{ grid-template-columns: 1fr; }}
            .ip-header, .file-header {{ flex-direction: column; align-items: start; }}
            .ip-header > *, .file-header > * {{ margin-bottom: 8px; }}
            .file-table {{ font-size: 0.8em; }}
            .relationship-header {{ flex-direction: column; align-items: start; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕵️ Análisis Forense DNS</h1>
            <div class="subtitle">Detección Avanzada de Exfiltración de Datos - {datetime.now().strftime('%d/%m/%Y %H:%M')}</div>
        </div>
        
        <div class="dashboard">
            <div class="dashboard-card">
                <div class="metric-value">{self.analysis_summary['total_packets']:,}</div>
                <div class="metric-label">Paquetes Analizados</div>
                <div class="metric-description">Total de paquetes DNS procesados en el análisis forense</div>
            </div>
            
            <div class="dashboard-card">
                <div class="metric-value">{self.analysis_summary['exfil_packets']:,}</div>
                <div class="metric-label">Paquetes Maliciosos</div>
                <div class="metric-description">Paquetes identificados como exfiltración de datos</div>
            </div>
            
            <div class="dashboard-card">
                <div class="metric-value">{total_files_unique}</div>
                <div class="metric-label">Archivos Detectados</div>
                <div class="metric-description">Archivos únicos en proceso de exfiltración</div>
            </div>
            
            <div class="dashboard-card">
                <div class="metric-value">{total_actual_data_mb:.2f}<span style="font-size: 0.6em;"> MB</span></div>
                <div class="metric-label">Datos Exfiltrados</div>
                <div class="metric-description">Volumen real de información comprometida</div>
            </div>
        </div>

        <!-- Estadísticas Detalladas -->
        <div class="section">
            <h2 class="section-title">📈 Análisis Detallado del Tráfico</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px;">
                <div class="detail-item">
                    <div class="detail-label">Paquetes Totales</div>
                    <div class="detail-value" style="font-size: 1.5em;">{self.analysis_summary['total_packets']:,}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Paquetes de Exfiltración</div>
                    <div class="detail-value" style="font-size: 1.5em;">{self.analysis_summary['exfil_packets']:,}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Archivos Completados</div>
                    <div class="detail-value" style="font-size: 1.5em;">{total_files_completed}/{total_files_unique}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Efectividad</div>
                    <div class="detail-value" style="font-size: 1.5em;">{(total_files_completed/total_files_unique*100) if total_files_unique > 0 else 0:.1f}%</div>
                </div>
            </div>
        </div>

        <!-- Sección de Técnicas y Codificaciones - MEJORADA -->
        <div class="section">
            <h2 class="section-title">🔧 Técnicas de Exfiltración Detectadas</h2>
            <div class="techniques-grid">
"""

        # Mostrar cada técnica con sus estadísticas
        for technique, stats in technique_stats.items():
            if technique != 'Unknown':  # No mostrar técnicas desconocidas
                domains_list = list(stats['domains'])
                primary_domain = domains_list[0] if domains_list else "N/A"
                
                # Determinar clase CSS para el badge de encoding
                encoding_class = stats['encoding'].lower().replace('_', '-')
                if 'base32' in encoding_class:
                    encoding_class = 'base32'
                elif 'base64' in encoding_class:
                    encoding_class = 'base64'
                elif 'hex' in encoding_class:
                    encoding_class = 'hex'
                
                html_content += f"""
                <div class="technique-card">
                    <div class="technique-header">
                        <div class="technique-name">{technique}</div>
                        <div class="encoding-badge {encoding_class}">{stats['encoding']}</div>
                    </div>
                    <div class="technique-description">{stats['description']}</div>
                    <div class="technique-stats">
                        <div class="stat-item">📊 {stats['sessions']} sesiones</div>
                        <div class="stat-item">🔐 {stats['encoding']}</div>
                        <div class="stat-item">🌐 {stats['queries']} consultas</div>
                    </div>
                    <div style="margin-top: 10px; font-size: 0.85em; color: var(--text-secondary);">
                        <strong>Dominios:</strong> {primary_domain}{f' +{len(domains_list)-1} más' if len(domains_list) > 1 else ''}
                    </div>
                </div>
                """

        html_content += """
            </div>
        </div>
"""

        # Detalles de Detección
        if self.detection_log:
            html_content += """
                <div class="section">
                    <h2 class="section-title">🔍 Proceso de Detección</h2>
                    <div class="detection-log">
            """
            
            for log_entry in self.detection_log:
                log_class = "info"
                if "❌" in log_entry or "Error" in log_entry:
                    log_class = "error"
                elif "⚠️" in log_entry or "Warning" in log_entry:
                    log_class = "warning"
                elif "✅" in log_entry or "Detectado" in log_entry:
                    log_class = "success"
                
                html_content += f'<div class="log-entry {log_class}">{log_entry}</div>'
            
            html_content += """
                    </div>
                </div>
            """

        # Dominios Maliciosos
        if self.malicious_ips:
            html_content += """
                <div class="section">
                    <h2 class="section-title">🔴 Infraestructura Maliciosa</h2>
                    <div class="ip-list">
            """
            
            for ip_info in sorted(self.malicious_ips, key=lambda x: x['confidence'], reverse=True):
                html_content += f"""
                        <div class="ip-item malicious">
                            <div class="ip-header">
                                <div class="ip-address">
                                    🌐 {ip_info['ip']}
                                    <span class="role-badge">Servidor C2</span>
                                </div>
                                <div class="confidence">{ip_info['confidence']}%</div>
                            </div>
                            <div class="ip-details">
                                <div class="detail-item">
                                    <div class="detail-label">Consultas DNS</div>
                                    <div class="detail-value">{ip_info['total_queries']}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Archivos Recibidos</div>
                                    <div class="detail-value">{ip_info['files_received']}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Frecuencia</div>
                                    <div class="detail-value">{ip_info['query_frequency']:.1f}/min</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Técnica Principal</div>
                                    <div class="detail-value">{ip_info['techniques'][0] if ip_info['techniques'] else 'N/A'}</div>
                                </div>
                            </div>
                        </div>
                """
            
            html_content += """
                    </div>
                </div>
            """

        # IPs Infectadas
        if self.infected_ips:
            html_content += """
                <div class="section">
                    <h2 class="section-title">🟡 Hosts Comprometidos</h2>
                    <div class="ip-list">
            """
            
            for ip_info in sorted(self.infected_ips, key=lambda x: x['confidence'], reverse=True):
                actual_data_mb = ip_info['actual_exfiltrated_data'] / (1024 * 1024)
                html_content += f"""
                        <div class="ip-item infected">
                            <div class="ip-header">
                                <div class="ip-address">
                                    💻 {ip_info['ip']}
                                    <span class="role-badge">Origen</span>
                                </div>
                                <div class="confidence">{ip_info['confidence']}%</div>
                            </div>
                            <div class="ip-details">
                                <div class="detail-item">
                                    <div class="detail-label">Archivos Exfiltrados</div>
                                    <div class="detail-value">{len(ip_info['files_exfiltrated'])}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Datos Transferidos</div>
                                    <div class="detail-value">{actual_data_mb:.2f} MB</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Frecuencia</div>
                                    <div class="detail-value">{ip_info['query_frequency']:.1f}/min</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Técnica Principal</div>
                                    <div class="detail-value">{ip_info['techniques'][0] if ip_info['techniques'] else 'N/A'}</div>
                                </div>
                            </div>
                        </div>
                """
            
            html_content += """
                    </div>
                </div>
            """

        # Relaciones IP-DNS
        if hasattr(self, 'ip_dns_relationships') and self.ip_dns_relationships:
            html_content += """
                <div class="section relationship-section">
                    <h2 class="section-title">🔗 Análisis de Conectividad</h2>
                    <p style="color: var(--text-secondary); margin-bottom: 20px;">
                        Mapeo de relaciones entre hosts comprometidos e infraestructura maliciosa
                    </p>
            """
            
            for ip, relationship in self.ip_dns_relationships.items():
                is_serialized = relationship['is_serialized']
                serialization_text = "SERIADO" if is_serialized else "DISTRIBUIDO"
                serialization_class = "" if is_serialized else "not-serialized"
                
                html_content += f"""
                    <div class="ip-dns-relationship">
                        <div class="relationship-header">
                            <div class="ip-address">
                                💻 {ip}
                                <span class="serialization-badge {serialization_class}">{serialization_text}</span>
                            </div>
                            <div class="relationship-strength">
                                Fuerza: {relationship['relationship_strength']:.1f}%
                            </div>
                        </div>
                        
                        <div class="ip-details">
                            <div class="detail-item">
                                <div class="detail-label">Dominios Contactados</div>
                                <div class="detail-value">{len(relationship['domains'])}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Consultas Totales</div>
                                <div class="detail-value">{relationship['total_queries']}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Archivos Exfiltrados</div>
                                <div class="detail-value">{len(relationship['files_exfiltrated'])}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Técnicas Detectadas</div>
                                <div class="detail-value">{', '.join(list(relationship['techniques'])[:2])}</div>
                            </div>
                        </div>
                        
                        <div style="margin-top: 15px;">
                            <div class="detail-label" style="margin-bottom: 8px;">Dominios de Comando y Control:</div>
                            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                """
                
                for domain in relationship['domains']:
                    html_content += f'<span class="tech-badge">{domain}</span>'
                
                html_content += """
                            </div>
                        </div>
                    </div>
                """
            
            html_content += """
                </div>
            """

        # Archivos Exfiltrados
        if unique_files:
            html_content += """
                <div class="section">
                    <h2 class="section-title">📁 Archivos Exfiltrados</h2>
                    <table class="file-table">
                        <thead>
                            <tr>
                                <th>Archivo</th>
                                <th>Tamaño</th>
                                <th>Tipo</th>
                                <th>Origen → Destino</th>
                                <th>Estado</th>
                                <th>Completitud</th>
                                <th>Técnica</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            
            for file_info in sorted(unique_files, key=lambda x: x['file_size'], reverse=True):
                file_size_kb = file_info['file_size'] / 1024
                status_color = "🟢" if file_info['completeness'] >= 95 else "🟡" if file_info['completeness'] >= 80 else "🔴"
                status_text = "COMPLETO" if file_info['completeness'] >= 95 else "PARCIAL" if file_info['completeness'] >= 80 else "INCOMPLETO"
                completeness_class = "partial" if file_info['completeness'] < 95 else ""
                completeness_class = "low" if file_info['completeness'] < 80 else completeness_class
                
                html_content += f"""
                            <tr>
                                <td>
                                    <span class="file-icon">{file_info['file_icon']}</span>
                                    {file_info['filename']}
                                    {"<span class=\"duplicate-warning\">DUPLICADO</span>" if file_info.get('is_duplicate') else ""}
                                </td>
                                <td>{file_size_kb:.1f} KB</td>
                                <td>{file_info['file_type']}</td>
                                <td>{file_info['source_ip']} → {file_info['destination_domain']}</td>
                                <td>{status_color} {status_text}</td>
                                <td>
                                    {file_info['completeness']:.1f}%
                                    <div class="completeness-bar">
                                        <div class="completeness-fill {completeness_class}" style="width: {file_info['completeness']}%"></div>
                                    </div>
                                </td>
                                <td><span class="tech-badge">{file_info['technique']}</span></td>
                            </tr>
                """
            
            html_content += """
                        </tbody>
                    </table>
                </div>
            """
        else:
            html_content += """
                <div class="section">
                    <h2 class="section-title">📁 Archivos Exfiltrados</h2>
                    <div style="text-align: center; padding: 40px; color: var(--text-secondary);">
                        <p style="font-size: 1.2em;">No se detectaron archivos completos en el tráfico analizado.</p>
                        <p>Esto puede deberse a:</p>
                        <ul style="text-align: left; display: inline-block; margin-top: 20px;">
                            <li>Exfiltración de datos sin estructura de archivos</li>
                            <li>Transferencias incompletas o interrumpidas</li>
                            <li>Uso de técnicas de exfiltración no detectadas</li>
                        </ul>
                    </div>
                </div>
            """

        html_content += f"""
                <div class="recommendations">
                    <h3>🚨 Acciones de Respuesta Inmediata</h3>
                    <ul>
                        <li>🔍 <strong>Aislamiento de red</strong> para los equipos comprometidos identificados</li>
                        <li>🚫 <strong>Bloqueo proactivo</strong> de dominios maliciosos en firewall DNS</li>
                        <li>📊 <strong>Análisis forense extendido</strong> de los hosts afectados</li>
                        <li>🔒 <strong>Refuerzo de políticas</strong> de seguridad perimetral</li>
                        <li>📝 <strong>Documentación completa</strong> del incidente para auditoría</li>
                        <li>🔄 <strong>Monitorización continua</strong> de patrones de exfiltración</li>
                    </ul>
                </div>
                
                <div class="footer">
                    <p>Reporte generado por DNS Forensic Analyzer v3.0 | Análisis de Exfiltración Avanzada</p>
                    <p>Archivo analizado: {os.path.basename(self.pcap_file)} | {datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"📊 Reporte HTML generado: {output_file}")
            return True
        except Exception as e:
            print(f"❌ Error generando reporte HTML: {e}")
            return False

# USO DEL SCRIPT
if __name__ == "__main__":
    print("🕵️  ANALIZADOR FORENSE DNS - DETECCIÓN DE EXFILTRACIÓN")
    print("🔍 Identifica: Equipos infectados y dominios maliciosos")
    print("📁 Detecta: Archivos exfiltrados con análisis de completitud")
    print("🔗 Analiza: Relaciones IP-DNS y patrones de seriado")
    print("🎯 Precisión: Detección avanzada con descripción de técnicas")
    print("=" * 60)
    
    if len(sys.argv) != 2:
        print("❌ Uso: python detector.py <archivo_pcap>")
        print("💡 Ejemplo: python detector.py C:\\ruta\\capture.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    if not os.path.exists(pcap_file):
        print(f"❌ Archivo no encontrado: {pcap_file}")
        sys.exit(1)
    
    detector = DNSExfilIPDetector(pcap_file)
    
    if detector.analyze_dns_queries():
        html_report = detector.generate_html_report()
        
        if html_report:
            print(f"\n🎉 Análisis forense completado exitosamente!")
            print(f"📁 Archivo analizado: {pcap_file}")
            print(f"📊 Reporte generado: dns_exfil_report.html")
            print(f"\n📈 RESULTADOS DEL ANÁLISIS:")
            print(f"   🔴 Dominios maliciosos: {len(detector.malicious_ips)}")
            for ip in detector.malicious_ips:
                print(f"      - {ip['ip']} ({ip['confidence']}% confianza) - {ip['total_queries']} consultas")
            print(f"   🟡 Equipos infectados: {len(detector.infected_ips)}")
            for ip in detector.infected_ips:
                actual_data_mb = ip['actual_exfiltrated_data'] / (1024 * 1024)
                print(f"      - {ip['ip']} ({ip['confidence']}% confianza) - {actual_data_mb:.2f} MB enviados")
            print(f"   📁 Archivos únicos: {detector.analysis_summary['total_files_detected']}")
            print(f"   ✅ Archivos completados: {detector.analysis_summary['total_files_completed']}")
            print(f"   📦 Datos exfiltrados: {detector.analysis_summary['total_actual_data'] / (1024*1024):.2f} MB")
            
            if hasattr(detector, 'ip_dns_relationships'):
                print(f"   🔗 Relaciones analizadas: {len(detector.ip_dns_relationships)}")
                for ip, rel in detector.ip_dns_relationships.items():
                    serialized = "SERIADO" if rel['is_serialized'] else "DISTRIBUIDO"
                    print(f"      - {ip}: {len(rel['domains'])} dominios - {serialized}")
        else:
            print("❌ Error generando reporte HTML")
    else:
        print("❌ Error en el análisis del archivo PCAP")