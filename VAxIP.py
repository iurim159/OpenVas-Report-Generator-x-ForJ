import sys
import os
import urllib.request
import xml.etree.ElementTree as ET
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
import matplotlib.pyplot as plt

def generate_complete_va_report(xml_file_path, logo_path_or_url, footer_path, output_docx_path):
    print(f"[*] Inizio elaborazione report VA dal file: {xml_file_path}")

    if not os.path.exists(xml_file_path):
        print(f"[!] Errore: Il file XML '{xml_file_path}' non esiste o il percorso non è corretto.")
        sys.exit(1)

    # --- 0. Download o gestione Logo ---
    logo_file = "logo_forj_downloaded.png"
    if logo_path_or_url.startswith("http://") or logo_path_or_url.startswith("https://"):
        try:
            req = urllib.request.Request(logo_path_or_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as resp, open(logo_file, 'wb') as f:
                f.write(resp.read())
        except Exception as e:
            print(f"[!] Download logo fallito ({e}), uso fallback locale se disponibile.")
            logo_file = "input_file_1.png"
    else:
        logo_file = logo_path_or_url

    # --- 1. Parsing dell'XML ---
    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    hosts_data = {}

    for host_elem in root.findall('.//host'):
        ip = host_elem.findtext('ip')
        if ip and ip not in hosts_data:
            hosts_data[ip] = {
                'ip': ip,
                'hostname': 'Non rilevato',
                'mac': 'Non rilevato',
                'os': 'Non specificato',
                'ports': [],
                'vulnerabilities': []
            }
        if ip:
            for detail in host_elem.findall('detail'):
                name = detail.findtext('name', default='')
                val = detail.findtext('value', default='')
                if name == 'hostname' and val:
                    hosts_data[ip]['hostname'] = val
                elif name == 'MAC' and val:
                    hosts_data[ip]['mac'] = val
                elif name == 'OS' and val and hosts_data[ip]['os'] in ['Non specificato', '']:
                    hosts_data[ip]['os'] = val
                elif name == 'ports' and val:
                    hosts_data[ip]['ports'] = [p.strip() for p in val.split(',')]

    total_vulns_count = 0
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Log/Info': 0}
    host_vuln_counts = {}

    for result in root.findall('.//results/result'):
        host_node = result.find('host')
        host_ip = ''
        if host_node is not None and host_node.text:
            host_ip = host_node.text.strip().split()[0]

        vuln_name = result.findtext('name', default='')
        port = result.findtext('port', default='')
        threat = result.findtext('threat', default='Log')
        severity = result.findtext('severity', default='0.0')
        description = result.findtext('description', default='')

        solution_node = result.find('solution')
        solution = solution_node.text.strip() if solution_node is not None and solution_node.text else ''

        nvt = result.find('nvt')
        cves = []
        if nvt is not None:
            for ref in nvt.findall('.//ref[@type="cve"]'):
                cves.append(ref.get('id'))

        if host_ip in hosts_data:
            hosts_data[host_ip]['vulnerabilities'].append({
                'name': vuln_name,
                'port': port,
                'threat': threat,
                'severity': severity,
                'description': description,
                'solution': solution,
                'cves': cves
            })
            
            total_vulns_count += 1
            if threat in severity_counts:
                severity_counts[threat] += 1
            else:
                severity_counts['Medium'] += 1
                
            host_vuln_counts[host_ip] = host_vuln_counts.get(host_ip, 0) + 1

    # Raggruppamento vulnerabilità con soluzione valida
    grouped_solvable_vulns = {}
    for ip, data in hosts_data.items():
        for vuln in data['vulnerabilities']:
            vname = vuln['name']
            sol = vuln['solution']
            if sol and len(sol) > 5:
                if vname not in grouped_solvable_vulns:
                    grouped_solvable_vulns[vname] = {
                        'threat': vuln['threat'],
                        'severity': vuln['severity'],
                        'solution': sol,
                        'cves': vuln['cves'],
                        'affected_ips': []
                    }
                if ip not in grouped_solvable_vulns[vname]['affected_ips']:
                    grouped_solvable_vulns[vname]['affected_ips'].append(ip)

    # --- 2. Generazione Grafici Matplotlib ---
    print("[*] Generazione grafici statistici...")
    chart_severity_path = "chart_severity.png"
    plt.figure(figsize=(6, 3.5))
    labels = [k for k, v in severity_counts.items() if v > 0]
    sizes = [v for k, v in severity_counts.items() if v > 0]
    colors_map = {'Critical': '#C00000', 'High': '#E36C0A', 'Medium': '#FFC000', 'Low': '#92D050', 'Log/Info': '#00B0F0'}
    colors = [colors_map.get(l, '#1B365D') for l in labels]

    if sizes:
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, startangle=140, textprops={'fontsize': 9, 'weight': 'bold'})
    plt.title("Distribuzione Vulnerabilità per Livello di Rischio", fontsize=11, fontweight='bold', color='#1B365D')
    plt.tight_layout()
    plt.savefig(chart_severity_path, dpi=300)
    plt.close()

    chart_hosts_path = "chart_hosts.png"
    plt.figure(figsize=(6.5, 3.5))
    top_hosts = sorted(host_vuln_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    host_ips = [x[0] for x in top_hosts]
    counts = [x[1] for x in top_hosts]

    plt.barh(host_ips[::-1], counts[::-1], color='#1B365D', height=0.55)
    plt.xlabel("Numero di Vulnerabilità Rilevate", fontsize=9, fontweight='bold', color='#333333')
    plt.title("Top Asset per Rilevazioni di Sicurezza", fontsize=11, fontweight='bold', color='#1B365D')
    plt.grid(axis='x', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(chart_hosts_path, dpi=300)
    plt.close()

    # --- 3. Creazione Documento Word (.docx) ---
    print("[*] Scrittura documento Word...")
    doc = docx.Document()

    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

        section.different_first_page_header_footer = True
        if os.path.exists(logo_file):
            header = section.header
            header_p = header.paragraphs[0]
            header_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            run_logo = header_p.add_run()
            run_logo.add_picture(logo_file, width=Inches(1.8))

    DARK_BLUE = RGBColor(27, 54, 93)
    TEAL_ACCENT = RGBColor(0, 150, 180)

    def set_cell_background(cell, fill_hex):
        from docx.oxml import parse_xml
        from docx.oxml.ns import nsdecls
        cell._element.get_or_add_tcPr().append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>'))

    def set_table_borders(table, color="CCCCCC", sz="4", val="single"):
        from docx.oxml import parse_xml
        from docx.oxml.ns import nsdecls
        tblPr = table._element.xpath('w:tblPr')
        if tblPr:
            tblPr[0].append(parse_xml(f'<w:tblBorders {nsdecls("w")}><w:top w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/><w:bottom w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/><w:left w:val="none"/><w:right w:val="none"/><w:insideH w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/><w:insideV w:val="none"/></w:tblBorders>'))

    def add_section_header(title_text):
        h = doc.add_heading(level=1)
        r = h.add_run(title_text)
        r.font.name = "Arial"
        r.font.size = Pt(15)
        r.font.bold = True
        r.font.color.rgb = DARK_BLUE
        return h

    # Logo in copertina (Prima pagina)
    if os.path.exists(logo_file):
        p_logo = doc.add_paragraph()
        p_logo.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_logo.add_run().add_picture(logo_file, width=Inches(2.5))
        p_logo.paragraph_format.space_after = Pt(12)

    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_t = p_title.add_run("RAPPORTO DI VULNERABILITY ASSESSMENT")
    r_t.font.name = "Arial"
    r_t.font.size = Pt(22)
    r_t.font.bold = True
    r_t.font.color.rgb = DARK_BLUE

    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_s = p_sub.add_run("Documento Tecnico di Conformità e Piano di Risanamento della Rete")
    r_s.font.name = "Arial"
    r_s.font.size = Pt(13)
    r_s.font.italic = True
    r_s.font.color.rgb = TEAL_ACCENT

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # 1. Executive Summary con Grafici
    add_section_header("1. Executive Summary e Resoconto Generale Rete")
    p_ex = doc.add_paragraph(
        f"L'analisi di sicurezza eseguita sulla rete aziendale ha preso in esame un totale di {len(hosts_data)} asset. "
        f"Sono state rilevate complessivamente {total_vulns_count} vulnerabilità o anomalie di configurazione."
    )
    p_ex.runs[0].font.size = Pt(10)

    if os.path.exists(chart_severity_path):
        p_img1 = doc.add_paragraph()
        p_img1.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_img1.add_run().add_picture(chart_severity_path, width=Inches(5.2))
        p_img1.paragraph_format.space_after = Pt(8)

    if os.path.exists(chart_hosts_path):
        p_img2 = doc.add_paragraph()
        p_img2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_img2.add_run().add_picture(chart_hosts_path, width=Inches(5.4))
        p_img2.paragraph_format.space_after = Pt(12)

    # 2. Scope
    add_section_header("2. Definizione del Perimetro (Scope)")
    p_sc = doc.add_paragraph("L'attività di Vulnerability Assessment è stata eseguita previa formale autorizzazione scritta. L'analisi è limitata agli asset sottostanti.")
    p_sc.runs[0].font.size = Pt(10)

    tbl_scope = doc.add_table(rows=len(hosts_data) + 1, cols=3)
    tbl_scope.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(tbl_scope)
    for idx, th in enumerate(["Indirizzo IP", "Hostname", "Tipologia Asset"]):
        cell = tbl_scope.rows[0].cells[idx]
        set_cell_background(cell, "1B365D")
        p = cell.paragraphs[0]
        r = p.add_run(th)
        r.font.bold = True
        r.font.color.rgb = RGBColor(255, 255, 255)
        r.font.size = Pt(9.5)

    for r_idx, (ip, data) in enumerate(hosts_data.items(), start=1):
        row = tbl_scope.rows[r_idx]
        row.cells[0].paragraphs[0].add_run(ip).font.size = Pt(9)
        row.cells[1].paragraphs[0].add_run(data['hostname']).font.size = Pt(9)
        row.cells[2].paragraphs[0].add_run(f"Endpoint ({data['os']})").font.size = Pt(9)

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # 3. Metodologia
    add_section_header("3. Metodologia e Strumenti")
    p_m = doc.add_paragraph("Analisi condotta secondo NIST SP 800-115, OWASP e CVSS v3.1.")
    p_m.runs[0].font.size = Pt(10)
    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # 4. Inventario Asset
    add_section_header("4. Inventario degli Asset e delle Porte Aperte")
    tbl_inv = doc.add_table(rows=len(hosts_data) + 1, cols=4)
    tbl_inv.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(tbl_inv)
    for idx, th in enumerate(["Indirizzo IP", "Sistema Operativo", "MAC Address", "Porte Aperte"]):
        cell = tbl_inv.rows[0].cells[idx]
        set_cell_background(cell, "1B365D")
        r = cell.paragraphs[0].add_run(th)
        r.font.bold = True
        r.font.color.rgb = RGBColor(255, 255, 255)
        r.font.size = Pt(9.5)

    for r_idx, (ip, data) in enumerate(hosts_data.items(), start=1):
        row = tbl_inv.rows[r_idx]
        row.cells[0].paragraphs[0].add_run(ip).font.size = Pt(9)
        row.cells[1].paragraphs[0].add_run(data['os']).font.size = Pt(9)
        row.cells[2].paragraphs[0].add_run(data['mac']).font.size = Pt(9)
        row.cells[3].paragraphs[0].add_run(", ".join(data['ports']) if data['ports'] else "N/D").font.size = Pt(9)

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # 5. Analisi Vulnerabilità per Host
    add_section_header("5. Analisi delle Vulnerabilità e Filtro Falsi Positivi")
    for ip, data in hosts_data.items():
        if not data['vulnerabilities']:
            continue
        p_h = doc.add_paragraph()
        p_h.paragraph_format.space_before = Pt(10)
        r_h = p_h.add_run(f"Asset: {ip} ({data['hostname']})")
        r_h.font.bold = True
        r_h.font.size = Pt(11)
        r_h.font.color.rgb = TEAL_ACCENT

        for vuln in data['vulnerabilities']:
            tbl_v = doc.add_table(rows=4, cols=2)
            tbl_v.alignment = WD_TABLE_ALIGNMENT.CENTER
            set_table_borders(tbl_v)
            details = [
                ("Vulnerabilità", vuln['name']),
                ("Severità (CVSS)", f"{vuln['threat']} (Score: {vuln['severity']})"),
                ("CVE", ", ".join(vuln['cves']) if vuln['cves'] else "N/D"),
                ("Descrizione", vuln['description'])
            ]
            for i, (k, v) in enumerate(details):
                row = tbl_v.rows[i]
                row.cells[0].width = Inches(2.0)
                row.cells[1].width = Inches(4.5)
                set_cell_background(row.cells[0], "F4F6F8")
                row.cells[0].paragraphs[0].add_run(k).font.bold = True
                row.cells[0].paragraphs[0].runs[0].font.size = Pt(9)
                row.cells[0].paragraphs[0].runs[0].font.color.rgb = DARK_BLUE
                row.cells[1].paragraphs[0].add_run(v).font.size = Pt(9)
            doc.add_paragraph().paragraph_format.space_after = Pt(4)

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # 6. PIANO DI REMEDIATION (Comparirà solo se ci sono soluzioni note)
    if grouped_solvable_vulns:
        add_section_header("6. Piano di Remediation (Solo Vulnerabilità con Procedura Nota)")
        p_r_intro = doc.add_paragraph(
            "Di seguito sono riportate esclusivamente le azioni correttive per le quali è disponibile una procedura tecnica di risoluzione specifica e testata."
        )
        p_r_intro.runs[0].font.size = Pt(10)

        for vname, info in grouped_solvable_vulns.items():
            p_vh = doc.add_paragraph()
            p_vh.paragraph_format.space_before = Pt(8)
            p_vh.paragraph_format.space_after = Pt(2)
            r_vh = p_vh.add_run(f"▶ {vname}")
            r_vh.font.bold = True
            r_vh.font.size = Pt(10.5)
            r_vh.font.color.rgb = DARK_BLUE

            ips_str = ", ".join(info['affected_ips'])
            p_ips = doc.add_paragraph(f"Host interessati: {ips_str}")
            p_ips.runs[0].font.size = Pt(9)
            p_ips.runs[0].font.italic = True

            p_sol = doc.add_paragraph(f"Procedura di Risoluzione: {info['solution']}")
            p_sol.runs[0].font.size = Pt(9.5)
            p_sol.paragraph_format.space_after = Pt(6)

    # Footer finale nell'ultima pagina
    if os.path.exists(footer_path):
        doc.add_paragraph().paragraph_format.space_after = Pt(18)
        p_ff = doc.add_paragraph()
        p_ff.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_ff.paragraph_format.space_before = Pt(24)
        p_ff.add_run().add_picture(footer_path, width=Inches(6.5))

    output_filename = "Vulnerability_Assessment_FORJ.docx"
    doc.save(output_filename)
    print(f"[✔] Report generato con successo e salvato in: {output_filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[!] Utilizzo corretto: python3 VAxIP.py <file_report.xml>")
        sys.exit(1)

    xml_input = sys.argv[1]
    logo_url = "https://www.forj.it/wp-content/uploads/2022/07/logo-forj.png"
    footer_img = "input_file_2.png"

    generate_complete_va_report(xml_input, logo_url, footer_img, "Vulnerability_Assessment_FORJ.docx")