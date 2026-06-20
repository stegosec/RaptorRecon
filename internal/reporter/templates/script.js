document.addEventListener("DOMContentLoaded", () => {
    let data = window.raptorData;
    if (!data) {
        console.error("Failed to load Raptor JSON data from window");
        return;
    }

    // --- State ---
    let totalSubnets = data.subnets ? data.subnets.length : 0;
    let totalHosts = 0;
    let totalPorts = 0;
    let crit = 0, high = 0, med = 0, low = 0, info = 0;
    const hostRows = []; // Array of grouped host data

    function escapeHTML(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function getSeverityWeight(sev) {
        const s = sev.toLowerCase();
        if (s.includes("crit")) return 5;
        if (s.includes("high")) return 4;
        if (s.includes("med")) return 3;
        if (s.includes("low")) return 2;
        return 1;
    }

    function getBadgeClass(severity) {
        const s = severity.toLowerCase();
        if (s.includes('crit')) return 'critical';
        if (s.includes('high')) return 'high';
        if (s.includes('med')) return 'medium';
        if (s.includes('low')) return 'low';
        return 'info';
    }

    // --- Processing Data ---
    if (data.subnets) {
        data.subnets.forEach(subnet => {
            if (subnet.hosts) {
                totalHosts += subnet.hosts.length;
                subnet.hosts.forEach(host => {
                    let hostRow = {
                        ip: host.ip,
                        hostname: host.hostname || '',
                        subnet: subnet.cidr,
                        mac: host.mac_address || '',
                        os: host.os !== 'Desconocido' ? host.os : '',
                        vendor: host.vendor || '',
                        severity: 'info',
                        severityWeight: 1,
                        riskScore: host.risk_score || 0,
                        attackPaths: host.attack_paths || [],
                        ports: [],
                        banners: [],
                        cves: [],
                        static_findings: [],
                        mitigations: []
                    };
                    
                    if (host.ports) {
                        totalPorts += host.ports.length;
                        host.ports.forEach(p => {
                            let pStr = p.port + '/' + (p.protocol || 'tcp');
                            hostRow.ports.push(pStr);
                            
                            let serviceStr = p.service || 'unknown';
                            if (p.banner) {
                                hostRow.banners.push(`[${pStr}] ${p.banner.trim()}`);
                            } else {
                                hostRow.banners.push(`[${pStr}] ${serviceStr}`);
                            }

                            if (p.cves && p.cves.length > 0) {
                                p.cves.forEach(cve => {
                                    countSeverity(cve.severity);
                                    let weight = getSeverityWeight(cve.severity);
                                    if (weight > hostRow.severityWeight) {
                                        hostRow.severityWeight = weight;
                                        hostRow.severity = cve.severity.toLowerCase();
                                    }
                                    hostRow.cves.push(cve);
                                });
                            }
                        });
                    }
                    
                    if (host.static_findings) {
                        host.static_findings.forEach(f => {
                            countSeverity(f.severity);
                            let weight = getSeverityWeight(f.severity);
                            if (weight > hostRow.severityWeight) {
                                hostRow.severityWeight = weight;
                                hostRow.severity = f.severity.toLowerCase();
                            }
                            hostRow.static_findings.push(f);
                            if (f.remediation) {
                                hostRow.mitigations.push(`[${f.rule_id || 'Fix'}] ${f.remediation}`);
                            }
                        });
                    }

                    if (host.pivot_findings) {
                        host.pivot_findings.forEach(f => {
                            countSeverity(f.severity);
                            let weight = getSeverityWeight(f.severity);
                            if (weight > hostRow.severityWeight) {
                                hostRow.severityWeight = weight;
                                hostRow.severity = f.severity.toLowerCase();
                            }
                            // Insert into static_findings for the table display
                            hostRow.static_findings.push({
                                rule_id: f.rule_id,
                                rule_name: `[PIVOT] ${f.rule_name}`,
                                severity: f.severity,
                                description: `Expuesto vía proxy ${f.proxy_host}:${f.proxy_port}. ` + (f.description || ""),
                                tags: ['pivot'],
                                context: f.context
                            });
                        });
                    }
                    
                    hostRows.push(hostRow);
                });
            }
        });
    }

    function countSeverity(sev) {
        const s = sev.toLowerCase();
        if (s.includes("crit")) crit++;
        else if (s.includes("high")) high++;
        else if (s.includes("med")) med++;
        else if (s.includes("low")) low++;
        else info++;
    }

    /**
     * getRiskBadgeHTML convierte un RiskScore numérico (0-100) calculado por risk.go
     * en un badge visual con color semafórico y mini barra de progreso.
     *   >= 90  → CRITICAL  (rojo)    
     *   >= 70  → HIGH      (naranja)
     *   >= 40  → MEDIUM    (amarillo)
     *   >  0   → LOW       (cyan)
     *   == 0   → (sin badge, host sin riesgo calculado)
     */
    function getRiskBadgeHTML(score) {
        if (!score || score <= 0) return '';
        const s = parseFloat(score);
        let label, color, bg, glow;
        if (s >= 90) {
            label = 'CRITICAL'; color = '#fff'; bg = '#ff003c'; glow = 'rgba(255,0,60,0.6)';
        } else if (s >= 70) {
            label = 'HIGH';     color = '#fff'; bg = '#ff5e00'; glow = 'rgba(255,94,0,0.5)';
        } else if (s >= 40) {
            label = 'MEDIUM';   color = '#000'; bg = '#eab308'; glow = 'rgba(234,179,8,0.4)';
        } else {
            label = 'LOW';      color = '#000'; bg = '#00f0ff'; glow = 'rgba(0,240,255,0.4)';
        }
        // Mini barra de progreso proporcional al score (max 100)
        const pct = Math.min(s, 100);
        return `
            <div style="margin-top: 6px; margin-bottom: 2px;">
                <span title="Risk Score calculado por motor CVSS: ${s}/100"
                      style="display:inline-flex; align-items:center; gap:5px;
                             background:${bg}; color:${color};
                             font-size:0.65rem; font-weight:700; letter-spacing:1px;
                             padding:2px 7px; border-radius:3px;
                             box-shadow: 0 0 8px ${glow};
                             font-family:'Outfit',sans-serif; text-transform:uppercase;">
                    ⚡ ${label}
                </span>
                <span style="font-size:0.6rem; color:#64748b; margin-left:4px; font-family:monospace;"
                      title="CVSS Risk Score">${s.toFixed(1)}/100</span>
            </div>
            <div style="height:3px; background:rgba(255,255,255,0.06); border-radius:2px; margin-bottom:4px; overflow:hidden;">
                <div style="height:100%; width:${pct}%; background:${bg};
                            box-shadow: 0 0 6px ${glow}; border-radius:2px;
                            transition: width 0.6s ease;"></div>
            </div>`;
    }

    // --- Update Top Cards ---
    document.getElementById('val-subnets').textContent = totalSubnets;
    document.getElementById('val-hosts').textContent = totalHosts;
    document.getElementById('val-ports').textContent = totalPorts;
    document.getElementById('val-crit').textContent = crit;
    document.getElementById('val-high').textContent = high;

    const riskScoreRaw = (crit * 10) + (high * 5) + (med * 3) + (low * 1);

    // --- Executive Intelligence ---
    const hostRisks = [];
    if (data.subnets) {
        data.subnets.forEach(subnet => {
            if (subnet.hosts) {
                subnet.hosts.forEach(host => {
                    let hCrit = 0, hHigh = 0, hMed = 0, hLow = 0;
                    if (host.static_findings) {
                        host.static_findings.forEach(f => {
                            const s = f.severity.toLowerCase();
                            if (s.includes("crit")) hCrit++;
                            else if (s.includes("high")) hHigh++;
                            else if (s.includes("med")) hMed++;
                            else if (s.includes("low")) hLow++;
                        });
                    }
                    if (host.ports) {
                        host.ports.forEach(p => {
                            if (p.cves) {
                                p.cves.forEach(cve => {
                                    const s = (cve.severity || "").toLowerCase();
                                    if (s.includes("crit")) hCrit++;
                                    else if (s.includes("high")) hHigh++;
                                    else if (s.includes("med")) hMed++;
                                    else if (s.includes("low")) hLow++;
                                });
                            }
                        });
                    }
                    const hScore = host.risk_score || 0;
                    if (hScore > 0 || hCrit > 0 || hHigh > 0 || (host.attack_paths && host.attack_paths.length > 0)) {
                        hostRisks.push({
                            ip: host.ip,
                            vendor: host.vendor || 'Unknown',
                            score: hScore,
                            crit: hCrit,
                            high: hHigh,
                            paths: host.attack_paths || []
                        });
                    }
                });
            }
        });
    }

    hostRisks.sort((a, b) => b.score - a.score);
    const topAssets = hostRisks.slice(0, 3);

    const topAssetsList = document.getElementById('top-assets-list');
    if (topAssets.length > 0) {
        topAssets.forEach(asset => {
            let color = 'var(--color-low)';
            if (asset.score > 20 || asset.crit > 0) color = 'var(--color-crit)';
            else if (asset.score > 10 || asset.high > 0) color = 'var(--color-high)';
            else if (asset.score > 3) color = 'var(--color-med)';

            topAssetsList.innerHTML += `
                <div class="asset-card" style="border-left-color: ${color}; box-shadow: 0 0 15px ${color}20;">
                    <div class="asset-card-info">
                        <div style="font-weight: 600; display: flex; align-items: center; gap: 0.75rem; font-family: 'Outfit', sans-serif; font-size: 1.1rem; color: #fff;">
                            <span>${asset.ip}</span>
                            <span style="font-size: 0.7rem; background: rgba(255,255,255,0.05); color: var(--text-secondary); padding: 0.2rem 0.5rem; border-radius: 4px; border: 1px solid rgba(255,255,255,0.1); letter-spacing: 1px;">${asset.vendor || 'Unknown'}</span>
                        </div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary); font-family: 'Inter', monospace; margin-top: 0.4rem;">
                            Score Details: C:${asset.crit} H:${asset.high}
                        </div>
                    </div>
                    <div class="asset-card-score" style="color: ${color}; text-shadow: 0 0 10px ${color}80;">${asset.score}</div>
                </div>
            `;
        });
    } else {
        topAssetsList.innerHTML = '<div style="color: var(--text-secondary); font-size: 0.9rem;">No vulnerabilities detected.</div>';
    }

    const execSummary = document.getElementById('exec-summary');
    if (riskScoreRaw === 0) {
        execSummary.innerHTML = "<strong>Postura de Seguridad Confirmada:</strong> No se detectaron vulnerabilidades o configuraciones erróneas significativas en la superficie de ataque escaneada. Mantén el monitoreo estándar.";
    } else {
        let text = `<strong>Evaluación de Seguridad:</strong> Se detectó un Risk Score global de ${riskScoreRaw} a través de ${totalHosts} ${totalHosts === 1 ? 'host activo' : 'hosts activos'}. `;
        if (crit > 0) {
            execSummary.classList.add('critical-state');
            text += `<br><strong>Hallazgo Crítico:</strong> Se ${crit === 1 ? 'descubrió' : 'descubrieron'} ${crit} ${crit === 1 ? 'vulnerabilidad crítica' : 'vulnerabilidades críticas'}. `;
            if (topAssets.length > 0) {
                text += `El Attack Path principal está concentrado en <strong>${topAssets[0].ip}</strong> (${topAssets[0].vendor}). `;
            }
            text += `<strong>Acción Inmediata Requerida:</strong> Aísla los activos críticos y aplica parches de emergencia para prevenir Remote Code Execution o exfiltración de datos.`;
        } else if (high > 0) {
            text += `<br><strong>Riesgo Alto:</strong> Se ${high === 1 ? 'encontró' : 'encontraron'} ${high} ${high === 1 ? 'incidencia' : 'incidencias'} de severidad alta. Se recomienda priorizar la remediación en menos de 7 días para reducir la exposición.`;
        } else {
            text += `<br><strong>Riesgo Moderado:</strong> Los hallazgos consisten mayoritariamente en problemas de severidad media a baja. Incorpóralos en el ciclo de parcheo estándar.`;
        }
        execSummary.innerHTML = text;
    }

    // Render Attack Paths
    let attackPathsHtml = '';
    hostRisks.forEach(asset => {
        if (asset.paths && asset.paths.length > 0) {
            asset.paths.forEach(p => {
                const nodes = p.split('➔').map(n => n.trim().replace('[', '').replace(']', ''));
                let pathStr = '';
                nodes.forEach((n, idx) => {
                    let bColor = idx === 0 ? '#00f0ff' : (idx === nodes.length - 1 ? '#ff003c' : '#eab308');
                    pathStr += `<span style="display:inline-block; padding: 4px 8px; border: 1px solid ${bColor}; border-radius: 4px; background: rgba(0,0,0,0.3); font-size: 0.75rem; color: #f1f5f9; white-space: nowrap;">${n}</span>`;
                    if (idx < nodes.length - 1) {
                        pathStr += `<span style="color: #475569; margin: 0 8px; font-weight: bold;">➔</span>`;
                    }
                });
                attackPathsHtml += `<div style="margin-bottom: 8px; padding: 10px; background: rgba(255,255,255,0.02); border-left: 2px solid #ff003c; border-radius: 4px;">
                    <div style="font-size: 0.7rem; color: #94a3b8; margin-bottom: 6px; font-family: monospace;">TARGET: <span style="color: #fff;">${asset.ip}</span></div>
                    <div style="display: flex; align-items: center; flex-wrap: wrap; gap: 4px;">${pathStr}</div>
                </div>`;
            });
        }
    });

    if (attackPathsHtml !== '') {
        const pathsDiv = document.createElement('div');
        pathsDiv.style.marginTop = '20px';
        pathsDiv.innerHTML = `<h3 style="color: #f1f5f9; font-size: 1.1rem; margin-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 6px; font-family: 'Outfit', sans-serif;">Attack Paths Probables</h3>
        ${attackPathsHtml}`;
        execSummary.parentNode.insertBefore(pathsDiv, execSummary.nextSibling);
    }

    if (document.getElementById('severityChart') && typeof Chart !== 'undefined') {
        try {
            const ctx = document.getElementById('severityChart').getContext('2d');
            let sum = crit + high + med + low + info;
            let chartData = sum === 0 ? [0,0,0,0,1] : [crit, high, med, low, info];
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Crítico', 'Alto', 'Medio', 'Bajo', 'Info'],
                    datasets: [{
                        data: chartData,
                        backgroundColor: ['#ff003c', '#ff5e00', '#eab308', '#00f0ff', '#334155'],
                        borderWidth: 1,
                        borderColor: '#10141f',
                        hoverOffset: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '78%',
                    plugins: {
                        legend: { position: 'right', labels: { color: '#e2e8f0', font: { family: 'Outfit', size: 13 } } }
                    }
                }
            });
        } catch (e) {
            console.error("Error renderizando Chart:", e);
        }
    }

    // --- Baselining Deltas ---
    if (window.raptorDelta) {
        const deltaContainer = document.getElementById('delta-container');
        const deltaGrid = document.getElementById('delta-grid');
        
        if (deltaContainer && deltaGrid) {
            deltaContainer.style.display = 'block';
            let deltaHtml = '';
            
            const newHostsCount = window.raptorDelta.new_hosts ? window.raptorDelta.new_hosts.length : 0;
            const missingHostsCount = window.raptorDelta.missing_hosts ? window.raptorDelta.missing_hosts.length : 0;
            const newPortsCount = window.raptorDelta.new_ports || 0;
            
            // Render only if there are changes
            if (newHostsCount > 0 || missingHostsCount > 0 || newPortsCount > 0) {
                if (newHostsCount > 0) {
                    deltaHtml += `
                        <div class="card" style="border-left: 3px solid #ff003c;">
                            <div class="card-title">New Hosts Exposed</div>
                            <div class="card-value" style="color: #ff003c;">+${newHostsCount}</div>
                            <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 5px;">Since last scan</div>
                        </div>
                    `;
                }
                
                if (newPortsCount > 0) {
                    deltaHtml += `
                        <div class="card" style="border-left: 3px solid #ff5e00;">
                            <div class="card-title">New Ports Opened</div>
                            <div class="card-value" style="color: #ff5e00;">+${newPortsCount}</div>
                            <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 5px;">On existing hosts</div>
                        </div>
                    `;
                }
                
                if (missingHostsCount > 0) {
                    deltaHtml += `
                        <div class="card" style="border-left: 3px solid #10b981;">
                            <div class="card-title">Hosts Offline</div>
                            <div class="card-value" style="color: #10b981;">-${missingHostsCount}</div>
                            <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 5px;">No longer responding</div>
                        </div>
                    `;
                }
            } else {
                deltaHtml = `
                    <div class="card" style="grid-column: 1 / -1; border-left: 3px solid #00f0ff;">
                        <div class="card-title" style="color: #00f0ff;">No Infrastructure Changes</div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 5px;">The attack surface has remained perfectly stable since the last baseline snapshot.</div>
                    </div>
                `;
            }
            
            deltaGrid.innerHTML = deltaHtml;
        }
    }

    // --- Network Context ---
    const networkGrid = document.getElementById('network-grid');
    if (networkGrid && data.subnets) {
        let networkHtml = '';
        data.subnets.forEach(subnet => {
            const hostCount = subnet.hosts ? subnet.hosts.length : 0;
            
            // Collect IPs, MACs and Vendors
            let macList = '';
            if (subnet.hosts) {
                subnet.hosts.forEach(h => {
                    if (h.mac_address || h.vendor) {
                        let macStr = h.mac_address || "MAC Desconocida";
                        let vendorStr = h.vendor || "Desconocido";
                        macList += `
                        <div style="background: rgba(255,255,255,0.03); border-left: 2px solid #3b82f6; border-radius: 4px; padding: 6px 8px; margin-top: 8px; display: flex; flex-direction: column; gap: 4px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="color: #00f0ff; font-family: monospace; font-size: 0.85rem; font-weight: bold;">${escapeHTML(h.ip)}</span>
                                <span style="color: var(--text-secondary); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.5px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; max-width: 120px;" title="${escapeHTML(vendorStr)}">${escapeHTML(vendorStr)}</span>
                            </div>
                            <div style="color: var(--text-primary); font-family: monospace; font-size: 0.75rem;">
                                ${escapeHTML(macStr)}
                            </div>
                        </div>`;
                    }
                });
            }
            if (macList === '') {
                macList = '<div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 4px; font-style: italic;">Sin visibilidad L2 (probablemente enrutado vía L3/VPN)</div>';
            }

            networkHtml += `
                <div class="card" style="border-left: 3px solid #3b82f6;">
                    <div class="card-title">${escapeHTML(subnet.cidr)}</div>
                    <div class="card-value" style="font-size: 1.5rem; color: #3b82f6;">${escapeHTML(String(hostCount))} Hosts Activos</div>
                    <div style="margin-top: 10px; border-top: 1px solid var(--border-color); padding-top: 6px;">
                        <div style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px;">Hardware (IP / MAC / Fabricante)</div>
                        ${macList}
                    </div>
                </div>
            `;
        });
        networkGrid.innerHTML = networkHtml;
    }

    // --- Proxy Pivot Details ---
    if (window.raptorPivot && window.raptorPivot.length > 0) {
        const pivotContainer = document.getElementById('pivot-container');
        const pivotList = document.getElementById('pivot-list');
        
        if (pivotContainer && pivotList) {
            pivotContainer.style.display = 'block';
            let pivotHtml = '';
            
            window.raptorPivot.forEach(proxyEntry => {
                let pType = proxyEntry.proxy_type.toUpperCase();
                let proxyTitle = `Proxy: ${proxyEntry.proxy_host}:${proxyEntry.proxy_port} (${pType})`;
                
                let findingsHtml = proxyEntry.findings.map(f => {
                    let badgeClass = getBadgeClass(f.severity);
                    
                    return `
                    <div style="padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.05); margin-bottom: 4px;">
                        <div style="display:flex; justify-content: space-between; margin-bottom: 4px;">
                            <div class="finding-title" style="display:flex; align-items:center; gap:8px;">
                                <span style="font-family: monospace; color: #00f0ff; font-weight: bold;">${escapeHTML(f.host)}:${escapeHTML(String(f.port))} [${escapeHTML(f.protocol)}]</span>
                                <span class="cve-badge ${badgeClass}">${escapeHTML(f.severity.toUpperCase())}</span>
                            </div>
                        </div>
                        <div style="font-size: 0.85rem; color: var(--text-primary); font-family: 'Inter', sans-serif;">${escapeHTML(f.rule_name)}</div>
                        <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 2px;">${escapeHTML(f.description)}</div>
                        <div style="margin-top: 4px; font-size: 0.7rem; color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); background: rgba(245, 158, 11, 0.05); padding: 2px 6px; display: inline-block; border-radius: 3px;">🔀 ${escapeHTML(f.visibility.toUpperCase())}</div>
                    </div>`;
                }).join('');
                
                pivotHtml += `
                <div class="card" style="border-left: 3px solid #f59e0b; grid-column: 1 / -1; margin-bottom: 1rem;">
                    <div class="card-title" style="color: #f59e0b; font-size: 1.1rem;"><svg style="width:16px;height:16px;vertical-align:middle;margin-right:6px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 3h5v5"></path><path d="M4 20L21 3"></path><path d="M21 16v5h-5"></path><path d="M15 15l6 6"></path><path d="M4 4l5 5"></path></svg> ${proxyTitle}</div>
                    <div style="margin-top: 10px;">
                        ${findingsHtml}
                    </div>
                </div>`;
            });
            
            pivotList.innerHTML = pivotHtml;
        }
    }

    // --- Generate Vis-Network Topology ---
    // Helper to map icon types to inline SVG Data URIs for offline rendering (Moved to top scope so all nodes can use it)
    function getSVGURI(iconType, colorHex) {
        let path = "";
        if (iconType === 'target') {
            // Sleek abstract shield/hexagon for central node
            path = "M12 2L3 6v6.5c0 5.05 3.81 9.85 9 11.5 5.19-1.65 9-6.45 9-11.5V6l-9-4zm0 2L19 7.2v5.3c0 4.1-2.9 8-7 9.5-4.1-1.5-7-5.4-7-9.5V7.2L12 4z M12 6.5l4 2.5v4l-4 2.5-4-2.5v-4l4-2.5z";
        } else if (iconType === 'subnet') {
            // Minimalist switch / network node
            path = "M21 16V8c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v8c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zm-2 0H5V8h14v8z M7 12h2v2H7v-2zm4 0h2v2h-2v-2zm4 0h2v2h-2v-2z";
        } else if (iconType === 'desktop') {
            // Premium Desktop
            path = "M21 2H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h7v2H8v2h8v-2h-2v-2h7c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H3V4h18v12z";
        } else if (iconType === 'mobile') {
            // Premium Mobile
            path = "M17 1.01L7 1c-1.1 0-2 .9-2 2v18c0 1.1.9 2 2 2h10c1.1 0 2-.9 2-2V3c0-1.1-.9-1.99-2-1.99zM17 19H7V5h10v14z";
        } else if (iconType === 'microchip') {
            // IoT / Microchip
            path = "M7 4V2h2v2h2V2h2v2h2V2h2v2h2v4h2v2h-2v2h2v2h-2v2h2v2h-2v4h-2v2h-2v-2h-2v2h-2v-2h-2v2H9v-2H7v2H5v-2H3v-4H1v-2h2v-2H1v-2h2v-2H1V8h2V4h4zm10 14V6H7v12h10zm-2-10v8H9V8h6z";
        } else if (iconType === 'router') {
            // Cisco/Router abstract
            path = "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-2-12l4 4-4 4v-3H7v-2h3V8zm4 8l-4-4 4-4v3h3v2h-3v3z";
        } else {
            // Generic endpoint/mobile
            path = "M20 18c1.1 0 1.99-.9 1.99-2L22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6z";
        }
        
        // Abstract background inside the SVG for premium SOC feel
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="100%" height="100%">
            <defs>
                <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="1" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
            </defs>
            <path d="${path}" fill="${colorHex}" filter="url(#glow)"/>
        </svg>`;
        return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
    }

    const visNodes = new vis.DataSet([]);
    const visEdges = new vis.DataSet([]);

    visNodes.add({ id: 'target', label: `Network\\n${data.target}`, shape: 'image', image: getSVGURI('target', '#00f0ff'), font: { color: '#ffffff', face: 'Outfit' }, size: 38, shadow: { enabled: true, color: 'rgba(0,240,255,0.6)', size: 15 } });

    if (data.subnets) {
        data.subnets.forEach((subnet, sIndex) => {
            const sNodeId = `subnet_${sIndex}`;
            visNodes.add({ id: sNodeId, label: subnet.cidr, shape: 'image', image: getSVGURI('subnet', '#3b82f6'), size: 28, font: { color: '#94a3b8', face: 'Inter' }, shadow: { enabled: true, color: 'rgba(59,130,246,0.4)', size: 10 } });
            visEdges.add({ id: `edge_ts_${sIndex}`, from: 'target', to: sNodeId, color: { color: '#2e354f' }, dashes: true });
            visEdges.add({ from: 'target', to: sNodeId, color: { color: '#475569' } });

            if (subnet.hosts) {
                subnet.hosts.forEach((host, hIndex) => {
                    const hNodeId = `host_${sIndex}_${hIndex}`;
                    const hasVulns = (host.static_findings && host.static_findings.length > 0);
                    
                    let hostLabel = `${host.ip}`;
                    if (host.vendor) hostLabel += `\\n(${host.vendor})`;

                    // Identificar Vendor para Icono
                    let vendorIcon = 'desktop'; // Default desktop
                    if (host.vendor) {
                        const v = host.vendor.toLowerCase();
                        if (v.includes('zte') || v.includes('huawei')) vendorIcon = 'mobile';
                        else if (v.includes('chongqing')) vendorIcon = 'microchip';
                        else if (v.includes('cisco') || v.includes('juniper') || v.includes('mikrotik')) vendorIcon = 'router';
                    }

                    let hostColor = '#1c202f';
                    let hostBorder = '#2e354f';
                    let iconColor = '#00f0ff';
                    if (hasVulns) {
                        hostColor = '#2a0a18';
                        hostBorder = '#ff003c';
                        iconColor = '#ff003c';
                    }

                    visNodes.add({ 
                        id: hNodeId, 
                        label: hostLabel, 
                        shape: 'image', 
                        image: getSVGURI(vendorIcon, iconColor),
                        size: 24,
                        font: { color: '#f1f5f9', face: 'Outfit', size: 14, strokeWidth: 2, strokeColor: '#0f172a' },
                        shadow: { enabled: true, color: hasVulns ? 'rgba(255,0,60,0.8)' : 'rgba(0,240,255,0.6)', size: 20, x: 0, y: 0 },
                        hidden: true
                    });
                    visEdges.add({ id: `edge_sh_${sIndex}_${hIndex}`, from: sNodeId, to: hNodeId, color: { color: '#2e354f', highlight: '#00f0ff' }, hidden: true });
                    
                    if (host.ports && host.ports.length > 0) {
                        host.ports.forEach((port, pIndex) => {
                            const pNodeId = `p_${sIndex}_${hIndex}_${pIndex}`;
                            const pLabel = `${port.port}/${port.protocol}\n${port.service}`;
                            
                            let pColor = '#10141f';
                            let pBorder = '#00f0ff';
                            let pShadow = 'rgba(0, 240, 255, 0.4)';
                            
                            let portStaticVulns = host.static_findings ? host.static_findings.filter(f => f.port === port.port && (f.severity === 'high' || f.severity === 'critical')) : [];
                            
                            if ((port.cves && port.cves.length > 0) || (portStaticVulns.length > 0)) {
                                pColor = '#2a0a18';
                                pBorder = '#ff003c';
                                pShadow = 'rgba(255, 0, 60, 0.6)';
                            }
                            
                            visNodes.add({ 
                                id: pNodeId, 
                                label: pLabel, 
                                shape: 'dot', 
                                size: 12,
                                color: { background: pColor, border: pBorder }, 
                                font: { color: '#94a3b8', face: 'Outfit', size: 11 },
                                shadow: { enabled: true, color: pShadow, size: 10 },
                                hidden: true
                            });
                            visEdges.add({ id: `edge_hp_${sIndex}_${hIndex}_${pIndex}`, from: hNodeId, to: pNodeId, color: { color: '#2e354f' }, hidden: true });
                        });
                    }
                });
            }
        });
    }

    const container = document.getElementById('vis-network');
    if (container && typeof vis !== 'undefined') {
        try {
            const visData = { nodes: visNodes, edges: visEdges };
            const options = {
                nodes: { shapeProperties: { borderRadius: 4 } },
                edges: { smooth: { type: 'continuous', forceDirection: 'none' }, width: 1.5 },
                physics: {
                    enabled: true,
                    barnesHut: { gravitationalConstant: -3000, centralGravity: 0.1, springLength: 200, springConstant: 0.04, damping: 0.09 },
                    stabilization: { iterations: 300 }
                },
                interaction: { hover: true, tooltipDelay: 200 }
            };
            const network = new vis.Network(container, visData, options);
            
            network.on("stabilizationIterationsDone", function () {
                network.setOptions( { physics: false } );
            });

            // Interactividad: Colapso por niveles (Subnet -> Host -> Ports)
            network.on("click", function (params) {
                if (params.nodes.length > 0) {
                    const nodeId = params.nodes[0];
                    let stateChanged = false;
                    
                    // Click on Subnet
                    if (nodeId.startsWith('subnet_')) {
                        const sIndex = nodeId.split('_')[1];
                        const subnetNode = data.subnets[sIndex];
                        if (subnetNode && subnetNode.hosts) {
                            const updates = [];
                            const edgeUpdates = [];
                            const firstHostId = `host_${sIndex}_0`;
                            const firstHostNode = visNodes.get(firstHostId);
                            
                            if (firstHostNode) {
                                const isCurrentlyHidden = firstHostNode.hidden;
                                stateChanged = true;
                                subnetNode.hosts.forEach((h, hIndex) => {
                                    updates.push({ id: `host_${sIndex}_${hIndex}`, hidden: !isCurrentlyHidden });
                                    edgeUpdates.push({ id: `edge_sh_${sIndex}_${hIndex}`, hidden: !isCurrentlyHidden });
                                    // If we are hiding the host, we must also hide its ports
                                    if (!isCurrentlyHidden && h.ports) {
                                        h.ports.forEach((p, pIndex) => {
                                            updates.push({ id: `p_${sIndex}_${hIndex}_${pIndex}`, hidden: true });
                                            edgeUpdates.push({ id: `edge_hp_${sIndex}_${hIndex}_${pIndex}`, hidden: true });
                                        });
                                    }
                                });
                                visNodes.update(updates);
                                visEdges.update(edgeUpdates);
                            }
                        }
                    }
                    // Click on Host
                    else if (nodeId.startsWith('host_')) {
                        const parts = nodeId.split('_');
                        const sIndex = parts[1];
                        const hIndex = parts[2];
                        const hostNode = data.subnets[sIndex].hosts[hIndex];
                        
                        if (hostNode && hostNode.ports) {
                            const updates = [];
                            const edgeUpdates = [];
                            const firstPortId = `p_${sIndex}_${hIndex}_0`;
                            const firstPortNode = visNodes.get(firstPortId);
                            
                            if (firstPortNode) {
                                const isCurrentlyHidden = firstPortNode.hidden;
                                stateChanged = true;
                                hostNode.ports.forEach((p, pIndex) => {
                                    updates.push({ id: `p_${sIndex}_${hIndex}_${pIndex}`, hidden: !isCurrentlyHidden });
                                    edgeUpdates.push({ id: `edge_hp_${sIndex}_${hIndex}_${pIndex}`, hidden: !isCurrentlyHidden });
                                });
                                visNodes.update(updates);
                                visEdges.update(edgeUpdates);
                            }
                        }
                    }

                    // Wake up physics engine briefly so nodes can repel and expand
                    if (stateChanged) {
                        network.setOptions({ physics: true });
                        network.stabilize(50);
                    }
                }
            });
        } catch (e) {
            console.error("Error renderizando Vis-Network:", e);
        }
    }

    // --- Findings Table ---
    const tbody = document.getElementById('findings-body');
    const searchInput = document.getElementById('search-input');
    const filterBtns = document.querySelectorAll('.filter-btn');
    
    // Toggle Topology
    const topologyWrapper = document.getElementById('topology-wrapper');
    const toggleBtn = document.getElementById('toggle-topology-btn');
    if (toggleBtn && topologyWrapper) {
        toggleBtn.addEventListener('click', () => {
            topologyWrapper.classList.toggle('expanded');
            if (topologyWrapper.classList.contains('expanded')) {
                toggleBtn.textContent = 'Collapse Network Topology';
            } else {
                toggleBtn.textContent = 'Expand Network Topology';
            }
        });
    }
    
    let currentFilter = 'all';
    let searchQuery = '';

    // Removed duplicate getBadgeClass definition
    function renderTable() {
        tbody.innerHTML = '';
        const filtered = hostRows.filter(h => {
            const hasVulnOfSeverity = (h.cves.some(c => getBadgeClass(c.severity) === currentFilter) ||
                                      h.static_findings.some(f => getBadgeClass(f.severity) === currentFilter));
            const matchFilter = currentFilter === 'all' || hasVulnOfSeverity;
            
            const textToSearch = `${h.ip} ${h.subnet} ${h.ports.join(' ')} ${h.banners.join(' ')} ${h.cves.map(c=>c.id).join(' ')} ${h.static_findings.map(f=>f.rule_id).join(' ')}`.toLowerCase();
            const matchSearch = textToSearch.includes(searchQuery.toLowerCase());
            return matchFilter && matchSearch;
        });

        if (filtered.length === 0) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td colspan="5" style="text-align: center; padding: 3rem 1rem;">
                    <div style="font-size: 3rem; color: #10b981; margin-bottom: 1rem;">✓</div>
                    <h3 style="color: var(--text-primary); font-size: 1.2rem; margin-bottom: 0.5rem; letter-spacing: 1px;">Secure Posture Confirmed</h3>
                    <p style="color: var(--text-secondary); font-size: 0.9rem;">No assets match the current criteria.</p>
                </td>
            `;
            tbody.appendChild(tr);
            return;
        }

        filtered.forEach(h => {
            // Render Ports
            const portsHTML = h.ports.map(p => `<span class="port-badge">${p}</span>`).join('');
            
            // Render Banners with truncation and tooltip
            const bannersHTML = h.banners.map(b => {
                const truncated = b.length > 45 ? b.substring(0, 42) + '...' : b;
                return `<span class="banner-text" title="${b.replace(/"/g, '&quot;')}">${truncated}</span>`;
            }).join('');
            
            // Render Vulns (CVEs and Static)
            let webHTML = '';
            let vulnsHTML = '';
            
            // Helper function to get color for border based on severity class
            const getBorderColor = (sevClass) => {
                switch(sevClass) {
                    case 'critical': return '#ff003c';
                    case 'high': return '#ff5e00';
                    case 'medium': return '#eab308';
                    case 'low': return '#00f0ff';
                    default: return '#334155';
                }
            };

            const renderFindingMeta = (f) => {
                let metaHTML = '';
                
                // Render Tags (Minimalist pills)
                if (f.tags && f.tags.length > 0) {
                    metaHTML += `<div style="margin-top: 6px; margin-bottom: 6px; display: flex; flex-wrap: wrap; gap: 4px;">`;
                    metaHTML += f.tags.map(t => `<span style="font-size: 0.65rem; padding: 2px 6px; background: rgba(255,255,255,0.05); color: #94a3b8; border: 1px solid rgba(255,255,255,0.1); border-radius: 4px; letter-spacing: 0.5px;">[${t}]</span>`).join('');
                    metaHTML += `</div>`;
                }

                if (f.mitre && f.mitre.length > 0) {
                    metaHTML += f.mitre.map(m => `<span style="display:inline-block; font-size: 0.7rem; padding: 2px 6px; margin-right: 4px; margin-top: 4px; border-radius: 3px; background: rgba(139, 92, 246, 0.15); color: #c4b5fd; border: 1px solid rgba(139, 92, 246, 0.5);">🛡️ ${m}</span>`).join('');
                }
                if (f.compliance && f.compliance.length > 0) {
                    metaHTML += f.compliance.map(c => `<span style="display:inline-block; font-size: 0.7rem; padding: 2px 6px; margin-right: 4px; margin-top: 4px; border-radius: 3px; background: rgba(217, 119, 6, 0.15); color: #fcd34d; border: 1px solid rgba(217, 119, 6, 0.5);">📜 ${c}</span>`).join('');
                }
                if (f.evidence) {
                    const slaStr = f.sla ? `<div style="font-size: 0.75rem; color: #ff003c; margin-top: 6px; font-weight: bold;">SLA Remediación: ${f.sla}</div>` : '';
                    
                    let contextStr = '';
                    if (f.context || f.confidence) {
                        contextStr = `<div style="font-size: 0.7rem; color: #94a3b8; margin-top: 8px; margin-bottom: 4px; font-family: monospace; display: flex; align-items: center; gap: 12px;">`;
                        if (f.context) contextStr += `<span>Context: <span style="color: #00f0ff;">${f.context.toUpperCase()}</span></span>`;
                        if (f.confidence) {
                            let confColor = '#3b82f6';
                            let confBg = 'transparent';
                            let confIcon = '';
                            const confLevel = f.confidence.toLowerCase();
                            if (confLevel === 'confirmed') { confColor = '#000'; confBg = '#10b981'; confIcon = '🎯 '; }
                            else if (confLevel === 'high') { confColor = '#fff'; confBg = '#f97316'; confIcon = '⚠️ '; }
                            else if (confLevel === 'medium') { confColor = '#eab308'; }
                            
                            if (confLevel === 'confirmed' || confLevel === 'high') {
                                contextStr += `<span style="background: ${confBg}; color: ${confColor}; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-family: 'Inter', sans-serif; letter-spacing: 0.5px;">${confIcon}CONFIDENCE: ${f.confidence.toUpperCase()}</span>`;
                            } else {
                                contextStr += `<span>Confidence: <span style="color: ${confColor};">${f.confidence.toUpperCase()}</span></span>`;
                            }
                        }
                        contextStr += `</div>`;
                    }

                    metaHTML += `<details style="margin-top: 8px;">
                        <summary style="cursor: pointer; font-size: 0.75rem; color: #00f0ff; outline: none; user-select: none;">&#128269; Ver PoC Crudo</summary>
                        ${contextStr}
                        <pre style="background: #111; color: #0f0; font-family: monospace; padding: 10px; border: 1px solid #333; border-radius: 4px; overflow-x: auto; font-size: 0.75rem; margin-top: 6px; white-space: pre-wrap; word-break: break-all;">${f.evidence.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
                        ${slaStr}
                    </details>`;
                }
                return metaHTML;
            };

            h.static_findings.forEach(f => {
                const meta = renderFindingMeta(f);
                const cvssStr = (f.cvss_base && f.cvss_base > 0) ? ` (${f.cvss_base})` : '';
                
                if (f.rule_id === 'WEB-TECH-FINGERPRINT') {
                    webHTML += `<div style="margin-bottom: 6px; padding: 6px; background: rgba(0,0,0,0.2); border-left: 2px solid #00f0ff; border-radius: 4px;">
                        <div style="font-size: 0.75rem; color: #00f0ff; text-transform: uppercase; font-weight: bold; margin-bottom: 4px;">${f.rule_name || 'Web Tech'}${cvssStr}</div>
                        <div style="font-size: 0.8rem; color: var(--text-secondary); line-height: 1.4; word-break: break-word;">${f.description || f.rule_id}</div>
                        ${meta}
                    </div>`;
                } else if (f.rule_id === 'TLS-DOMAINS-DISCOVERED') {
                    webHTML += `<div style="margin-bottom: 6px; padding: 6px; background: rgba(0,0,0,0.2); border-left: 2px solid #00f0ff; border-radius: 4px;">
                        <div style="font-size: 0.75rem; color: #00f0ff; text-transform: uppercase; font-weight: bold; margin-bottom: 4px;">${f.rule_name || 'Dominios SSL'}${cvssStr}</div>
                        <div style="font-size: 0.8rem; color: var(--text-secondary); line-height: 1.4; word-break: break-word; font-family: monospace;">${f.description || f.rule_id}</div>
                        ${meta}
                    </div>`;
                } else { 
                    const bColor = getBorderColor(getBadgeClass(f.severity));
                    vulnsHTML += `<div style="margin-bottom: 8px; padding: 6px; background: rgba(0,0,0,0.2); border-left: 2px solid ${bColor}; border-radius: 4px;">
                        <div style="margin-bottom: 4px;"><span class="cve-badge ${getBadgeClass(f.severity)}">${f.rule_id || 'FINDING'}${cvssStr}</span> <span style="font-size: 0.85rem; color: var(--text-primary); font-family: 'Inter', sans-serif;">${f.rule_name || ''}</span></div>
                        ${f.description ? `<div style="font-size: 0.75rem; color: var(--text-secondary); line-height: 1.4; word-break: break-word;">${f.description}</div>` : ''}
                        ${meta}
                    </div>`;
                }
            });
            h.cves.forEach(cve => {
                const bColor = getBorderColor(getBadgeClass(cve.severity));
                vulnsHTML += `<div style="margin-bottom: 8px; padding: 6px; background: rgba(0,0,0,0.2); border-left: 2px solid ${bColor}; border-radius: 4px;">
                    <div style="margin-bottom: 4px;"><span class="cve-badge ${getBadgeClass(cve.severity)}">${cve.id}</span></div>
                    ${cve.description ? `<div style="font-size: 0.75rem; color: var(--text-secondary); line-height: 1.4; word-break: break-word;">${cve.description}</div>` : ''}
                </div>`;
            });
            
            // Render Mitigations
            const mitigationsHTML = h.mitigations.map(m => `<div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 4px; border-left: 2px solid rgba(255,255,255,0.1); padding-left: 6px;">${m}</div>`).join('');

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="vertical-align: top;">
                    <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
                        <span class="host-severity-badge ${getBadgeClass(h.severity)}" title="Host Severity">${getBadgeClass(h.severity)}</span>
                        <div class="host-ip">${h.ip}</div>
                    </div>
                    ${getRiskBadgeHTML(h.riskScore)}
                    ${h.hostname ? `<div class="host-hostname" title="Hostname (DNS)" style="font-family: monospace; font-size: 0.8rem; color: var(--text-primary); margin-bottom: 4px; padding-left: 2px;">${h.hostname}</div>` : ''}
                    <span class="subnet-badge" style="margin-left: 0;">${h.subnet}</span>
                    ${h.mac ? `<div class="host-mac" title="MAC Address" style="display:flex;align-items:center;gap:4px;font-size:0.75rem;margin-bottom:4px;color:var(--text-secondary)"><svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm0-14c-3.31 0-6 2.69-6 6s2.69 6 6 6 6-2.69 6-6-2.69-6-6-6z"/></svg>${h.mac}</div>` : ''}
                    ${h.os ? `<div class="host-os" title="Operating System" style="display:flex;align-items:center;gap:4px;font-size:0.75rem;margin-bottom:4px;color:var(--text-secondary)"><svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M4 6h16v10H4zm2 12h12v2H6z"/></svg>${h.os}</div>` : ''}
                    ${h.vendor ? `<div class="host-vendor" title="Hardware Vendor" style="display:flex;align-items:center;gap:4px;font-size:0.75rem;margin-bottom:4px;color:var(--text-secondary)"><svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 14H4V6h16v12z"/></svg>${h.vendor}</div>` : ''}
                </td>
                <td style="vertical-align: top;">
                    <div class="scrollable-cell">
                        ${portsHTML || '<span style="color: var(--text-secondary)">-</span>'}
                    </div>
                </td>
                <td style="vertical-align: top;">
                    <div class="scrollable-cell">
                        ${bannersHTML || '<span style="color: var(--text-secondary)">-</span>'}
                    </div>
                </td>
                <td style="max-width: 250px; vertical-align: top;">
                    <div class="scrollable-cell">
                        ${webHTML || '<span style="color: var(--text-secondary)">-</span>'}
                    </div>
                </td>
                <td style="max-width: 300px; line-height: 1.8; vertical-align: top;">
                    <div class="scrollable-cell">
                        ${vulnsHTML || '<span style="color: var(--text-secondary)">-</span>'}
                    </div>
                </td>
                <td style="max-width: 300px; vertical-align: top;">
                    <div class="scrollable-cell">
                        ${mitigationsHTML || '<span style="color: var(--text-secondary)">-</span>'}
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    // Event Listeners
    searchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value;
        renderTable();
    });

    filterBtns.forEach(btn => {
        if(btn.id === 'export-csv-btn') return; // Skip export button for filtering logic
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.dataset.filter;
            renderTable();
        });
    });

    // Export to CSV Function
    const exportBtn = document.getElementById('export-csv-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "Host IP,Subnet,Ports,Services & Banners,Vulnerabilities,Mitigations\n";
            
            hostRows.forEach(h => {
                const ports = h.ports.join(';');
                const banners = h.banners.join(';').replace(/"/g, '""');
                const vulns = [...h.static_findings.map(f => f.rule_id), ...h.cves.map(c => c.id)].join(';');
                const mitigations = h.mitigations.join(';').replace(/"/g, '""');
                
                csvContent += `"${h.ip}","${h.subnet}","${ports}","${banners}","${vulns}","${mitigations}"\n`;
            });
            
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", "raptor_executive_export.csv");
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });
    }

    renderTable();
});
