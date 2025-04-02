document.addEventListener('DOMContentLoaded', () => {
    const uploadBox = document.querySelector('.upload-box');
    const fileInput = document.getElementById('fileInput');
    const uploadBtn = document.querySelector('.upload-btn');
    const analysisResults = document.querySelector('.analysis-results');
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    // Tab switching
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');
            
            // Update active states
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.style.display = 'none');
            
            button.classList.add('active');
            document.getElementById(tabId).style.display = 'block';
        });
    });

    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadBox.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    // Highlight drop zone when dragging over it
    ['dragenter', 'dragover'].forEach(eventName => {
        uploadBox.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        uploadBox.addEventListener(eventName, unhighlight, false);
    });

    // Handle dropped files
    uploadBox.addEventListener('drop', handleDrop, false);

    // Handle button click upload
    uploadBtn.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', handleFiles, false);

    function preventDefaults (e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight(e) {
        uploadBox.style.borderColor = 'var(--primary-green)';
        uploadBox.style.boxShadow = '0 0 20px rgba(0, 255, 0, 0.3)';
    }

    function unhighlight(e) {
        uploadBox.style.borderColor = '';
        uploadBox.style.boxShadow = '';
    }

    function handleDrop(e) {
        const dt = e.dataTransfer;
        if (dt.files && dt.files.length > 0) {
            handleFiles({ target: { files: dt.files } });
        }
    }

    function handleFiles(e) {
        console.log('File input event triggered');
        
        if (!e || !e.target) {
            console.error('Invalid event object');
            alert('Error: Invalid file input event');
            return;
        }

        if (!e.target.files) {
            console.error('No files property in event target');
            alert('Error: No files detected');
            return;
        }

        if (e.target.files.length === 0) {
            console.error('No files selected (empty FileList)');
            alert('Error: No files selected');
            return;
        }

        const file = e.target.files[0];
        console.log('File object:', {
            name: file.name,
            size: file.size,
            type: file.type,
            lastModified: file.lastModified
        });

        if (!file) {
            console.error('Invalid file object');
            alert('Error: Invalid file');
            return;
        }

        if (!file.name.toLowerCase().endsWith('.exe')) {
            console.error('Not an exe file:', file.name);
            alert('Please upload an .exe file');
            return;
        }

        if (file.size === 0) {
            console.error('File size is 0 bytes:', file.name);
            alert('Error: The file is empty (0 bytes)');
            return;
        }

        if (file.size > 100 * 1024 * 1024) { // 100MB limit
            console.error('File too large:', formatFileSize(file.size));
            alert('File is too large. Maximum size is 100MB');
            return;
        }

        console.log('File validation passed, proceeding to analysis');
        analyzeFile(file);
    }

    async function analyzeFile(file) {
        try {
            const reader = new FileReader();
            reader.onload = async function(e) {
                try {
                    const content = new Uint8Array(e.target.result);
                    const textDecoder = new TextDecoder('utf-8');
                    let textContent = '';
                    
                    // Try to decode the content in chunks to handle binary files
                    for(let i = 0; i < content.length; i += 1024) {
                        try {
                            const chunk = content.slice(i, i + 1024);
                            textContent += textDecoder.decode(chunk, {stream: true});
                        } catch(e) {
                            console.log('Chunk decode error, continuing...');
                        }
                    }

                    // Analysis results object
                    const results = {
                        suspicious: [],
                        network: [],
                        domains: [],
                        c2servers: [],
                        dlls: [],
                        apis: []
                    };

                    // Search patterns
                    const patterns = {
                        discord: /https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g,
                        playit: /(?:https?:\/\/)?(?:www\.)?playit\.gg\/[a-zA-Z0-9-_\/]*/g,
                        telegram: /(?:https?:\/\/)?t\.me\/[a-zA-Z0-9_]+/g,
                        pastebin: /(?:https?:\/\/)?pastebin\.com\/[a-zA-Z0-9]+/g,
                        urls: /https?:\/\/[a-zA-Z0-9-._~:/?#\[\]@!$&'()*+,;=]+/g,
                        ips: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d{1,5})?\b/g,
                        domains: /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g,
                        dlls: /\b\w+\.dll\b/gi,
                        apis: /\b(CreateProcess|WinExec|ShellExecute|URLDownloadToFile|InternetOpen|socket|connect|WSAStartup|CreateService|VirtualAlloc|WriteProcessMemory|ReadProcessMemory|CreateRemoteThread)\w*\b/g,
                        base64: /[a-zA-Z0-9+/]{30,}={0,2}/g
                    };

                    // Analyze content
                    results.suspicious = [...new Set([
                        ...(textContent.match(patterns.discord) || []),
                        ...(textContent.match(patterns.playit) || []),
                        ...(textContent.match(patterns.telegram) || []),
                        ...(textContent.match(patterns.pastebin) || [])
                    ])];

                    // Extract potential Base64 encoded URLs
                    const base64Strings = textContent.match(patterns.base64) || [];
                    for (const b64str of base64Strings) {
                        try {
                            const decoded = atob(b64str);
                            if (decoded.includes('http') || decoded.includes('discord') || decoded.includes('webhook')) {
                                results.suspicious.push(`[Base64 Encoded] ${decoded}`);
                            }
                        } catch (e) {
                            // Not a valid base64 string, skip
                        }
                    }

                    results.network = [...new Set([
                        ...(textContent.match(patterns.urls) || []),
                        ...(textContent.match(patterns.ips) || [])
                    ])];

                    results.domains = [...new Set(textContent.match(patterns.domains) || [])];
                    results.dlls = [...new Set(textContent.match(patterns.dlls) || [])];
                    results.apis = [...new Set(textContent.match(patterns.apis) || [])];

                    // Identify potential C2 servers
                    results.c2servers = results.network.filter(url => {
                        const lowerUrl = url.toLowerCase();
                        return (
                            lowerUrl.includes('discord.com/api/webhooks') ||
                            lowerUrl.includes('playit.gg') ||
                            lowerUrl.includes('pastebin.com') ||
                            lowerUrl.includes('t.me') ||
                            /:\d{1,5}/.test(url) || // URLs with ports
                            /\\x|%[0-9a-f]{2}/.test(url) // Encoded characters
                        );
                    });

                    // Calculate risk score
                    let riskScore = 0;
                    riskScore += results.suspicious.length * 25;
                    riskScore += results.c2servers.length * 30;
                    riskScore += results.network.length * 10;
                    riskScore += results.apis.length * 15;
                    riskScore = Math.min(100, riskScore);

                    // Update UI with results
                    const fileInfo = document.getElementById('fileInfo');
                    fileInfo.innerHTML = `
                        <div class="found-item">
                            <strong>File Name:</strong> ${file.name}
                        </div>
                        <div class="found-item">
                            <strong>Size:</strong> ${formatFileSize(file.size)}
                        </div>
                        <div class="found-item">
                            <strong>Last Modified:</strong> ${new Date(file.lastModified).toLocaleString()}
                        </div>
                    `;

                    // Update risk score
                    const scoreElement = document.querySelector('.score');
                    scoreElement.textContent = riskScore;
                    scoreElement.style.color = riskScore > 50 ? '#ff3333' : '#00ff00';
                    
                    // Update suspicious activities
                    document.getElementById('suspiciousStrings').innerHTML = `
                        <div class="found-item">
                            <strong>Suspicious URLs:</strong>
                            <pre>${results.suspicious.length > 0 ? results.suspicious.join('\n') : 'None detected'}</pre>
                        </div>
                    `;

                    // Update network connections
                    document.getElementById('networkConnections').innerHTML = `
                        <div class="found-item">
                            <strong>Network Connections:</strong>
                            <pre>${results.network.length > 0 ? results.network.join('\n') : 'None detected'}</pre>
                        </div>
                    `;

                    // Update DNS queries
                    document.getElementById('dnsQueries').innerHTML = `
                        <div class="found-item">
                            <strong>Detected Domains:</strong>
                            <pre>${results.domains.length > 0 ? results.domains.join('\n') : 'None detected'}</pre>
                        </div>
                    `;

                    // Update C2 indicators
                    document.getElementById('c2Indicators').innerHTML = `
                        <div class="found-item">
                            <strong>C2 Indicators:</strong>
                            <pre>${results.c2servers.length > 0 ? results.c2servers.join('\n') : 'None detected'}</pre>
                        </div>
                    `;

                    // Update imported DLLs
                    document.getElementById('importedDlls').innerHTML = `
                        <div class="found-item">
                            <strong>Detected DLLs:</strong>
                            <pre>${results.dlls.length > 0 ? results.dlls.join('\n') : 'None detected'}</pre>
                        </div>
                    `;

                    // Update API calls
                    document.getElementById('apiCalls').innerHTML = `
                        <div class="found-item">
                            <strong>Suspicious APIs:</strong>
                            <pre>${results.apis.length > 0 ? results.apis.join('\n') : 'None detected'}</pre>
                        </div>
                    `;

                    // Show results and hide upload section
                    document.querySelector('.analysis-results').style.display = 'block';
                    document.querySelector('.upload-section').style.display = 'none';

                } catch (error) {
                    console.error('Error analyzing file:', error);
                    alert('Error analyzing file content. Please try again.');
                }
            };

            reader.onerror = function() {
                console.error('Error reading file');
                alert('Error reading file. Please try again.');
            };

            reader.readAsArrayBuffer(file);
        } catch (error) {
            console.error('Error in analyzeFile:', error);
            alert('Error processing file. Please try again.');
        }
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}); 