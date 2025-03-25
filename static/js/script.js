document.addEventListener('DOMContentLoaded', function() {
    // DOM elements
    const emailForm = document.getElementById('emailForm');
    const resultsContainer = document.getElementById('resultsContainer');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const errorAlert = document.getElementById('errorAlert');
    const errorMessage = document.getElementById('errorMessage');

    // Chart.js gauge chart for risk level
    let riskGaugeChart = null;

    // Form submission handler
    emailForm.addEventListener('submit', function(e) {
        e.preventDefault();
        analyzeEmail();
    });

    // Function to analyze the email
    function analyzeEmail() {
        const emailSender = document.getElementById('emailSender').value.trim();
        const emailSubject = document.getElementById('emailSubject').value.trim();
        const emailContent = document.getElementById('emailContent').value.trim();

        // Validate inputs
        if (!emailContent) {
            showError("Please enter the email content.");
            return;
        }

        // Prepare form data
        const formData = new FormData();
        formData.append('email_sender', emailSender);
        formData.append('email_subject', emailSubject);
        formData.append('email_content', emailContent);

        // Show loading indicator
        loadingIndicator.classList.remove('d-none');
        resultsContainer.classList.add('d-none');
        errorAlert.classList.add('d-none');

        // Send request to server
        fetch('/analyze', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Server returned ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            // Hide loading indicator
            loadingIndicator.classList.add('d-none');
            
            if (data.error) {
                showError(data.error);
            } else {
                displayResults(data);
                resultsContainer.classList.remove('d-none');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            loadingIndicator.classList.add('d-none');
            showError("Failed to analyze email: " + error.message);
        });
    }

    // Function to display error message
    function showError(message) {
        errorMessage.textContent = message;
        errorAlert.classList.remove('d-none');
        resultsContainer.classList.add('d-none');
    }

    // Function to display analysis results
    function displayResults(data) {
        // Update overall score and risk level
        const overallScore = document.getElementById('overallScore');
        const scoreValue = data.overall_score;
        let badgeClass = 'bg-success';
        
        if (scoreValue > 70) {
            badgeClass = 'bg-danger';
        } else if (scoreValue > 40) {
            badgeClass = 'bg-warning';
        }
        
        overallScore.className = `badge ${badgeClass} fs-5`;
        overallScore.textContent = `Risk Score: ${scoreValue}%`;
        
        document.getElementById('riskLevel').textContent = data.risk_level + ' Risk';
        
        // Update the gauge chart
        updateRiskGauge(scoreValue);
        
        // Update individual score sections
        updateScoreIndicator('content', data.content_analysis.score * 100, 
            `${data.content_analysis.suspicious_phrases} suspicious phrases detected`);
        
        updateScoreIndicator('url', data.url_analysis.score * 100, 
            `${data.url_analysis.suspicious_urls} of ${data.url_analysis.total_urls} URLs flagged`);
        
        updateScoreIndicator('sender', data.sender_analysis.score * 100, 
            data.sender_analysis.summary);
        
        // Update highlighted content
        document.getElementById('highlightedContent').innerHTML = data.highlighted_content;
        
        // Update URL table
        updateURLTable(data.url_analysis.urls);
        
        // Update educational tips
        updateEducationalTips(data.educational_tips);
    }

    // Update the risk gauge chart
    function updateRiskGauge(score) {
        const ctx = document.getElementById('riskGauge').getContext('2d');
        
        // Destroy existing chart if it exists
        if (riskGaugeChart) {
            riskGaugeChart.destroy();
        }
        
        // Create gauge chart
        riskGaugeChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [
                        getColorForScore(score),
                        'rgba(200, 200, 200, 0.1)'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                circumference: 180,
                rotation: -90,
                cutout: '75%',
                plugins: {
                    tooltip: {
                        enabled: false
                    },
                    legend: {
                        display: false
                    },
                    datalabels: {
                        display: false
                    }
                },
                maintainAspectRatio: true
            }
        });
        
        // Add score value in center
        setTimeout(() => {
            const width = ctx.canvas.width;
            const height = ctx.canvas.height;
            ctx.font = 'bold 20px Arial';
            ctx.fillStyle = getColorForScore(score);
            ctx.textAlign = 'center';
            ctx.fillText(`${Math.round(score)}%`, width / 2, height - 10);
        }, 50);
    }

    // Update score indicators
    function updateScoreIndicator(type, score, summary) {
        const scoreElement = document.getElementById(`${type}Score`);
        const summaryElement = document.getElementById(`${type}Summary`);
        
        // Update the score display
        scoreElement.textContent = `${Math.round(score)}%`;
        scoreElement.style.color = getColorForScore(score);
        
        // Update the summary text
        summaryElement.textContent = summary;
    }

    // Update URL analysis table
    function updateURLTable(urls) {
        const urlTable = document.getElementById('urlTable');
        
        if (!urls || urls.length === 0) {
            urlTable.innerHTML = `
                <tr>
                    <td colspan="3" class="text-center">No URLs detected</td>
                </tr>
            `;
            return;
        }
        
        let tableHTML = '';
        
        urls.forEach(url => {
            let riskClass = 'text-success';
            if (url.risk_level === 'High') {
                riskClass = 'text-danger';
            } else if (url.risk_level === 'Medium') {
                riskClass = 'text-warning';
            }
            
            tableHTML += `
                <tr>
                    <td><code>${url.url}</code></td>
                    <td class="${riskClass}">${url.risk_level}</td>
                    <td>${url.reason}</td>
                </tr>
            `;
        });
        
        urlTable.innerHTML = tableHTML;
    }

    // Update educational tips
    function updateEducationalTips(tips) {
        const tipsContainer = document.getElementById('educationalTips');
        
        if (!tips || tips.length === 0) {
            tipsContainer.innerHTML = '<p class="text-center">No educational tips available.</p>';
            return;
        }
        
        let tipsHTML = '';
        
        tips.forEach(tip => {
            let iconClass = 'fa-info-circle';
            let cardClass = 'border-info';
            
            if (tip.category === 'Content') {
                iconClass = 'fa-file-alt';
                cardClass = 'border-warning';
            } else if (tip.category === 'Links') {
                iconClass = 'fa-link';
                cardClass = 'border-danger';
            } else if (tip.category === 'Sender') {
                iconClass = 'fa-user';
                cardClass = 'border-primary';
            }
            
            tipsHTML += `
                <div class="col-md-6 mb-3">
                    <div class="card h-100 ${cardClass}">
                        <div class="card-header">
                            <i class="fas ${iconClass} me-2"></i>${tip.category}: ${tip.title}
                        </div>
                        <div class="card-body">
                            <p>${tip.description}</p>
                        </div>
                    </div>
                </div>
            `;
        });
        
        tipsContainer.innerHTML = tipsHTML;
    }

    // Helper function to get color based on score
    function getColorForScore(score) {
        if (score > 70) {
            return '#dc3545'; // danger/red
        } else if (score > 40) {
            return '#ffc107'; // warning/yellow
        } else {
            return '#28a745'; // success/green
        }
    }
});
