

let pieChart = null;
let barChart = null;

// Initialize Charts
function initCharts() {
    const pieCtx = document.getElementById('pieChart')?.getContext('2d');
    const barCtx = document.getElementById('barChart')?.getContext('2d');

    if (pieCtx && barCtx) {

        // Pie Chart
        pieChart = new Chart(pieCtx, {
            type: 'pie',
            data: {
                labels: ['Safe URLs', 'Phishing URLs'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: ['#28a745', '#dc3545'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Analysis Overview Bar Chart
        barChart = new Chart(barCtx, {
            type: 'bar',
            data: {
                labels: ['Total Analyzed', 'Safe URLs', 'Phishing URLs'],
                datasets: [{
                    label: 'URL Count',
                    data: [0, 0, 0],
                    backgroundColor: ['#007bff', '#28a745', '#dc3545'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
}

// Update Statistics
async function updateStatistics() {
    try {
        const response = await fetch('/stats');
        const stats = await response.json();

        if (stats.error) {
            console.error('Error loading statistics:', stats.error);
            return;
        }

        // Update Cards
        const safeLinks = document.getElementById('safe-links');
        const phishingLinks = document.getElementById('phishing-links');

        if (safeLinks) safeLinks.textContent = stats.safe_urls;
        if (phishingLinks) phishingLinks.textContent = stats.phishing_urls;

        // Update Pie Chart
        if (pieChart) {
            pieChart.data.datasets[0].data = [
                stats.safe_urls,
                stats.phishing_urls
            ];
            pieChart.update();
        }

        // Update Analysis Overview Chart
        if (barChart) {
            barChart.data.datasets[0].data = [
                stats.total_analyzed,
                stats.safe_urls,
                stats.phishing_urls
            ];
            barChart.update();
        }

    } catch (error) {
        console.error('Error updating statistics:', error);
    }
}

// Initialize on Page Load
document.addEventListener('DOMContentLoaded', function () {
    initCharts();
    updateStatistics();

    // Refresh statistics every 30 seconds
    setInterval(updateStatistics, 30000);
});