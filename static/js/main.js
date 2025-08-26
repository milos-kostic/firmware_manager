document.addEventListener('DOMContentLoaded', (event) => {
    console.log('DOM fully loaded and parsed');

    // Example: Add a click event listener to a button
    const checkFirmwareButton = document.getElementById('check-firmware-btn');
    if (checkFirmwareButton) {
        checkFirmwareButton.addEventListener('click', async () => {
            const deviceModel = document.getElementById('device-model').value;
            const installedVersion = document.getElementById('installed-version').value;

            if (deviceModel && installedVersion) {
                await fetchFirmwareStatus(deviceModel, installedVersion);
            } else {
                alert('Please enter both device model and installed version.');
            }
        });
    }

    async function fetchFirmwareStatus(model, installedVersion) {
        try {
            // This is the URL for the /check_firmware endpoint in Flask app
            const url = `/check_firmware?model=${encodeURIComponent(model)}&installed_version=${encodeURIComponent(installedVersion)}`;

            // Make a fetch request to the backend
            const response = await fetch(url);

            // The backend returns a JSON object, but Flask route
            // currently returns a rendered template.
            // For a pure API call, the backend should use jsonify().
            // For this example, we'll assume the backend returns JSON.
            const result = await response.json();

            // Update the UI with the result
            const statusDiv = document.getElementById('firmware-status');
            if (result.error) {
                statusDiv.innerHTML = `<p style="color: red;">Error: ${result.error}</p>`;
            } else {
                statusDiv.innerHTML = `
                    <p><strong>Model:</strong> ${result.model}</p>
                    <p><strong>Status:</strong> ${result.status}</p>
                    <p><strong>Installed Version:</strong> ${result.installed}</p>
                    <p><strong>Latest Version:</strong> ${result.latest}</p>
                `;
            }

        } catch (error) {
            console.error('Failed to fetch firmware status:', error);
            document.getElementById('firmware-status').innerHTML = `<p style="color: red;">An unexpected error occurred.</p>`;
        }
    }
});