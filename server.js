const express = require('express');
const path = require('path');
const app = express();

// Serve static files from the root and frontend directory
app.use(express.static(__dirname));
app.use('/frontend', express.static(path.join(__dirname, 'frontend')));

// Serve index.html for all routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(5500, () => console.log('Server running on http://127.0.0.1:5500'));