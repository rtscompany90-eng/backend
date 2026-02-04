const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Ensure uploads directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR);
}

// Ensure database file exists
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify([]));
}

// Middleware
app.use(helmet());
app.use(cors()); // Allow all origins by default for easy frontend integration
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Database Helpers
const readDb = () => {
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        return [];
    }
};

const writeDb = (data) => {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
};

// Multer Storage Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, `${uuidv4()}${ext}`);
    }
});

// File Filter
const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
        return cb(null, true);
    } else {
        cb(new Error('Only Images and PDFs are allowed!'));
    }
};

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
    fileFilter: fileFilter
});

// ================= API ROUTES =================

// 1. GET /api/files - List all secured files (Public Metadata only)
app.get('/api/files', (req, res) => {
    const files = readDb().sort((a, b) => b.timestamp - a.timestamp); // Newest first
    const safeFiles = files.map(file => ({
        id: file.id,
        originalName: file.originalName,
        mimeType: file.mimeType,
        size: file.size,
        timestamp: file.timestamp,
        isProtected: true // Just a flag for UI
    }));
    res.json(safeFiles);
});

// 2. POST /api/upload - Upload a file with password
app.post('/api/upload', upload.single('file'), async (req, res) => {
    const { password } = req.body;

    if (!req.file || !password) {
        return res.status(400).json({ error: 'File and password are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const newFile = {
            id: uuidv4(),
            originalName: req.file.originalname,
            filename: req.file.filename,
            mimeType: req.file.mimetype,
            size: req.file.size,
            path: req.file.path,
            password: hashedPassword,
            timestamp: Date.now()
        };

        const db = readDb();
        db.push(newFile);
        writeDb(db);

        res.status(201).json({
            message: 'File uploaded and encrypted successfully.',
            fileId: newFile.id
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server Error during upload.' });
    }
});

// 3. POST /api/file/:id/download - Verify password and Download
// We use POST so the password is sent securely in the body, not URL
app.post('/api/file/:id/download', async (req, res) => {
    const { id } = req.params;
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ error: 'Password is required to unlock this file.' });
    }

    const db = readDb();
    const file = db.find(f => f.id === id);

    if (!file) {
        return res.status(404).json({ error: 'File not found.' });
    }

    try {
        const isMatch = await bcrypt.compare(password, file.password);
        if (isMatch) {
            // Check if file exists on disk
            if (fs.existsSync(file.path)) {
                res.download(file.path, file.originalName);
            } else {
                res.status(500).json({ error: 'File integrity error: File missing from disk.' });
            }
        } else {
            res.status(401).json({ error: 'Incorrect password. Access denied.' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal validation error.' });
    }
});

// Global Error Handler
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: err.message });
    } else if (err) {
        return res.status(500).json({ error: err.message });
    }
    next();
});

// Start Server
app.listen(PORT, () => {
    console.log(`Backend API Server running on http://localhost:${PORT}`);
    console.log(`- Uploads stored in ${UPLOAD_DIR}`);
    console.log(`- API Ready: GET /api/files | POST /api/upload | POST /api/file/:id/download`);
});
