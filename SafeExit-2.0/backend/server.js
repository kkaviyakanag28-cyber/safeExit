require('dotenv').config();

const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Server } = require('socket.io');

if (
  !process.env.MONGO_URI ||
  !process.env.JWT_SECRET ||
  process.env.JWT_SECRET.length < 32
) {
  console.error(
    'Set MONGO_URI and a JWT_SECRET of at least 32 characters in backend/.env'
  );
  process.exit(1);
}

const PORT = Number(process.env.PORT || 5000);
const CLIENT = process.env.CLIENT_URL || 'http://localhost:5173';

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: CLIENT,
    credentials: true
  }
});

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'same-site' }
}));

app.use(cors({
  origin: CLIENT,
  credentials: true
}));

app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

app.use((req, res, next) => {
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    const origin = req.get('origin');

    if (origin && origin !== CLIENT) {
      return res.status(403).json({
        message: 'Untrusted origin'
      });
    }
  }

  next();
});

const opts = { timestamps: true };

// ===========================
// DATABASE MODELS
// ===========================

const User = mongoose.model(
  'SafeExitUser',
  new mongoose.Schema({
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },
    passwordHash: {
      type: String,
      required: true
    },
    role: {
      type: String,
      enum: ['student', 'officer', 'warden', 'admin'],
      default: 'student'
    }
  }, opts)
);

const Issue = mongoose.model(
  'SafeExitIssue',
  new mongoose.Schema({
    area: {
      type: String,
      enum: ['college', 'hostel'],
      required: true
    },
    category: {
      type: String,
      required: true
    },
    title: {
      type: String,
      required: true,
      maxlength: 120
    },
    location: {
      type: String,
      required: true,
      maxlength: 150
    },
    description: {
      type: String,
      required: true,
      maxlength: 1500
    },
    visibility: {
      type: String,
      enum: ['public', 'private'],
      default: 'private'
    },
    status: {
      type: String,
      enum: ['pending', 'in_progress', 'resolved', 'rejected'],
      default: 'pending'
    },

    // NEW: Automatic priority
    priority: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'medium'
    },

    // NEW: Student resolution confirmation
    resolutionConfirmation: {
      type: String,
      enum: ['not_required', 'awaiting', 'confirmed', 'reopened'],
      default: 'not_required'
    },

    resolvedAt: {
      type: Date,
      default: null
    },

    // NEW: Automatic escalation
    escalationLevel: {
      type: Number,
      default: 0
    },

    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SafeExitUser',
      required: true
    },
    supportedBy: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SafeExitUser'
    }],
    staffNote: {
      type: String,
      default: '',
      maxlength: 1000
    },
    photo: {
      type: String,
      default: ''
    }
  }, opts)
);

const Message = mongoose.model(
  'SafeExitMessage',
  new mongoose.Schema({
    issue: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SafeExitIssue',
      required: true
    },
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SafeExitUser',
      required: true
    },
    text: {
      type: String,
      required: true,
      maxlength: 1000
    }
  }, opts)
);

const Announcement = mongoose.model(
  'SafeExitAnnouncement',
  new mongoose.Schema({
    area: {
      type: String,
      enum: ['all', 'college', 'hostel'],
      default: 'all'
    },
    title: {
      type: String,
      required: true,
      maxlength: 120
    },
    body: {
      type: String,
      required: true,
      maxlength: 1000
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SafeExitUser'
    }
  }, opts)
);

const Notice = mongoose.model(
  'SafeExitNotice',
  new mongoose.Schema({
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SafeExitUser'
    },
    text: String,
    read: {
      type: Boolean,
      default: false
    }
  }, opts)
);

// ===========================
// AUTHENTICATION
// ===========================

const userDto = u => ({
  id: String(u._id),
  name: u.name,
  email: u.email,
  role: u.role
});

const cookieOpts = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  path: '/',
  maxAge: 7 * 86400000
};

function setSession(res, u) {
  res.cookie(
    'safeexit_session',
    jwt.sign(
      { sub: String(u._id) },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    ),
    cookieOpts
  );
}

async function auth(req, res, next) {
  try {
    const token = req.cookies.safeexit_session;

    if (!token) {
      return res.status(401).json({
        message: 'Please log in'
      });
    }

    const data = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = await User.findById(data.sub);

    if (!req.user) {
      return res.status(401).json({
        message: 'Session expired'
      });
    }

    next();
  } catch {
    return res.status(401).json({
      message: 'Session expired'
    });
  }
}

const staff = u =>
  ['officer', 'warden', 'admin'].includes(u.role);

const allowed = (u, area) =>
  u.role === 'admin' ||
  (u.role === 'officer' && area === 'college') ||
  (u.role === 'warden' && area === 'hostel');

const canSee = (u, issue) =>
  allowed(u, issue.area) ||
  String(issue.createdBy) === String(u._id) ||
  issue.visibility === 'public';

const canMessage = (u, issue) =>
  allowed(u, issue.area) ||
  String(issue.createdBy) === String(u._id);

const sensitive = [
  'Lost & Found',
  'Campus Safety',
  'Hostel Safety',
  'Harassment',
  'Personal Safety'
];

const categories = {
  college: [
    'Electrical',
    'Classroom',
    'Laboratory',
    'Water & Washroom',
    'Campus Safety',
    'Lost & Found',
    'Harassment',
    'Other'
  ],
  hostel: [
    'Room Maintenance',
    'Mess & Food',
    'Water Supply',
    'Wi-Fi',
    'Hostel Safety',
    'Lost & Found',
    'Harassment',
    'Other'
  ]
};

// ===========================
// NEW: PRIORITY CLASSIFICATION
// ===========================

// Keyword-based classification.
// This is not a substitute for emergency services.

function classifyPriority(category, title, description) {
  const text = `${category} ${title} ${description}`.toLowerCase();

  const criticalWords = [
    'fire',
    'smoke',
    'electric shock',
    'electrocution',
    'gas leak',
    'violence',
    'serious injury',
    'sexual harassment',
    'physical assault'
  ];

  const highWords = [
    'sparking',
    'exposed wire',
    'water leakage',
    'no drinking water',
    'unsafe',
    'broken lock',
    'security threat',
    'harassment',
    'bullying'
  ];

  if (criticalWords.some(word => text.includes(word))) {
    return 'critical';
  }

  if (highWords.some(word => text.includes(word))) {
    return 'high';
  }

  if (
    ['Campus Safety', 'Hostel Safety', 'Electrical']
      .includes(category)
  ) {
    return 'high';
  }

  if (['Wi-Fi', 'Lost & Found'].includes(category)) {
    return 'low';
  }

  return 'medium';
}

// ===========================
// HELPERS AND NOTIFICATIONS
// ===========================

function dto(i, u) {
  return {
    id: String(i._id),
    area: i.area,
    category: i.category,
    title: i.title,
    location: i.location,
    description: i.description,
    visibility: i.visibility,
    status: i.status,

    priority: i.priority || 'medium',
    resolutionConfirmation:
      i.resolutionConfirmation || 'not_required',
    escalationLevel: i.escalationLevel || 0,
    resolvedAt: i.resolvedAt || null,

    createdBy: String(i.createdBy),
    supporterCount: i.supportedBy.length,
    supportedByMe: i.supportedBy.some(
      id => String(id) === String(u._id)
    ),
    staffNote: i.staffNote,
    photo: !!i.photo,
    createdAt: i.createdAt
  };
}

const wrap = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const notify = async (id, text) => {
  await Notice.create({ user: id, text });

  io.to('user:' + id).emit('notification', { text });
};

const notifyArea = async (area, text) => {
  const roles = area === 'college'
    ? ['officer', 'admin']
    : ['warden', 'admin'];

  const users = await User.find({
    role: { $in: roles }
  }).select('_id');

  await Promise.all(
    users.map(u => notify(u._id, text))
  );
};

// ===========================
// HEALTH
// ===========================

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// ===========================
// REGISTER AND LOGIN
// ===========================

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 25,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

app.post(
  '/api/auth/register',
  authLimiter,
  wrap(async (req, res) => {
    const { name, email, password } = req.body || {};

    if (
      typeof name !== 'string' ||
      name.trim().length < 2 ||
      name.length > 100 ||
      typeof email !== 'string' ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      typeof password !== 'string' ||
      password.length < 8 ||
      password.length > 128
    ) {
      return res.status(400).json({
        message: 'Valid name, email and password (8+ characters) required'
      });
    }

    const normalized = email.trim().toLowerCase();

    if (await User.exists({ email: normalized })) {
      return res.status(409).json({
        message: 'Email already registered'
      });
    }

    const u = await User.create({
      name: name.trim(),
      email: normalized,
      passwordHash: await bcrypt.hash(password, 12),
      role: 'student'
    });

    setSession(res, u);

    res.status(201).json({
      user: userDto(u)
    });
  })
);

app.post(
  '/api/auth/login',
  authLimiter,
  wrap(async (req, res) => {
    const { email, password } = req.body || {};

    if (
      typeof email !== 'string' ||
      typeof password !== 'string'
    ) {
      return res.status(400).json({
        message: 'Email and password required'
      });
    }

    const u = await User.findOne({
      email: email.trim().toLowerCase()
    });

    if (!u || !await bcrypt.compare(password, u.passwordHash)) {
      return res.status(401).json({
        message: 'Invalid email or password'
      });
    }

    setSession(res, u);

    res.json({
      user: userDto(u)
    });
  })
);

app.get('/api/auth/me', auth, (req, res) => {
  res.json({
    user: userDto(req.user)
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('safeexit_session', {
    path: '/',
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  });

  res.json({ ok: true });
});

// ===========================
// GET REPORTS
// ===========================

app.get(
  '/api/campus-issues',
  auth,
  wrap(async (req, res) => {
    const { area } = req.query;

    if (!['college', 'hostel'].includes(area)) {
      return res.status(400).json({
        message: 'Choose an area'
      });
    }

    if (staff(req.user) && !allowed(req.user, area)) {
      return res.status(403).json({
        message: 'Not authorized for this area'
      });
    }

    const filter = allowed(req.user, area)
      ? { area }
      : {
          area,
          $or: [
            { visibility: 'public' },
            { createdBy: req.user._id }
          ]
        };

    const list = await Issue.find(filter)
      .sort({ createdAt: -1 })
      .limit(250);

    res.json(list.map(i => dto(i, req.user)));
  })
);

app.get(
  '/api/campus-issues/mine',
  auth,
  wrap(async (req, res) => {
    const list = await Issue.find({
      createdBy: req.user._id
    })
      .sort({ createdAt: -1 })
      .limit(250);

    res.json(list.map(i => dto(i, req.user)));
  })
);

// ===========================
// SUBMIT REPORT
// ===========================

app.post(
  '/api/campus-issues',
  auth,
  wrap(async (req, res) => {
    if (req.user.role !== 'student') {
      return res.status(403).json({
        message: 'Only students can submit reports'
      });
    }

    let {
      area,
      category,
      title,
      location,
      description,
      visibility
    } = req.body || {};

    if (
      !categories[area]?.includes(category) ||
      ![title, location, description].every(
        x => typeof x === 'string' && x.trim()
      ) ||
      title.length > 120 ||
      location.length > 150 ||
      description.length > 1500 ||
      !['public', 'private'].includes(visibility)
    ) {
      return res.status(400).json({
        message: 'Please fill in all report fields correctly'
      });
    }

    if (sensitive.includes(category)) {
      visibility = 'private';
    }

    const i = await Issue.create({
      area,
      category,
      title: title.trim(),
      location: location.trim(),
      description: description.trim(),
      visibility,
      createdBy: req.user._id,

      // Automatically assign priority
      priority: classifyPriority(category, title, description)
    });

    io.emit('issuesUpdated', { area });

    await notifyArea(
      area,
      'New ' + area + ' issue: ' + i.title + ' (' + i.location + ')'
    );

    res.status(201).json(dto(i, req.user));
  })
);

// ===========================
// SUPPORT PUBLIC REPORT
// ===========================

app.post(
  '/api/campus-issues/:id/support',
  auth,
  wrap(async (req, res) => {
    if (req.user.role !== 'student') {
      return res.status(403).json({
        message: 'Student account required'
      });
    }

    const i = await Issue.findById(req.params.id);

    if (!i || i.visibility !== 'public') {
      return res.status(404).json({
        message: 'Public report not found'
      });
    }

    if (
      String(i.createdBy) === String(req.user._id) ||
      ['resolved', 'rejected'].includes(i.status)
    ) {
      return res.status(400).json({
        message: 'Cannot support this report'
      });
    }

    await Issue.updateOne(
      { _id: i._id },
      { $addToSet: { supportedBy: req.user._id } }
    );

    io.emit('issuesUpdated', { area: i.area });

    res.json({ ok: true });
  })
);

// ===========================
// STAFF STATUS UPDATE
// ===========================

app.patch(
  '/api/campus-issues/:id/status',
  auth,
  wrap(async (req, res) => {
    const i = await Issue.findById(req.params.id);

    if (!i) {
      return res.status(404).json({
        message: 'Report not found'
      });
    }

    if (!allowed(req.user, i.area)) {
      return res.status(403).json({
        message: 'Not authorized for this area'
      });
    }

    const { status, staffNote } = req.body || {};

    if (
      !['pending', 'in_progress', 'resolved', 'rejected']
        .includes(status) ||
      typeof staffNote !== 'string' ||
      staffNote.length > 1000
    ) {
      return res.status(400).json({
        message: 'Invalid status or note'
      });
    }

    i.status = status;
    i.staffNote = staffNote.trim();

    if (status === 'resolved') {
      i.resolvedAt = new Date();
      i.resolutionConfirmation = 'awaiting';
    } else {
      i.resolvedAt = null;
      i.resolutionConfirmation = 'not_required';
    }

    await i.save();

    const text = status === 'resolved'
      ? `Your report "${i.title}" was marked resolved. Please confirm whether it is fixed.`
      : `Your report "${i.title}" is now ${status.replace('_', ' ')}`;

    await notify(i.createdBy, text);

    io.emit('issuesUpdated', { area: i.area });

    res.json(dto(i, req.user));
  })
);

// ===========================
// NEW: STUDENT CONFIRMATION
// ===========================

app.patch(
  '/api/campus-issues/:id/confirm',
  auth,
  wrap(async (req, res) => {
    const i = await Issue.findById(req.params.id);

    if (!i) {
      return res.status(404).json({
        message: 'Report not found'
      });
    }

    if (String(i.createdBy) !== String(req.user._id)) {
      return res.status(403).json({
        message: 'Only the report owner can confirm'
      });
    }

    if (
      i.status !== 'resolved' ||
      i.resolutionConfirmation !== 'awaiting'
    ) {
      return res.status(400).json({
        message: 'Report is not awaiting confirmation'
      });
    }

    const { confirmed } = req.body || {};

    if (typeof confirmed !== 'boolean') {
      return res.status(400).json({
        message: 'Confirmation must be true or false'
      });
    }

    if (confirmed) {
      i.resolutionConfirmation = 'confirmed';
    } else {
      i.resolutionConfirmation = 'reopened';
      i.status = 'in_progress';
      i.resolvedAt = null;
      i.escalationLevel = 0;
    }

    await i.save();

    if (!confirmed) {
      await notifyArea(
        i.area,
        `Issue reopened by student: ${i.title}`
      );
    }

    io.emit('issuesUpdated', { area: i.area });

    res.json(dto(i, req.user));
  })
);

// ===========================
// PRIVATE MESSAGES
// ===========================

app.get(
  '/api/campus-issues/:id/messages',
  auth,
  wrap(async (req, res) => {
    const i = await Issue.findById(req.params.id);

    if (!i || !canMessage(req.user, i)) {
      return res.status(403).json({
        message: 'Private conversation unavailable'
      });
    }

    const msgs = await Message.find({
      issue: i._id
    })
      .populate('sender', 'name role')
      .sort({ createdAt: 1 })
      .limit(200);

    res.json(msgs.map(m => ({
      id: String(m._id),
      text: m.text,
      sender: m.sender?.name || 'User',
      role: m.sender?.role,
      createdAt: m.createdAt
    })));
  })
);

app.post(
  '/api/campus-issues/:id/messages',
  auth,
  wrap(async (req, res) => {
    const i = await Issue.findById(req.params.id);

    if (!i || !canMessage(req.user, i)) {
      return res.status(403).json({
        message: 'Private conversation unavailable'
      });
    }

    const text = req.body?.text;

    if (
      typeof text !== 'string' ||
      !text.trim() ||
      text.length > 1000
    ) {
      return res.status(400).json({
        message: 'Message must be 1–1000 characters'
      });
    }

    await Message.create({
      issue: i._id,
      sender: req.user._id,
      text: text.trim()
    });

    io.emit('messagesUpdated', {
      issueId: String(i._id)
    });

    if (String(i.createdBy) !== String(req.user._id)) {
      await notify(
        i.createdBy,
        'New staff message about "' + i.title + '"'
      );
    } else {
      await notifyArea(
        i.area,
        'New student message about "' + i.title + '"'
      );
    }

    res.status(201).json({ ok: true });
  })
);

// ===========================
// OPTIONAL PHOTO UPLOAD
// ===========================

const uploadDir = path.join(__dirname, 'private_uploads');

fs.mkdirSync(uploadDir, {
  recursive: true
});

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => {
      const extension = {
        'image/jpeg': 'jpg',
        'image/png': 'png',
        'image/webp': 'webp'
      }[file.mimetype] || 'bin';

      cb(
        null,
        crypto.randomBytes(20).toString('hex') + '.' + extension
      );
    }
  }),
  limits: {
    fileSize: 3 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    cb(
      null,
      ['image/jpeg', 'image/png', 'image/webp']
        .includes(file.mimetype)
    );
  }
});

app.post(
  '/api/campus-issues/:id/photo',
  auth,
  upload.single('photo'),
  wrap(async (req, res) => {
    const i = await Issue.findById(req.params.id);

    if (
      !i ||
      String(i.createdBy) !== String(req.user._id)
    ) {
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }

      return res.status(403).json({
        message: 'Only the author can upload a photo'
      });
    }

    if (!req.file) {
      return res.status(400).json({
        message: 'JPEG, PNG or WebP photo required (max 3 MB)'
      });
    }

    if (i.photo) {
      fs.promises.unlink(
        path.join(uploadDir, i.photo)
      ).catch(() => {});
    }

    i.photo = req.file.filename;
    await i.save();

    res.json({ ok: true });
  })
);

app.get(
  '/api/campus-issues/:id/photo',
  auth,
  wrap(async (req, res) => {
    const i = await Issue.findById(req.params.id);

    if (
      !i ||
      !i.photo ||
      !canSee(req.user, i)
    ) {
      return res.status(404).json({
        message: 'Photo unavailable'
      });
    }

    res.set('Cache-Control', 'private, no-store');

    res.sendFile(
      path.join(uploadDir, path.basename(i.photo))
    );
  })
);

// ===========================
// ANNOUNCEMENTS
// ===========================

app.get(
  '/api/announcements',
  auth,
  wrap(async (req, res) => {
    const q = req.user.role === 'warden'
      ? { area: { $in: ['all', 'hostel'] } }
      : req.user.role === 'officer'
        ? { area: { $in: ['all', 'college'] } }
        : {};

    res.json(
      await Announcement.find(q)
        .sort({ createdAt: -1 })
        .limit(50)
    );
  })
);

app.post(
  '/api/announcements',
  auth,
  wrap(async (req, res) => {
    if (!staff(req.user)) {
      return res.status(403).json({
        message: 'Staff only'
      });
    }

    const { area, title, body } = req.body || {};

    if (
      !['all', 'college', 'hostel'].includes(area) ||
      typeof title !== 'string' ||
      !title.trim() ||
      title.length > 120 ||
      typeof body !== 'string' ||
      !body.trim() ||
      body.length > 1000
    ) {
      return res.status(400).json({
        message: 'Invalid announcement'
      });
    }

    if (
      (req.user.role === 'officer' && area !== 'college') ||
      (req.user.role === 'warden' && area !== 'hostel')
    ) {
      return res.status(403).json({
        message: 'Not authorized for this area'
      });
    }

    const a = await Announcement.create({
      area,
      title: title.trim(),
      body: body.trim(),
      author: req.user._id
    });

    io.emit('announcementsUpdated');

    res.status(201).json(a);
  })
);

// ===========================
// NOTIFICATIONS
// ===========================

app.get(
  '/api/notifications',
  auth,
  wrap(async (req, res) => {
    res.json(
      await Notice.find({
        user: req.user._id
      })
        .sort({ createdAt: -1 })
        .limit(50)
    );
  })
);

app.post(
  '/api/notifications/read',
  auth,
  wrap(async (req, res) => {
    await Notice.updateMany(
      {
        user: req.user._id,
        read: false
      },
      {
        $set: { read: true }
      }
    );

    res.json({ ok: true });
  })
);

// ===========================
// ANALYTICS
// ===========================

app.get(
  '/api/analytics',
  auth,
  wrap(async (req, res) => {
    if (!staff(req.user)) {
      return res.status(403).json({
        message: 'Staff only'
      });
    }

    const filter = req.user.role === 'admin'
      ? {}
      : {
          area: req.user.role === 'officer'
            ? 'college'
            : 'hostel'
        };

    const counts = await Issue.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    res.json({
      total: counts.reduce(
        (n, c) => n + c.count,
        0
      ),
      byStatus: Object.fromEntries(
        counts.map(c => [c._id, c.count])
      )
    });
  })
);

// ===========================
// ERROR HANDLING
// ===========================

app.use((err, req, res, next) => {
  console.error(err.message);

  res.status(
    err instanceof multer.MulterError
      ? 400
      : err instanceof SyntaxError
        ? 400
        : 500
  ).json({
    message: err instanceof multer.MulterError
      ? err.message
      : err instanceof SyntaxError
        ? 'Invalid JSON request'
        : 'Server error'
  });
});

// ===========================
// REAL-TIME SOCKET CONNECTION
// ===========================

io.use(async (socket, next) => {
  try {
    const cookie = require('cookie').parse(
      socket.handshake.headers.cookie || ''
    );

    const payload = jwt.verify(
      cookie.safeexit_session,
      process.env.JWT_SECRET
    );

    const u = await User.findById(payload.sub);

    if (!u) {
      throw Error('Invalid session');
    }

    socket.user = u;
    next();
  } catch {
    next(Error('Unauthorized'));
  }
});

io.on('connection', socket => {
  socket.join('user:' + socket.user._id);
});

// ===========================
// NEW: AUTOMATIC ESCALATION
// ===========================

async function checkEscalations() {
  const issues = await Issue.find({
    status: {
      $in: ['pending', 'in_progress']
    },
    $or: [
      { escalationLevel: { $lt: 2 } },
      { escalationLevel: { $exists: false } }
    ]
  });

  for (const issue of issues) {
    const hours =
      (Date.now() - new Date(issue.createdAt).getTime()) /
      3600000;

    const level = hours >= 48
      ? 2
      : hours >= 24
        ? 1
        : 0;

    const previous = issue.escalationLevel || 0;

    if (level <= previous) {
      continue;
    }

    const updated = await Issue.findOneAndUpdate(
      {
        _id: issue._id,
        status: {
          $in: ['pending', 'in_progress']
        },
        $or: [
          { escalationLevel: previous },
          ...(previous === 0
            ? [{ escalationLevel: { $exists: false } }]
            : [])
        ]
      },
      {
        $set: {
          escalationLevel: level
        }
      },
      {
        new: true
      }
    );

    if (!updated) {
      continue;
    }

    if (level === 1) {
      await notifyArea(
        issue.area,
        `24-hour reminder: "${issue.title}" is still unresolved.`
      );
    }

    if (level === 2) {
      const admins = await User.find({
        role: 'admin'
      }).select('_id');

      await Promise.all(
        admins.map(u =>
          notify(
            u._id,
            `48-hour escalation: "${issue.title}" (${issue.area}) needs attention.`
          )
        )
      );
    }
  }
}

// ===========================
// START BACKEND
// ===========================

async function start() {
  await mongoose.connect(process.env.MONGO_URI);

  console.log('MongoDB connected');

  server.listen(PORT, () => {
    console.log(
      'SafeExit backend: http://localhost:' + PORT
    );
  });

  checkEscalations().catch(e => {
    console.error('Escalation check:', e.message);
  });

  setInterval(() => {
    checkEscalations().catch(e => {
      console.error('Escalation check:', e.message);
    });
  }, 15 * 60 * 1000);
}

if (require.main === module) {
  start().catch(e => {
    console.error(e.message);
    process.exit(1);
  });
}

module.exports = {
  app,
  allowed,
  canSee
};