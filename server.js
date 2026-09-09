// ORIGINAL PROJECT FILE: backend/server.js

import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import {
  timingSafeEqual,
  createHmac,
  randomBytes,
} from "node:crypto";
import "dotenv/config";

const app = express();



// this is port code
// =====================================================
// PORT CONFIGURATION
// =====================================================

const PORT = process.env.PORT || 5000;


// =====================================================
// ENVIRONMENT VARIABLES
// =====================================================

const {
  JWT_SECRET,
  MONGODB_URI,
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  ADMIN_SECURITY_PIN,
} = process.env;


if (
  !JWT_SECRET ||
  !MONGODB_URI ||
  !ADMIN_USERNAME ||
  !ADMIN_PASSWORD ||
  !ADMIN_SECURITY_PIN
) {
  throw new Error(
    "Complete all required settings in backend/.env"
  );
}


if (!/^\d{6}$/.test(ADMIN_SECURITY_PIN)) {
  throw new Error(
    "ADMIN_SECURITY_PIN must contain exactly 6 digits"
  );
}


// =====================================================
// this is the cors code
// KHAN EASY KAHTA - CORS CONFIGURATION
// =====================================================

const allowedOrigins = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "https://khan-easy-kahta-frontend.vercel.app",
  ...(process.env.FRONTEND_URL
    ? [process.env.FRONTEND_URL.replace(/\/+$/, "")]
    : []),
];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin, such as mobile apps, Postman, curl,
      // and server-to-server requests.
      if (!origin) {
        return callback(null, true);
      }

      if (
        allowedOrigins.includes(origin) ||
        /^http:\/\/localhost:[0-9]+$/.test(origin) ||
        /^http:\/\/127\.0\.0\.1:[0-9]+$/.test(origin) ||
        /^https:\/\/khan-easy-kahta-frontend.*\.vercel\.app$/.test(origin)
      ) {
        return callback(null, true);
      }

      console.log("CORS blocked:", origin);
      return callback(new Error("This origin is not allowed by CORS"));
    },
    credentials: true,
  })
);

app.use(express.json());


// =====================================================
// HELPERS
// =====================================================

const wrap = (handler) => (req, res, next) =>
  Promise.resolve(
    handler(req, res, next)
  ).catch(next);


const fail = (res, status, code) =>
  res.status(status).json({
    code,
    message: code,
  });


const validPassword = (value) =>
  typeof value === "string" &&
  value.length >= 6 &&
  Buffer.byteLength(value, "utf8") <= 72;


// =====================================================
// DATABASE SCHEMAS
// =====================================================

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    email: {
      type: String,
      trim: true,
      lowercase: true,
      unique: true,
      sparse: true,
    },
    passwordHash: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: ["admin", "user"],
      default: "user",
    },
    accountStatus: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "approved",
      index: true,
    },
    accountReviewedAt: Date,
    accountReviewedBy: mongoose.Schema.Types.ObjectId,
    monthlyFee: {
      type: Number,
      min: 0,
      default: 0,
    },
    tokenVersion: {
      type: Number,
      default: 0,
    },
    adminRecovery: {
      ticketHash: String,
      expiresAt: Date,
      passwordVersion: String,
    },
    passwordReset: {
      requestRef: String,
      ticketHash: String,
      status: {
        type: String,
        enum: [
          "pending",
          "approved",
          "rejected",
          "completed",
          "locked",
        ],
      },
      requestedAt: Date,
      expiresAt: Date,
      approvedAt: Date,
      approvedBy: mongoose.Schema.Types.ObjectId,
    },
  },
  { timestamps: true }
);

const khanPasswordResetSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    username: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
    },
    email: {
      type: String,
      default: "",
      trim: true,
      lowercase: true,
    },
    requestRef: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    ticketHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    status: {
      type: String,
      enum: [
        "pending",
        "approved",
        "rejected",
        "completed",
        "expired",
        "locked",
      ],
      default: "pending",
      index: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: true,
    },
    approvedAt: Date,
    approvedBy: mongoose.Schema.Types.ObjectId,
  },
  { timestamps: true }
);


const customerSchema = new mongoose.Schema(
  {
    id: { type: Number, required: true, unique: true },
    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    name: { type: String, required: true, trim: true },
    fatherName: { type: String, default: "", trim: true },
    phone: { type: String, default: "", trim: true },
    address: { type: String, default: "", trim: true },
  },
  { timestamps: true }
);

const transactionSchema = new mongoose.Schema(
  {
    id: { type: Number, required: true, unique: true },
    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    customerId: { type: Number, required: true, index: true },
    type: {
      type: String,
      enum: ["credit", "payment"],
      required: true,
    },
    amount: { type: Number, min: 1, required: true },
    date: { type: String, required: true },
    note: { type: String, default: "", trim: true },
  },
  { timestamps: true }
);

const profileSchema = new mongoose.Schema(
  {
    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      unique: true,
    },
    shopName: { type: String, default: "", trim: true },
    ownerName: { type: String, default: "", trim: true },
    phone: { type: String, default: "", trim: true },
    address: { type: String, default: "", trim: true },
  },
  { timestamps: true }
);

const paymentSchema = new mongoose.Schema(
  {
    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    month: { type: String, required: true, index: true },
    amount: { type: Number, required: true, min: 0 },
    transactionId: {
      type: String,
      required: true,
      trim: true,
    },
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },
    reviewedAt: { type: Date, default: null },
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
  },
  { timestamps: true }
);

paymentSchema.index(
  { ownerId: 1, month: 1 },
  { unique: true }
);

const financeSchema = new mongoose.Schema(
  {
    id: { type: Number, required: true, unique: true },
    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    type: {
      type: String,
      enum: ["income", "expense"],
      required: true,
    },
    amount: { type: Number, min: 1, required: true },
    date: { type: String, required: true, index: true },
    category: { type: String, default: "", trim: true },
    note: { type: String, default: "", trim: true },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const KhanPasswordReset = mongoose.model(
  "KhanPasswordReset",
  khanPasswordResetSchema
);
const Customer = mongoose.model("Customer", customerSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);
const Profile = mongoose.model("Profile", profileSchema);
const Payment = mongoose.model("Payment", paymentSchema);
const Finance = mongoose.model("Finance", financeSchema);

// =====================================================
// HELPERS
// =====================================================

function createId() {
  return Date.now() * 1000 + Math.floor(Math.random() * 1000);
}

function publicUser(user) {
  return {
    id: user._id,
    username: user.username,
    email: user.email || "",
    role: user.role,
    monthlyFee: user.monthlyFee || 0,
    accountStatus: user.accountStatus || "approved",
  };
}

function createSession(user) {
  const token = jwt.sign(
    {
      userId: String(user._id),
      username: user.username,
      role: user.role,
      purpose: "session",
      tokenVersion: user.tokenVersion || 0,
    },
    JWT_SECRET,
    { expiresIn: "8h" }
  );

  return { token, user: publicUser(user) };
}

function billingPeriod() {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Karachi",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date());

  const values = Object.fromEntries(
    parts.map((part) => [part.type, part.value])
  );

  return {
    month: `${values.year}-${values.month}`,
    day: Number(values.day),
  };
}

async function subscriptionStatus(userId, role) {
  const { month, day } = billingPeriod();

  if (role === "admin") {
    return {
      month,
      day,
      monthlyFee: 0,
      locked: false,
      gracePeriod: false,
      payment: null,
    };
  }

  const [user, payment] = await Promise.all([
    User.findById(userId).select("monthlyFee").lean(),
    Payment.findOne({ ownerId: userId, month }).lean(),
  ]);

  const monthlyFee = Number(user?.monthlyFee || 0);
  const approved = payment?.status === "approved";
  const paymentRequired = monthlyFee > 0;

  return {
    month,
    day,
    monthlyFee,
    gracePeriod: paymentRequired && day <= 3 && !approved,
    locked: paymentRequired && day > 3 && !approved,
    payment: payment || null,
  };
}

async function ensureAdminUser() {
  const existingAdmin = await User.findOne({
    username: ADMIN_USERNAME,
  });

  if (!existingAdmin) {
    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);

    await User.create({
      username: ADMIN_USERNAME,
      passwordHash,
      role: "admin",
      monthlyFee: 0,
    });

    console.log("Admin account created successfully");
  }

  const configuredAdmin = await User.findOne({
    username: ADMIN_USERNAME,
  });

  if (configuredAdmin.role !== "admin") {
    configuredAdmin.role = "admin";
    configuredAdmin.monthlyFee = 0;
    await configuredAdmin.save();
  }

  await User.updateMany(
    {
      role: "admin",
      _id: { $ne: configuredAdmin._id },
    },
    { $set: { role: "user" } }
  );
}

// =====================================================
// AUTHENTICATION
// =====================================================

function createAuthentication(User, secret) {
  return wrap(async (req, res, next) => {
    const header = req.headers.authorization || "";
    let claims;

    try {
      claims = jwt.verify(
        header.startsWith("Bearer ") ? header.slice(7) : "",
        secret,
        { algorithms: ["HS256"] }
      );
    } catch {
      return fail(res, 401, "SESSION_EXPIRED");
    }

    if (
      claims.purpose !== "session" ||
      !mongoose.isValidObjectId(claims.userId)
    ) {
      return fail(res, 401, "SESSION_EXPIRED");
    }

    const user = await User.findById(claims.userId)
      .select("username role tokenVersion accountStatus")
      .lean();

    if (
      !user ||
      claims.tokenVersion !== (user.tokenVersion || 0)
    ) {
      return fail(res, 401, "SESSION_EXPIRED");
    }

    if (
      user.accountStatus &&
      user.accountStatus !== "approved"
    ) {
      return fail(res, 403, "ACCOUNT_NOT_APPROVED");
    }

    req.user = {
      userId: String(user._id),
      username: user.username,
      role: user.role,
      tokenVersion: user.tokenVersion || 0,
    };

    next();
  });
}

const authenticateToken = createAuthentication(User, JWT_SECRET);

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Admin access is required",
    });
  }

  next();
}

async function requireActiveSubscription(req, res, next) {
  try {
    const status = await subscriptionStatus(
      req.user.userId,
      req.user.role
    );

    if (status.locked) {
      return res.status(402).json({
        message: "Monthly payment is required to unlock this account",
        subscription: status,
      });
    }

    next();
  } catch (error) {
    next(error);
  }
}

// =====================================================
// PASSWORD RECOVERY AND RATE LIMITS
// =====================================================

function installPasswordRecovery(
  app,
  {
    User,
    KhanPasswordReset,
    secret,
    authenticateToken,
    requireAdmin,
    adminUsername,
    adminPin,
  }
) {
  const digest = (value) =>
    createHmac("sha256", secret).update(value).digest("hex");

  const ticketHash = (ticket) => digest(`ticket:${ticket}`);
  const hour = 60 * 60 * 1000;

  // Login and password-recovery attempt limits were removed.
  const ipLimit = () => (_req, _res, next) => next();

  const credentials = (req) => ({
    username:
      typeof req.body?.username === "string"
        ? req.body.username.trim().slice(0, 100)
        : "",
    email:
      typeof req.body?.email === "string"
        ? req.body.email.trim().toLowerCase().slice(0, 200)
        : "",
    ticket:
      typeof req.body?.ticket === "string"
        ? req.body.ticket
        : "",
  });

  const ticketQuery = (req) => {
    const { ticket } = credentials(req);

    return {
      role: "user",
      "passwordReset.ticketHash": ticketHash(ticket),
    };
  };

  app.use(
    "/api/auth/login",
    ipLimit("login", 30, 15 * 60 * 1000)
  );

  app.use(
    "/api/auth/register",
    ipLimit("register", 10, hour)
  );

  app.use(
    "/api/auth/admin-pin",
    ipLimit("admin-pin", 10, 15 * 60 * 1000)
  );

  // Verify the private admin PIN before granting a password reset.
  app.post(
    "/api/auth/admin-recovery/verify-pin",
    ipLimit("admin-recovery-ip", 5, 15 * 60 * 1000),
    wrap(async (req, res) => {
      const suppliedPin = req.body?.adminPin;

      if (
        typeof adminPin !== "string" ||
        !/^\d{6}$/.test(adminPin) ||
        typeof suppliedPin !== "string" ||
        !/^\d{6}$/.test(suppliedPin)
      ) {
        return fail(res, 400, "ADMIN_RECOVERY_INVALID");
      }

      const pinMatches = timingSafeEqual(
        Buffer.from(suppliedPin),
        Buffer.from(adminPin)
      );

      if (!pinMatches) {
        return fail(res, 400, "ADMIN_RECOVERY_INVALID");
      }

      const user = await User.findOne({
        username: adminUsername,
        role: "admin",
      });

      if (!user) {
        return fail(res, 400, "ADMIN_RECOVERY_INVALID");
      }

      const resetToken = randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

      const updated = await User.findOneAndUpdate(
        {
          _id: user._id,
          role: "admin",
          passwordHash: user.passwordHash,
        },
        {
          $set: {
            adminRecovery: {
              ticketHash: ticketHash(resetToken),
              expiresAt,
              passwordVersion: digest(user.passwordHash),
            },
          },
        }
      );

      if (!updated) {
        return fail(res, 400, "ADMIN_RECOVERY_INVALID");
      }

      res.set("Cache-Control", "no-store").json({
        resetToken,
        expiresAt,
        username: adminUsername,
      });
    })
  );

  app.post(
    "/api/auth/admin-reset-password",
    ipLimit("admin-reset-ip", 20, 15 * 60 * 1000),
    wrap(async (req, res) => {
      const { username } = credentials(req);
      const { resetToken, newPassword } = req.body || {};

      if (
        username !== adminUsername ||
        typeof resetToken !== "string" ||
        !/^[a-f0-9]{64}$/.test(resetToken)
      ) {
        return fail(res, 400, "ADMIN_RESET_EXPIRED");
      }

      if (!validPassword(newPassword)) {
        return fail(res, 400, "PASSWORD_REQUIRED");
      }

      const query = {
        username: adminUsername,
        role: "admin",
        "adminRecovery.ticketHash": ticketHash(resetToken),
        "adminRecovery.expiresAt": { $gt: new Date() },
      };

      const user = await User.findOne(query);

      if (
        !user ||
        user.adminRecovery.passwordVersion !== digest(user.passwordHash)
      ) {
        return fail(res, 400, "ADMIN_RESET_EXPIRED");
      }

      const passwordHash = await bcrypt.hash(newPassword, 12);

      const updated = await User.findOneAndUpdate(
        {
          ...query,
          _id: user._id,
          passwordHash: user.passwordHash,
          "adminRecovery.expiresAt": { $gt: new Date() },
        },
        {
          $set: { passwordHash },
          $inc: { tokenVersion: 1 },
          $unset: { passwordReset: "", adminRecovery: "" },
        }
      );

      if (!updated) {
        return fail(res, 400, "ADMIN_RESET_EXPIRED");
      }

      res.set("Cache-Control", "no-store").json({
        code: "PASSWORD_UPDATED",
      });
    })
  );

  // User password recovery requires admin approval.
  // Username OR Email is accepted.
  // Normal users use KhanPasswordReset collection.
  // Admin keeps the separate private PIN recovery above.
  app.post(
    "/api/auth/forgot-password",
    ipLimit("forgot", 20, hour),
    wrap(async (req, res) => {
      const { username, email } = credentials(req);

      if (!username && !email) {
        return res.status(400).json({
          code: "USERNAME_OR_EMAIL_REQUIRED",
          message: "Enter your username or email.",
        });
      }

      let user = null;

      if (username) {
        user = await User.findOne({
          username,
          role: "user",
        });
      }

      if (!user && email) {
        user = await User.findOne({
          email,
          role: "user",
        });
      }

      if (!user) {
        return res.status(404).json({
          code: "ACCOUNT_NOT_FOUND",
          message:
            "No Khan Easy Kahta account found with this username or email.",
        });
      }

      const now = new Date();

      // Close any older active request for this user.
      await KhanPasswordReset.updateMany(
        {
          userId: user._id,
          status: { $in: ["pending", "approved"] },
        },
        {
          $set: { status: "expired" },
        }
      );

      const ticket = randomBytes(32).toString("hex");
      const requestRef = randomBytes(12).toString("hex");

      // Admin has two minutes to review this request.
      const expiresAt = new Date(Date.now() + 2 * 60 * 1000);

      const recovery = await KhanPasswordReset.create({
        userId: user._id,
        username: user.username,
        email: user.email || "",
        requestRef,
        ticketHash: ticketHash(ticket),
        status: "pending",
        expiresAt,
      });

      res.status(202).json({
        ticket,
        requestRef: recovery.requestRef,
        requestId: recovery._id,
        username: recovery.username,
        email: recovery.email,
        status: recovery.status,
        expiresAt: recovery.expiresAt,
        code: "REQUEST_SUBMITTED",
        message: "Password recovery request sent to admin.",
      });
    })
  );

  app.post(
    "/api/auth/reset-status",
    ipLimit("reset-status", 240, hour),
    wrap(async (req, res) => {
      const { ticket } = credentials(req);

      if (!/^[a-f0-9]{64}$/.test(ticket)) {
        return fail(res, 400, "INVALID_REQUEST");
      }

      const recovery = await KhanPasswordReset.findOne({
        ticketHash: ticketHash(ticket),
      });

      if (!recovery) {
        return res.json({
          status: "pending",
          expiresAt: null,
        });
      }

      if (
        recovery.expiresAt <= new Date() &&
        !["completed", "rejected", "expired"].includes(recovery.status)
      ) {
        recovery.status = "expired";
        await recovery.save();
      }

      res.json({
        requestId: recovery._id,
        requestRef: recovery.requestRef,
        username: recovery.username,
        email: recovery.email,
        status: recovery.status,
        expiresAt: recovery.expiresAt,
      });
    })
  );

  app.post(
    "/api/auth/reset-password",
    ipLimit("reset", 20, 15 * 60 * 1000),
    wrap(async (req, res) => {
      const { ticket } = credentials(req);
      const { newPassword } = req.body || {};

      if (!/^[a-f0-9]{64}$/.test(ticket)) {
        return fail(res, 400, "RESET_INVALID");
      }

      if (!validPassword(newPassword)) {
        return fail(res, 400, "PASSWORD_REQUIRED");
      }

      const recovery = await KhanPasswordReset.findOne({
        ticketHash: ticketHash(ticket),
        status: "approved",
        expiresAt: { $gt: new Date() },
      });

      if (!recovery) {
        return fail(res, 400, "RESET_INVALID");
      }

      const user = await User.findOne({
        _id: recovery.userId,
        role: "user",
      });

      if (!user) {
        return fail(res, 404, "ACCOUNT_NOT_FOUND");
      }

      const passwordHash = await bcrypt.hash(newPassword, 12);

      user.passwordHash = passwordHash;
      user.tokenVersion = Number(user.tokenVersion || 0) + 1;

      await user.save();

      recovery.status = "completed";
      await recovery.save();

      res.json({
        code: "PASSWORD_UPDATED",
        message:
          "Password changed successfully. You can now log in.",
      });
    })
  );

  app.get(
    "/api/admin/password-resets",
    authenticateToken,
    requireAdmin,
    wrap(async (_req, res) => {
      const now = new Date();

      await KhanPasswordReset.updateMany(
        {
          status: { $in: ["pending", "approved"] },
          expiresAt: { $lte: now },
        },
        {
          $set: { status: "expired" },
        }
      );

      const requests = await KhanPasswordReset.find({
        createdAt: {
          $gt: new Date(Date.now() - 7 * 24 * hour),
        },
      })
        .sort({ createdAt: -1 })
        .limit(100)
        .lean();

      res.json(
        requests.map((request) => ({
          requestId: request._id,
          requestRef: request.requestRef,
          username: request.username,
          email: request.email || "",
          status: request.status,
          requestedAt: request.createdAt,
          expiresAt: request.expiresAt,
        }))
      );
    })
  );

  app.post(
    "/api/admin/password-resets/:ref/review",
    authenticateToken,
    requireAdmin,
    ipLimit("reset-review", 30, hour),
    wrap(async (req, res) => {
      const { decision } = req.body || {};

      if (!["approved", "rejected"].includes(decision)) {
        return fail(res, 400, "INVALID_REQUEST");
      }

      if (decision === "approved" && req.body.verified !== true) {
        return fail(res, 400, "VERIFY_USER_FIRST");
      }

      const now = new Date();

      const recovery = await KhanPasswordReset.findOne({
        requestRef: req.params.ref,
        status: "pending",
      });

      if (!recovery) {
        return fail(res, 409, "REQUEST_CHANGED");
      }

      if (recovery.expiresAt <= now) {
        recovery.status = "expired";
        await recovery.save();

        return fail(res, 409, "REQUEST_EXPIRED");
      }

      if (decision === "approved") {
        recovery.status = "approved";
        recovery.approvedAt = now;
        recovery.approvedBy = req.user.userId;
      } else {
        recovery.status = "rejected";
      }

      await recovery.save();

      res.json({
        code:
          decision === "approved"
            ? "REQUEST_APPROVED"
            : "REQUEST_REJECTED",
        requestId: recovery._id,
        requestRef: recovery.requestRef,
        status: recovery.status,
        expiresAt: recovery.expiresAt,
      });
    })
  );
}

// =====================================================
// SELF-REGISTRATION AND ACCOUNT APPROVAL
// =====================================================

function installAccountRegistration(
  app,
  { User, authenticateToken, requireAdmin }
) {
  app.post(
    "/api/auth/register",
    wrap(async (req, res) => {
      const username =
        typeof req.body?.username === "string"
          ? req.body.username.trim()
          : "";

      const email =
        typeof req.body?.email === "string"
          ? req.body.email.trim().toLowerCase()
          : "";

      const password = req.body?.password;

      if (!username) {
        return res.status(400).json({
          message: "Username is required.",
        });
      }

      if (!email) {
        return res.status(400).json({
          message: "Email is required.",
        });
      }

      const emailIsValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

      if (!emailIsValid) {
        return res.status(400).json({
          message: "Enter a valid email address.",
        });
      }

      if (!validPassword(password)) {
        return res.status(400).json({
          message: "Password is required.",
        });
      }

      if (await User.exists({ username })) {
        return res.status(409).json({
          message: "This username is unavailable.",
        });
      }

      if (await User.exists({ email })) {
        return res.status(409).json({
          message: "This email is already registered.",
        });
      }

      const passwordHash = await bcrypt.hash(password, 12);

      try {
        await User.create({
          username,
          email,
          passwordHash,
          role: "user",
          monthlyFee: 0,
          accountStatus: "pending",
        });
      } catch (error) {
        if (error.code === 11000) {
          return res.status(409).json({
            message: "This username or email is already registered.",
          });
        }
        throw error;
      }

      res.status(201).json({
        status: "pending",
        message: "Account request sent to admin for approval.",
      });
    })
  );

  app.get(
    "/api/admin/account-requests",
    authenticateToken,
    requireAdmin,
    wrap(async (_req, res) => {
      const users = await User.find({
        role: "user",
        accountStatus: { $in: ["pending", "rejected"] },
      })
        .select("username email accountStatus createdAt monthlyFee")
        .sort({ createdAt: -1 })
        .lean();

      res.json(
        users.map((user) => ({
          id: String(user._id),
          username: user.username,
          email: user.email || "",
          status: user.accountStatus,
          createdAt: user.createdAt,
        }))
      );
    })
  );

  app.post(
    "/api/admin/account-requests/:id/review",
    authenticateToken,
    requireAdmin,
    wrap(async (req, res) => {
      const { decision, monthlyFee } = req.body || {};

      if (
        !mongoose.isValidObjectId(req.params.id) ||
        !["approved", "rejected"].includes(decision)
      ) {
        return fail(res, 400, "INVALID_REQUEST");
      }

      if (
        decision === "approved" &&
        (
          typeof monthlyFee !== "number" ||
          !Number.isFinite(monthlyFee) ||
          monthlyFee < 0
        )
      ) {
        return res.status(400).json({
          message: "Enter a valid monthly fee.",
        });
      }

      const update = {
        accountStatus: decision,
        accountReviewedAt: new Date(),
        accountReviewedBy: req.user.userId,
      };

      if (decision === "approved") {
        update.monthlyFee = monthlyFee;
      }

      const user = await User.findOneAndUpdate(
        {
          _id: req.params.id,
          role: "user",
          accountStatus: "pending",
        },
        {
          $set: update,
          $inc: { tokenVersion: 1 },
        },
        { new: true, runValidators: true }
      );

      if (!user) {
        return res.status(409).json({
          message:
            "This request was already reviewed. Refresh the list.",
        });
      }

      res.json({ status: user.accountStatus });
    })
  );
}

// =====================================================
// PUBLIC ROUTES
// =====================================================

app.get("/", (_req, res) => {
  res.json({
    app: "Khan Easy Kahta",
    status: "running",
    database: "MongoDB",
  });
});

app.get("/api/health", (_req, res) => {
  res.json({
    app: "Khan Easy Kahta",
    status: "running",
    database: "MongoDB",
  });
});

installPasswordRecovery(app, {
  User,
  KhanPasswordReset,
  secret: JWT_SECRET,
  authenticateToken,
  requireAdmin,
  adminUsername: ADMIN_USERNAME,
  adminPin: ADMIN_SECURITY_PIN,
});

installAccountRegistration(app, {
  User,
  authenticateToken,
  requireAdmin,
});

// =====================================================
// LOGIN
// =====================================================

app.post(
  "/api/auth/login",
  wrap(async (req, res) => {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({
        message: "Invalid username or password",
      });
    }

    const passwordIsCorrect = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!passwordIsCorrect) {
      return res.status(401).json({
        message: "Invalid username or password",
      });
    }

    if (
      user.accountStatus &&
      user.accountStatus !== "approved"
    ) {
      return res.status(403).json({
        message:
          user.accountStatus === "pending"
            ? "Your account is waiting for admin approval."
            : "Your account request was rejected. Contact the admin.",
      });
    }

    if (user.role === "admin") {
      const challengeToken = jwt.sign(
        {
          userId: String(user._id),
          purpose: "admin-pin",
          tokenVersion: user.tokenVersion || 0,
        },
        JWT_SECRET,
        { expiresIn: "5m" }
      );

      return res.json({
        requiresAdminPin: true,
        challengeToken,
      });
    }

    res.json(createSession(user));
  })
);

app.post(
  "/api/auth/admin-pin",
  wrap(async (req, res) => {
    const challengeToken = String(req.body.challengeToken || "");
    const adminPin = String(req.body.adminPin || "");

    let challenge;

    try {
      challenge = jwt.verify(challengeToken, JWT_SECRET);
    } catch {
      return res.status(401).json({
        message: "Admin verification expired. Log in again.",
      });
    }

    if (challenge.purpose !== "admin-pin") {
      return res.status(401).json({
        message: "Invalid admin verification",
      });
    }

    const user = await User.findById(challenge.userId);

    if (
      !user ||
      user.role !== "admin" ||
      challenge.tokenVersion !== (user.tokenVersion || 0)
    ) {
      return res.status(401).json({
        message: "Invalid admin verification",
      });
    }

    const receivedPin = Buffer.from(adminPin);
    const correctPin = Buffer.from(ADMIN_SECURITY_PIN);

    const pinIsCorrect =
      receivedPin.length === correctPin.length &&
      timingSafeEqual(receivedPin, correctPin);

    if (!pinIsCorrect) {
      return res.status(401).json({
        message: "Invalid admin PIN",
      });
    }

    res.json(createSession(user));
  })
);

// All routes below require authentication.
app.use("/api", authenticateToken);

// =====================================================
// ADMIN USER MANAGEMENT
// =====================================================

app.get(
  "/api/admin/users",
  requireAdmin,
  wrap(async (_req, res) => {
    const users = await User.find({
      $or: [
        { accountStatus: "approved" },
        { accountStatus: { $exists: false } },
      ],
    })
      .select("username email role monthlyFee createdAt accountStatus")
      .sort({ createdAt: -1 });

    res.json(users.map(publicUser));
  })
);

app.post(
  "/api/admin/users",
  requireAdmin,
  wrap(async (req, res) => {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const monthlyFee = Number(req.body.monthlyFee);

    if (!username) {
      return res.status(400).json({
        message: "Username is required",
      });
    }

    if (!validPassword(password)) {
      return res.status(400).json({
        message: "Password must be at least 6 characters",
      });
    }

    if (!Number.isFinite(monthlyFee) || monthlyFee < 0) {
      return res.status(400).json({
        message: "Enter a valid monthly fee",
      });
    }

    if (await User.exists({ username })) {
      return res.status(409).json({
        message: "This username already exists",
      });
    }

    if (email) {
      const emailIsValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

      if (!emailIsValid) {
        return res.status(400).json({
          message: "Enter a valid email address",
        });
      }

      if (await User.exists({ email })) {
        return res.status(409).json({
          message: "This email is already registered",
        });
      }
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await User.create({
      username,
      ...(email ? { email } : {}),
      passwordHash,
      role: "user",
      monthlyFee,
    });

    res.status(201).json(publicUser(user));
  })
);

app.put(
  "/api/admin/users/:id/fee",
  requireAdmin,
  wrap(async (req, res) => {
    const monthlyFee = Number(req.body.monthlyFee);

    if (!Number.isFinite(monthlyFee) || monthlyFee < 0) {
      return res.status(400).json({
        message: "Enter a valid monthly fee",
      });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { monthlyFee },
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    res.json(publicUser(user));
  })
);

app.delete(
  "/api/admin/users/:id",
  requireAdmin,
  wrap(async (req, res) => {
    if (req.params.id === req.user.userId) {
      return res.status(400).json({
        message: "You cannot delete your own admin account",
      });
    }

    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    await Promise.all([
      Customer.deleteMany({ ownerId: user._id }),
      Transaction.deleteMany({ ownerId: user._id }),
      Profile.deleteMany({ ownerId: user._id }),
      Payment.deleteMany({ ownerId: user._id }),
      Finance.deleteMany({ ownerId: user._id }),
    ]);

    res.json({
      message: "User and private data deleted",
    });
  })
);

// =====================================================
// SUBSCRIPTIONS AND PAYMENTS
// =====================================================

app.get(
  "/api/subscription/status",
  wrap(async (req, res) => {
    const status = await subscriptionStatus(
      req.user.userId,
      req.user.role
    );

    res.json(status);
  })
);

app.post(
  "/api/payments/submit",
  wrap(async (req, res) => {
    if (req.user.role === "admin") {
      return res.status(400).json({
        message: "Admin account does not require payment",
      });
    }

    const transactionId = String(req.body.transactionId || "").trim();

    if (transactionId.length < 4) {
      return res.status(400).json({
        message: "Enter a valid Easypaisa transaction ID",
      });
    }

    const { month } = billingPeriod();

    const user = await User.findById(req.user.userId)
      .select("monthlyFee")
      .lean();

    const monthlyFee = Number(user?.monthlyFee || 0);

    if (monthlyFee <= 0) {
      return res.status(400).json({
        message: "This account does not require a monthly payment",
      });
    }

    const existingPayment = await Payment.findOne({
      ownerId: req.user.userId,
      month,
    });

    if (existingPayment?.status === "approved") {
      return res.status(409).json({
        message: "This month's payment has already been approved",
        payment: existingPayment,
      });
    }

    const payment = await Payment.findOneAndUpdate(
      { ownerId: req.user.userId, month },
      {
        $set: {
          amount: monthlyFee,
          transactionId,
          status: "pending",
          reviewedAt: null,
          reviewedBy: null,
        },
        $setOnInsert: { ownerId: req.user.userId, month },
      },
      { new: true, upsert: true, runValidators: true }
    );

    res.status(existingPayment ? 200 : 201).json(payment);
  })
);

app.get(
  "/api/admin/payments",
  requireAdmin,
  wrap(async (_req, res) => {
    const payments = await Payment.find()
      .populate("ownerId", "username monthlyFee")
      .sort({ createdAt: -1 })
      .lean();

    res.json(payments);
  })
);

app.put(
  "/api/admin/payments/:id",
  requireAdmin,
  wrap(async (req, res) => {
    const status = req.body.status;

    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({
        message: "Invalid payment decision",
      });
    }

    const payment = await Payment.findByIdAndUpdate(
      req.params.id,
      {
        status,
        reviewedAt: new Date(),
        reviewedBy: req.user.userId,
      },
      { new: true }
    );

    if (!payment) {
      return res.status(404).json({
        message: "Payment not found",
      });
    }

    res.json(payment);
  })
);

// Business-data routes require an active subscription.
// Admin accounts are always unlocked.
app.use("/api", requireActiveSubscription);

// =====================================================
// COMPLETE USER DATA
// =====================================================

app.get(
  "/api/data",
  wrap(async (req, res) => {
    const ownerId = req.user.userId;

    const [customers, transactions, profile, finances] =
      await Promise.all([
        Customer.find({ ownerId }).lean(),
        Transaction.find({ ownerId }).lean(),
        Profile.findOne({ ownerId }).lean(),
        Finance.find({ ownerId })
          .sort({ date: -1, createdAt: -1 })
          .lean(),
      ]);

    res.json({
      customers,
      transactions,
      profile: profile || {},
      finances,
    });
  })
);

// =====================================================
// CUSTOMERS
// =====================================================

app.get(
  "/api/customers",
  wrap(async (req, res) => {
    const customers = await Customer.find({
      ownerId: req.user.userId,
    }).lean();

    res.json(customers);
  })
);

app.post(
  "/api/customers",
  wrap(async (req, res) => {
    const name = String(req.body.name || "").trim();

    if (!name) {
      return res.status(400).json({
        message: "Customer name is required",
      });
    }

    const customer = await Customer.create({
      id: createId(),
      ownerId: req.user.userId,
      name,
      fatherName: String(req.body.fatherName || "").trim(),
      phone: String(req.body.phone || "").trim(),
      address: String(req.body.address || "").trim(),
    });

    res.status(201).json(customer);
  })
);

app.put(
  "/api/customers/:id",
  wrap(async (req, res) => {
    const name = String(req.body.name || "").trim();

    if (!name) {
      return res.status(400).json({
        message: "Customer name is required",
      });
    }

    const customer = await Customer.findOneAndUpdate(
      {
        id: Number(req.params.id),
        ownerId: req.user.userId,
      },
      {
        name,
        fatherName: String(req.body.fatherName || "").trim(),
        phone: String(req.body.phone || "").trim(),
        address: String(req.body.address || "").trim(),
      },
      { new: true, runValidators: true }
    );

    if (!customer) {
      return res.status(404).json({
        message: "Customer not found",
      });
    }

    res.json(customer);
  })
);

app.delete(
  "/api/customers/:id",
  wrap(async (req, res) => {
    const customerId = Number(req.params.id);

    const customer = await Customer.findOneAndDelete({
      id: customerId,
      ownerId: req.user.userId,
    });

    if (!customer) {
      return res.status(404).json({
        message: "Customer not found",
      });
    }

    await Transaction.deleteMany({
      customerId,
      ownerId: req.user.userId,
    });

    res.json({
      message: "Customer and transactions deleted",
    });
  })
);

// =====================================================
// TRANSACTIONS
// =====================================================

app.get(
  "/api/transactions",
  wrap(async (req, res) => {
    const transactions = await Transaction.find({
      ownerId: req.user.userId,
    }).lean();

    res.json(transactions);
  })
);

app.post(
  "/api/transactions",
  wrap(async (req, res) => {
    const ownerId = req.user.userId;
    const customerId = Number(req.body.customerId);
    const amount = Number(req.body.amount);
    const type = req.body.type;
    const date = req.body.date;

    const customer = await Customer.findOne({
      id: customerId,
      ownerId,
    });

    if (!customer) {
      return res.status(404).json({
        message: "Customer not found",
      });
    }

    if (!["credit", "payment"].includes(type)) {
      return res.status(400).json({
        message: "Invalid transaction type",
      });
    }

    if (!amount || amount <= 0) {
      return res.status(400).json({
        message: "Amount must be greater than zero",
      });
    }

    if (!date) {
      return res.status(400).json({
        message: "Transaction date is required",
      });
    }

    if (type === "payment") {
      const records = await Transaction.find({
        customerId,
        ownerId,
      }).lean();

      const credit = records
        .filter((record) => record.type === "credit")
        .reduce((total, record) => total + record.amount, 0);

      const payment = records
        .filter((record) => record.type === "payment")
        .reduce((total, record) => total + record.amount, 0);

      const balance = Math.max(0, credit - payment);

      if (balance <= 0) {
        return res.status(400).json({
          message: "Customer has no pending balance",
        });
      }

      if (amount > balance) {
        return res.status(400).json({
          message: `Payment cannot be greater than Rs. ${balance}`,
        });
      }
    }

    const transaction = await Transaction.create({
      id: createId(),
      ownerId,
      customerId,
      type,
      amount,
      date,
      note: String(req.body.note || "").trim(),
    });

    res.status(201).json(transaction);
  })
);

app.put(
  "/api/transactions/:id",
  wrap(async (req, res) => {
    const ownerId = req.user.userId;
    const transactionId = Number(req.params.id);
    const customerId = Number(req.body.customerId);
    const amount = Number(req.body.amount);
    const type = req.body.type;
    const date = req.body.date;

    if (!Number.isFinite(transactionId)) {
      return res.status(400).json({ message: "Invalid transaction ID" });
    }

    if (!Number.isFinite(customerId)) {
      return res.status(400).json({ message: "Invalid customer" });
    }

    if (!["credit", "payment"].includes(type)) {
      return res.status(400).json({ message: "Invalid transaction type" });
    }

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({
        message: "Amount must be greater than zero",
      });
    }

    if (!date) {
      return res.status(400).json({ message: "Transaction date is required" });
    }

    const existingTransaction = await Transaction.findOne({
      id: transactionId,
      ownerId,
    });

    if (!existingTransaction) {
      return res.status(404).json({ message: "Transaction not found" });
    }

    const customerExists = await Customer.exists({ id: customerId, ownerId });

    if (!customerExists) {
      return res.status(404).json({ message: "Customer not found" });
    }

    const records = await Transaction.find({
      customerId,
      ownerId,
      id: { $ne: transactionId },
    }).lean();

    let totalCredit = 0;
    let totalPayment = 0;

    for (const record of records) {
      if (record.type === "credit") {
        totalCredit += Number(record.amount) || 0;
      } else if (record.type === "payment") {
        totalPayment += Number(record.amount) || 0;
      }
    }

    if (type === "credit") totalCredit += amount;
    else totalPayment += amount;

    if (totalPayment > totalCredit) {
      const availableBalance = Math.max(
        0,
        totalCredit - (totalPayment - amount)
      );

      return res.status(400).json({
        message: `Payment cannot be greater than Rs. ${availableBalance}`,
      });
    }

    existingTransaction.customerId = customerId;
    existingTransaction.type = type;
    existingTransaction.amount = amount;
    existingTransaction.date = date;
    existingTransaction.note = String(req.body.note || "").trim();

    await existingTransaction.save();
    res.json(existingTransaction);
  })
);

app.delete(
  "/api/transactions/:id",
  wrap(async (req, res) => {
    const transaction = await Transaction.findOneAndDelete({
      id: Number(req.params.id),
      ownerId: req.user.userId,
    });

    if (!transaction) {
      return res.status(404).json({
        message: "Transaction not found",
      });
    }

    res.json({
      message: "Transaction deleted",
    });
  })
);

// =====================================================
// INCOME AND EXPENSES
// =====================================================

app.get(
  "/api/finances",
  wrap(async (req, res) => {
    const records = await Finance.find({
      ownerId: req.user.userId,
    })
      .sort({ date: -1, createdAt: -1 })
      .lean();

    res.json(records);
  })
);

app.post(
  "/api/finances",
  wrap(async (req, res) => {
    const { type, date } = req.body;
    const amount = Number(req.body.amount);

    if (
      !["income", "expense"].includes(type) ||
      !date ||
      !Number.isFinite(amount) ||
      amount < 1
    ) {
      return res.status(400).json({
        message: "Enter a valid type, amount, and date",
      });
    }

    const record = await Finance.create({
      id: createId(),
      ownerId: req.user.userId,
      type,
      amount,
      date,
      category: String(req.body.category || "").trim(),
      note: String(req.body.note || "").trim(),
    });

    res.status(201).json(record);
  })
);

app.put(
  "/api/finances/:id",
  wrap(async (req, res) => {
    const { type, date } = req.body;
    const amount = Number(req.body.amount);

    if (
      !["income", "expense"].includes(type) ||
      !date ||
      !Number.isFinite(amount) ||
      amount < 1
    ) {
      return res.status(400).json({
        message: "Enter a valid type, amount, and date",
      });
    }

    const record = await Finance.findOneAndUpdate(
      {
        id: Number(req.params.id),
        ownerId: req.user.userId,
      },
      {
        type,
        amount,
        date,
        category: String(req.body.category || "").trim(),
        note: String(req.body.note || "").trim(),
      },
      { new: true, runValidators: true }
    );

    if (!record) {
      return res.status(404).json({
        message: "Record not found",
      });
    }

    res.json(record);
  })
);

app.delete(
  "/api/finances/:id",
  wrap(async (req, res) => {
    const record = await Finance.findOneAndDelete({
      id: Number(req.params.id),
      ownerId: req.user.userId,
    });

    if (!record) {
      return res.status(404).json({
        message: "Record not found",
      });
    }

    res.json({
      message: "Record deleted",
    });
  })
);

// =====================================================
// PROFILE
// =====================================================

app.get(
  "/api/profile",
  wrap(async (req, res) => {
    const profile = await Profile.findOne({
      ownerId: req.user.userId,
    }).lean();

    res.json(profile || {});
  })
);

app.put(
  "/api/profile",
  wrap(async (req, res) => {
    const profile = await Profile.findOneAndUpdate(
      {
        ownerId: req.user.userId,
      },
      {
        ownerId: req.user.userId,
        shopName: String(req.body.shopName || "").trim(),
        ownerName: String(req.body.ownerName || "").trim(),
        phone: String(req.body.phone || "").trim(),
        address: String(req.body.address || "").trim(),
      },
      { new: true, upsert: true, runValidators: true }
    );

    res.json(profile);
  })
);

// =====================================================
// ERROR HANDLERS
// =====================================================

app.use((_req, res) => {
  res.status(404).json({
    message: "API route not found",
  });
});

app.use((error, _req, res, _next) => {
  console.error(error);

  res.status(500).json({
    message: "Internal server error",
  });
});

// =====================================================
// START SERVER
// =====================================================

mongoose
  .connect(MONGODB_URI)
  .then(async () => {
    await ensureAdminUser();

    app.listen(PORT, () => {
      console.log("========================================");
      console.log(" KHAN EASY KAHTA - MULTI USER");
      console.log(` Backend: http://localhost:${PORT}`);
      console.log(" MongoDB: connected");
      console.log(" Easypaisa: 03445088350");
      console.log("========================================");
    });
  })
  .catch((error) => {
    console.error("Server could not start:", error.message);
    process.exit(1);
  });
