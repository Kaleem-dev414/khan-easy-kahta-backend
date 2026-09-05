// =====================================================
// KHAN EASY KAHTA - COMPLETE DATABASE SEEDER
// =====================================================

import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import "dotenv/config";

// =====================================================
// ENVIRONMENT VARIABLES
// =====================================================

const {
  MONGODB_URI,
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
} = process.env;

if (!MONGODB_URI) {
  throw new Error(
    "MONGODB_URI is missing from backend/.env"
  );
}

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
  throw new Error(
    "ADMIN_USERNAME and ADMIN_PASSWORD are required in backend/.env"
  );
}

// =====================================================
// KHAN EASY KAHTA - USER SCHEMA
// =====================================================

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
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
      enum: [
        "pending",
        "approved",
        "rejected",
      ],
      default: "approved",
      index: true,
    },

    accountReviewedAt: Date,

    accountReviewedBy:
      mongoose.Schema.Types.ObjectId,

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

      approvedBy:
        mongoose.Schema.Types.ObjectId,
    },
  },
  {
    timestamps: true,
  }
);

// =====================================================
// KHAN EASY KAHTA - CUSTOMER SCHEMA
// =====================================================

const customerSchema = new mongoose.Schema(
  {
    id: {
      type: Number,
      required: true,
      unique: true,
    },

    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    name: {
      type: String,
      required: true,
      trim: true,
    },

    fatherName: {
      type: String,
      default: "",
      trim: true,
    },

    phone: {
      type: String,
      default: "",
      trim: true,
    },

    address: {
      type: String,
      default: "",
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

// =====================================================
// KHAN EASY KAHTA - TRANSACTION SCHEMA
// =====================================================

const transactionSchema = new mongoose.Schema(
  {
    id: {
      type: Number,
      required: true,
      unique: true,
    },

    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    customerId: {
      type: Number,
      required: true,
      index: true,
    },

    type: {
      type: String,
      enum: [
        "credit",
        "payment",
      ],
      required: true,
    },

    amount: {
      type: Number,
      min: 1,
      required: true,
    },

    date: {
      type: String,
      required: true,
    },

    note: {
      type: String,
      default: "",
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

// =====================================================
// KHAN EASY KAHTA - PROFILE SCHEMA
// =====================================================

const profileSchema = new mongoose.Schema(
  {
    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      unique: true,
    },

    shopName: {
      type: String,
      default: "",
      trim: true,
    },

    ownerName: {
      type: String,
      default: "",
      trim: true,
    },

    phone: {
      type: String,
      default: "",
      trim: true,
    },

    address: {
      type: String,
      default: "",
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

// =====================================================
// KHAN EASY KAHTA - PAYMENT SCHEMA
// =====================================================

const paymentSchema = new mongoose.Schema(
  {
    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    month: {
      type: String,
      required: true,
      index: true,
    },

    amount: {
      type: Number,
      required: true,
      min: 0,
    },

    transactionId: {
      type: String,
      required: true,
      trim: true,
    },

    status: {
      type: String,
      enum: [
        "pending",
        "approved",
        "rejected",
      ],
      default: "pending",
    },

    reviewedAt: {
      type: Date,
      default: null,
    },

    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

paymentSchema.index(
  {
    ownerId: 1,
    month: 1,
  },
  {
    unique: true,
  }
);

// =====================================================
// KHAN EASY KAHTA - FINANCE SCHEMA
// =====================================================

const financeSchema = new mongoose.Schema(
  {
    id: {
      type: Number,
      required: true,
      unique: true,
    },

    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    type: {
      type: String,
      enum: [
        "income",
        "expense",
      ],
      required: true,
    },

    amount: {
      type: Number,
      min: 1,
      required: true,
    },

    date: {
      type: String,
      required: true,
      index: true,
    },

    category: {
      type: String,
      default: "",
      trim: true,
    },

    note: {
      type: String,
      default: "",
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

// =====================================================
// KHAN EASY KAHTA - MODELS
// =====================================================

const User =
  mongoose.models.User ||
  mongoose.model(
    "User",
    userSchema
  );

const Customer =
  mongoose.models.Customer ||
  mongoose.model(
    "Customer",
    customerSchema
  );

const Transaction =
  mongoose.models.Transaction ||
  mongoose.model(
    "Transaction",
    transactionSchema
  );

const Profile =
  mongoose.models.Profile ||
  mongoose.model(
    "Profile",
    profileSchema
  );

const Payment =
  mongoose.models.Payment ||
  mongoose.model(
    "Payment",
    paymentSchema
  );

const Finance =
  mongoose.models.Finance ||
  mongoose.model(
    "Finance",
    financeSchema
  );

// =====================================================
// CREATE UNIQUE ID
// =====================================================

function createId() {
  return (
    Date.now() * 1000 +
    Math.floor(
      Math.random() * 1000
    )
  );
}

// =====================================================
// CURRENT DATE
// =====================================================

function currentDate() {
  return new Date()
    .toISOString()
    .slice(0, 10);
}

// =====================================================
// CURRENT BILLING MONTH
// =====================================================

function currentMonth() {
  const parts =
    new Intl.DateTimeFormat(
      "en-CA",
      {
        timeZone:
          "Asia/Karachi",

        year:
          "numeric",

        month:
          "2-digit",
      }
    ).formatToParts(
      new Date()
    );

  const values =
    Object.fromEntries(
      parts.map(
        (part) => [
          part.type,
          part.value,
        ]
      )
    );

  return `${values.year}-${values.month}`;
}

// =====================================================
// KHAN EASY KAHTA - COMPLETE SEEDER
// =====================================================

async function seedDatabase() {
  try {
    console.log(
      "========================================"
    );

    console.log(
      " KHAN EASY KAHTA - COMPLETE SEEDER"
    );

    console.log(
      "========================================"
    );

    // =================================================
    // CONNECT MONGODB
    // =================================================

    await mongoose.connect(
      MONGODB_URI
    );

    console.log(
      "MongoDB connected successfully."
    );

    // =================================================
    // CREATE OR CHECK ADMIN
    // =================================================

    let admin =
      await User.findOne({
        username:
          ADMIN_USERNAME,
      });

    if (!admin) {
      const passwordHash =
        await bcrypt.hash(
          ADMIN_PASSWORD,
          12
        );

      admin =
        await User.create({
          username:
            ADMIN_USERNAME,

          passwordHash,

          role:
            "admin",

          accountStatus:
            "approved",

          monthlyFee:
            0,

          tokenVersion:
            0,
        });

      console.log(
        "Admin account created."
      );
    } else {
      console.log(
        "Admin account already exists."
      );
    }

    // Make sure configured admin is admin
    if (
      admin.role !== "admin"
    ) {
      admin.role =
        "admin";

      admin.accountStatus =
        "approved";

      admin.monthlyFee =
        0;

      await admin.save();

      console.log(
        "Admin role corrected."
      );
    }

    // =================================================
    // CREATE DEMO USER
    // =================================================

    const demoUsername =
      "demo";

    const demoPassword =
      "demo123";

    let demoUser =
      await User.findOne({
        username:
          demoUsername,
      });

    if (!demoUser) {
      const passwordHash =
        await bcrypt.hash(
          demoPassword,
          12
        );

      demoUser =
        await User.create({
          username:
            demoUsername,

          passwordHash,

          role:
            "user",

          accountStatus:
            "approved",

          accountReviewedAt:
            new Date(),

          accountReviewedBy:
            admin._id,

          monthlyFee:
            500,

          tokenVersion:
            0,
        });

      console.log(
        "Demo user created."
      );
    } else {
      console.log(
        "Demo user already exists."
      );
    }

    // =================================================
    // CREATE DEMO PROFILE
    // =================================================

    let profile =
      await Profile.findOne({
        ownerId:
          demoUser._id,
      });

    if (!profile) {
      profile =
        await Profile.create({
          ownerId:
            demoUser._id,

          shopName:
            "Demo Shop",

          ownerName:
            "Demo User",

          phone:
            "03001234567",

          address:
            "Mingora, Swat",
        });

      console.log(
        "Demo profile created."
      );
    } else {
      console.log(
        "Demo profile already exists."
      );
    }

    // =================================================
    // CREATE FIRST DEMO CUSTOMER
    // =================================================

    let customer1 =
      await Customer.findOne({
        ownerId:
          demoUser._id,

        phone:
          "03001111111",
      });

    if (!customer1) {
      customer1 =
        await Customer.create({
          id:
            createId(),

          ownerId:
            demoUser._id,

          name:
            "Ahmad Khan",

          fatherName:
            "Rahim Khan",

          phone:
            "03001111111",

          address:
            "Mingora, Swat",
        });

      console.log(
        "Demo customer 1 created."
      );
    } else {
      console.log(
        "Demo customer 1 already exists."
      );
    }

    // =================================================
    // CREATE SECOND DEMO CUSTOMER
    // =================================================

    let customer2 =
      await Customer.findOne({
        ownerId:
          demoUser._id,

        phone:
          "03002222222",
      });

    if (!customer2) {
      customer2 =
        await Customer.create({
          id:
            createId(),

          ownerId:
            demoUser._id,

          name:
            "Usman Ali",

          fatherName:
            "Kareem Ali",

          phone:
            "03002222222",

          address:
            "Saidu Sharif, Swat",
        });

      console.log(
        "Demo customer 2 created."
      );
    } else {
      console.log(
        "Demo customer 2 already exists."
      );
    }

    // =================================================
    // CUSTOMER 1 - CREDIT TRANSACTION
    // =================================================

    const customer1Credit =
      await Transaction.findOne({
        ownerId:
          demoUser._id,

        customerId:
          customer1.id,

        note:
          "Seeder demo credit 1",
      });

    if (!customer1Credit) {
      await Transaction.create({
        id:
          createId(),

        ownerId:
          demoUser._id,

        customerId:
          customer1.id,

        type:
          "credit",

        amount:
          10000,

        date:
          currentDate(),

        note:
          "Seeder demo credit 1",
      });

      console.log(
        "Customer 1 credit created."
      );
    } else {
      console.log(
        "Customer 1 credit already exists."
      );
    }

    // =================================================
    // CUSTOMER 1 - PAYMENT TRANSACTION
    // =================================================

    const customer1Payment =
      await Transaction.findOne({
        ownerId:
          demoUser._id,

        customerId:
          customer1.id,

        note:
          "Seeder demo payment 1",
      });

    if (!customer1Payment) {
      await Transaction.create({
        id:
          createId(),

        ownerId:
          demoUser._id,

        customerId:
          customer1.id,

        type:
          "payment",

        amount:
          3000,

        date:
          currentDate(),

        note:
          "Seeder demo payment 1",
      });

      console.log(
        "Customer 1 payment created."
      );
    } else {
      console.log(
        "Customer 1 payment already exists."
      );
    }

    // =================================================
    // CUSTOMER 2 - CREDIT TRANSACTION
    // =================================================

    const customer2Credit =
      await Transaction.findOne({
        ownerId:
          demoUser._id,

        customerId:
          customer2.id,

        note:
          "Seeder demo credit 2",
      });

    if (!customer2Credit) {
      await Transaction.create({
        id:
          createId(),

        ownerId:
          demoUser._id,

        customerId:
          customer2.id,

        type:
          "credit",

        amount:
          7500,

        date:
          currentDate(),

        note:
          "Seeder demo credit 2",
      });

      console.log(
        "Customer 2 credit created."
      );
    } else {
      console.log(
        "Customer 2 credit already exists."
      );
    }

    // =================================================
    // CREATE APPROVED MONTHLY PAYMENT
    // =================================================

    const month =
      currentMonth();

    let monthlyPayment =
      await Payment.findOne({
        ownerId:
          demoUser._id,

        month,
      });

    if (!monthlyPayment) {
      monthlyPayment =
        await Payment.create({
          ownerId:
            demoUser._id,

          month,

          amount:
            demoUser.monthlyFee || 500,

          transactionId:
            "1234567890",

          status:
            "approved",

          reviewedAt:
            new Date(),

          reviewedBy:
            admin._id,
        });

      console.log(
        `Demo monthly payment created for ${month}.`
      );
    } else {
      console.log(
        `Monthly payment for ${month} already exists.`
      );
    }

    // =================================================
    // CREATE DEMO INCOME
    // =================================================

    const income =
      await Finance.findOne({
        ownerId:
          demoUser._id,

        note:
          "Seeder demo income",
      });

    if (!income) {
      await Finance.create({
        id:
          createId(),

        ownerId:
          demoUser._id,

        type:
          "income",

        amount:
          5000,

        date:
          currentDate(),

        category:
          "Sales",

        note:
          "Seeder demo income",
      });

      console.log(
        "Demo income created."
      );
    } else {
      console.log(
        "Demo income already exists."
      );
    }

    // =================================================
    // CREATE DEMO EXPENSE
    // =================================================

    const expense =
      await Finance.findOne({
        ownerId:
          demoUser._id,

        note:
          "Seeder demo expense",
      });

    if (!expense) {
      await Finance.create({
        id:
          createId(),

        ownerId:
          demoUser._id,

        type:
          "expense",

        amount:
          1500,

        date:
          currentDate(),

        category:
          "Shop Expense",

        note:
          "Seeder demo expense",
      });

      console.log(
        "Demo expense created."
      );
    } else {
      console.log(
        "Demo expense already exists."
      );
    }

    // =================================================
    // FINISHED
    // =================================================

    console.log(
      ""
    );

    console.log(
      "========================================"
    );

    console.log(
      " KHAN EASY KAHTA SEEDING COMPLETED"
    );

    console.log(
      "========================================"
    );

    console.log(
      `Admin: ${ADMIN_USERNAME}`
    );

    console.log(
      "Demo Username: demo"
    );

    console.log(
      "Demo Password: demo123"
    );

    console.log(
      "Demo Monthly Fee: Rs. 500"
    );

    console.log(
      "========================================"
    );
  } catch (error) {
    console.error(
      ""
    );

    console.error(
      "KHAN EASY KAHTA SEEDER FAILED:"
    );

    console.error(
      error
    );

    process.exitCode =
      1;
  } finally {
    await mongoose.disconnect();

    console.log(
      "MongoDB disconnected."
    );
  }
}

// =====================================================
// RUN KHAN EASY KAHTA SEEDER
// =====================================================

seedDatabase();