const express = require("express");
const mongoose = require("mongoose");
const {
  User,
  Member,
  Message,
  Server,
  Room
} = require("./schema");

const router = express.Router();

/* -----------------------------------
 * Helpers
 * ----------------------------------- */

function parseFilters(req) {
  try {
    return JSON.parse(req.query.filters || "[]");
  } catch {
    return [];
  }
}

function regex(value) {
  return new RegExp(value, "i");
}

/* -----------------------------------
 * USERS
 * ----------------------------------- */
router.get("/users", async (req, res) => {
  const filters = parseFilters(req);
  const query = {};

  for (const f of filters) {
    if (!f.value) continue;

    if (f.field === "username") query.username = regex(f.value);
    if (f.field === "email") query.email = regex(f.value);
    if (f.field === "role") query.role = f.value;
  }

  const results = await User.find(query)
    .select("username email role created_at")
    .sort({ created_at: -1 })
    .lean();

  res.json({ results, count: results.length });
});

/* -----------------------------------
 * MEMBERS (SERVER NAME FILTER)
 * ----------------------------------- */
router.get("/members", async (req, res) => {
  const filters = parseFilters(req);
  const query = {};

  let serverIds;
  let userMatch;

  for (const f of filters) {
    if (!f.value) continue;

    if (f.field === "serverName") {
      const servers = await Server.find({
        server_name: regex(f.value)
      }).select("_id");
      serverIds = servers.map(s => s._id);
    }

    if (f.field === "role") query.role = regex(f.value);
    if (f.field === "user") userMatch = regex(f.value);
  }

  if (serverIds) {
    query.server = { $in: serverIds };
  }

  const results = await Member.find(query)
    .populate({
      path: "user",
      match: userMatch ? { username: userMatch } : {},
      select: "username email"
    })
    .populate("server", "server_name")
    .sort({ joined_at: -1 })
    .lean();

  const filtered = results.filter(m => m.user);

  res.json({ results: filtered, count: filtered.length });
});

/* -----------------------------------
 * ACTIVITY (AGGREGATED SUMMARY)
 * GET /api/v1/admin/activity
 * ----------------------------------- */
router.get("/activity", async (req, res) => {
  const filters = parseFilters(req);

  let senderId;
  let contextType;
  let minMentions;

  for (const f of filters) {
    if (!f.value) continue;

    if (f.field === "sender") {
      const user = await User.findOne({
        username: regex(f.value)
      }).select("_id");
      if (user) senderId = user._id;
    }

    if (f.field === "context_type") {
      contextType = f.value;
    }

    if (f.field === "mentions") {
      minMentions = Number(f.value);
    }
  }

  const matchStage = {};
  if (senderId) matchStage.sender = senderId;
  if (contextType) matchStage.context_type = contextType;

  const pipeline = [
    { $match: matchStage },

    /* Count mentions per message */
    {
      $addFields: {
        mentionCount: {
          $size: {
            $regexFindAll: {
              input: "$content",
              regex: /@/g
            }
          }
        }
      }
    },

    /* Group per sender */
    {
      $group: {
        _id: "$sender",
        totalMessages: { $sum: 1 },
        totalMentions: { $sum: "$mentionCount" }
      }
    },

    /* Optional mention filter (AFTER aggregation) */
    ...(typeof minMentions === "number"
      ? [{ $match: { totalMentions: { $gte: minMentions } } }]
      : []),

    { $sort: { totalMessages: -1 } },

    /* Join user info */
    {
      $lookup: {
        from: "users",
        localField: "_id",
        foreignField: "_id",
        as: "user"
      }
    },
    { $unwind: "$user" },

    {
      $project: {
        _id: 0,
        sender: "$user.username",
        totalMessages: 1,
        totalMentions: 1
      }
    }
  ];

  const results = await Message.aggregate(pipeline);

  res.json({
    results,
    count: results.length
  });
});

/* -----------------------------------
 * ROOM MESSAGES (SERVER NAME)
 * ----------------------------------- */
router.get("/messages", async (req, res) => {
  const filters = parseFilters(req);
  const query = { context_type: "Room" };

  let serverIds;

  for (const f of filters) {
    if (!f.value) continue;

    if (f.field === "serverName") {
      const servers = await Server.find({
        server_name: regex(f.value)
      }).select("_id");
      serverIds = servers.map(s => s._id);
    }

    if (f.field === "room") query.context = f.value;

    if (f.field === "sender") {
      const user = await User.findOne({ username: regex(f.value) });
      if (user) query.sender = user._id;
    }

    if (f.field === "content") query.content = regex(f.value);
  }

  if (serverIds) {
    query.context = { $in: serverIds };
  }

  const results = await Message.find(query)
    .populate("sender", "username")
    .sort({ created_at: -1 })
    .limit(200)
    .lean();

  res.json({ results, count: results.length });
});

/* -----------------------------------
 * DMs
 * ----------------------------------- */
router.get("/dms", async (req, res) => {
  const filters = parseFilters(req);
  const query = { context_type: "User" };

  for (const f of filters) {
    if (!f.value) continue;

    if (f.field === "sender") {
      const user = await User.findOne({ username: regex(f.value) });
      if (user) query.sender = user._id;
    }

    if (f.field === "recipient") {
      const user = await User.findOne({ username: regex(f.value) });
      if (user) query.recipients = user._id;
    }

    if (f.field === "content") query.content = regex(f.value);
  }

  const results = await Message.find(query)
    .populate("sender", "username")
    .populate("recipients", "username")
    .sort({ created_at: -1 })
    .limit(200)
    .lean();

  res.json({ results, count: results.length });
});

module.exports = router;
