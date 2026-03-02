const mongoose = require("mongoose");

const TaskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  completed: { type: Boolean, default: false },
  completedAt: { type: Date, default: null }
});

const AdminTodoSchema = new mongoose.Schema({
  date: { type: String, required: true, unique: true }, // YYYY-MM-DD
  tasks: [TaskSchema],
  lastMarkedAt: { type: Date, default: null }
}, { timestamps: true });

module.exports = mongoose.model("AdminTodo", AdminTodoSchema);